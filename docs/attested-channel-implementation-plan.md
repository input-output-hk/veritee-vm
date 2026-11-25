# Attested Channel — Implementation Plan

**Status:** Phases 0–6 implemented on `feat/attested-channel` (on-CVM e2e pending)
**Tracking issue:** [#15](https://github.com/input-output-hk/veritee-vm/issues/15)
**Protocol spec:** [`docs/tls-channel-binding.md`](./tls-channel-binding.md) (§6 normative protocol, §7 threat model)
**Audience:** Veritee VM / Warden / browser-extension contributors

This document turns the informal notes in issue #15 into a concrete, phased engineering
plan. It records the design decisions we locked, reconciles the issue with the actual code,
and specifies each phase (routes, types, files, tests) so the work can be split into small,
reviewable PRs.

---

## 1. Where we are today (ground truth)

### Baseline on `main` (after [PR #11](https://github.com/input-output-hk/veritee-vm/pull/11))

The attestation server on `main` is an **evidence endpoint** — MAA *or* raw SEV-SNP —
**not** yet a key-exchange / decrypt-and-forward channel. Concretely:

| Aspect | On `main` (post-#11) |
| --- | --- |
| HTTP surface | Host-internal route `GET /` → `get_attestation` on `0.0.0.0:8000` (Axum), exposed publicly through Caddy at HTTPS `/tee_attestation` |
| Attestation mode | **Cargo features** (mutually exclusive): `maa` (default) **or** `raw-report`. CLI `build-os` can select the mode. Response is `AttestationEvidence::{Maa, RawSevSnp}` |
| `report_data` binding | **MAA:** nonce/payload → `client_payload` (token commits to it). **Raw:** `report_data_binding(nonce, payload)` → 32-byte SHA-256 fed to Azure HCL `get_report_with_report_data` (not a free-form `/dev/sev-guest` ioctl) |
| Ephemeral key | An **RSA-2048 TPM key** (`eph_key_tpm.rs`) used *only* in MAA mode to unwrap MAA's inner AES key — not usable for ECDH/HPKE |
| Sessions / AEAD / proxy | **None** on `main` |
| Client verification | Delegated to **Warden** (`POST /dapps/verify_attestation`); CLI can parse both MAA and raw evidence for policy hydration |
| systemd unit | `ExecStart=/usr/local/bin/attestation_server` (binary installed by Earthly) |

> **Naming.** The handler is `get_attestation` (feature-gated bodies). Types
> `AttestationEvidence` / `report_data_binding` live in the server crate (PR #11), not only
> in design docs.

### What this PR (`feat/attested-channel`) adds on top

The attested **key-exchange channel** (issue #15): `akx` crypto core, epoch key +
`GET /enclave-key`, `POST /session[/complete]`, `POST /proxy`, Python client, background
attestation refresh, and VM wiring. Epoch-key attestation **reuses**
`generate_attestation(nonce, payload)` — the same evidence path as `GET /` — for both
`maa` and `raw-report` builds (binds `report_data = H("temenos-akx-v1" ‖ epoch ‖ pk_e)`
via payload / HCL report-data). No duplicate SNP/vTPM collection.

---

## 2. The core design decision: two-tier keys

Issue #15's **Option 1 + polling** wants to *pre-generate and cache/poll* the enclave's
ephemeral-key attestation to hide the ~3s cost. But §6 of the protocol requires the
attestation to **bind the client's `nonce_c` and ephemeral key** (client-first ordering),
which is inherently **per-session** and therefore *not* cacheable across clients. You cannot
both cache one attestation and bind per-client data into its `report_data`.

We resolve this with a **two-tier key model** (the standard "attested long-term key +
per-session signed DH", i.e. what RA-TLS / an attested certificate does):

1. **Epoch tier — cacheable / pollable (this is Option 1's route).**
   Inside the TEE, generate a medium-lived **Ed25519 signing key** `K_e` (rotated per boot /
   per polling interval). Produce **one** SEV-SNP attestation with
   `report_data = H("temenos-akx-v1" ‖ epoch ‖ pk_e)`. This is the expensive step; it is
   amortized and can be polled/refreshed in the background.

2. **Session tier — cheap, per client.**
   The client sends `ClientHello { sid, nonce_c }`. The enclave generates a **fresh
   ephemeral HPKE (X25519) keypair** `S_sess`, **signs the transcript**
   `H("temenos-akx-v1" ‖ sid ‖ nonce_c ‖ S_sess)` with `K_e`, and returns
   `{ S_sess, sig }` (plus the cached epoch attestation). The client verifies the
   attestation once (cached) and the signature per session, then both sides run HPKE to
   derive directional AEAD keys.

This keeps **all** the §6 security properties — server authentication (only the enclave
holds `sk_e`), forward secrecy (fresh `S_sess`), transcript / unknown-key-share binding
(signature over `nonce_c ‖ S_sess`), freshness (`nonce_c`) — while making the *attestation
itself* cacheable. The only spec change is that `report_data` now commits to the enclave's
long-term key, and the per-session binding is provided by a signature rather than by the
attestation directly. **§6 of `tls-channel-binding.md` will be updated to describe this
two-tier variant (Phase 6).**

### What is an “epoch”?

An **epoch** is a stretch of time during which the enclave uses **one fixed Ed25519
signing key** (`sk_e` / `pk_e`) as its medium-lived identity. Many client sessions can
share that key. At the start of an epoch the TEE:

1. generates `K_e` inside the enclave (`sk_e` never leaves),
2. attests `pk_e` once (the expensive step), and
3. then **signs** each per-session handshake transcript with `sk_e`.

Think of the epoch key as a **TEE passport** (attested, reused for a while) and each
session HPKE key as a **one-time ticket** signed by that passport. The `epoch` counter is a
`u64` persisted under `/var/lib/attestation_server/epoch` and incremented at each process
start (boot); optional timed rotation is controlled by `AKX_EPOCH_ROTATE_SECS`. Clients
discover a new passport via a refreshed `GET /enclave-key`.

**Why not sign sessions with the hardware root of trust instead?** On Azure SEV-SNP
CVMs the guest does not get a general-purpose “sign arbitrary bytes” API from VCEK/AK —
those keys produce **attestation-shaped** objects (SNP reports / TPM quotes). A
quote-per-session would reintroduce the ~3 s cost this design amortizes. We therefore use
the classic hierarchy: the platform RoT **attests** `pk_e` once (via MAA *or* raw HCL
report-data binding from PR #11); `pk_e` **signs** sessions often. Compromise of `sk_e`
can mint fake sessions until the next epoch rotation — which is why epochs are
medium-lived.

### Locked decisions

| # | Decision | Choice | Rationale |
| --- | --- | --- | --- |
| D1 | Attestation binding | **Two-tier** (epoch key attested + per-session signed DH) | Meets the issue's latency goal *and* §6's security properties |
| D2 | Client attestation verification | **Delegate to Warden** (`verify_attestation`) | Reuse audited verification; less new crypto in the CLI |
| D3 | Decrypt-and-forward proxy | **Extend the host attestation server** on internal `:8000`, forward to the DApp | Reuses TPM access; Caddy provides the public TLS endpoint |
| D4 | Crypto stack | **HPKE (RFC 9180)** X25519 / HKDF-SHA256 / AES-256-GCM + **Ed25519** epoch key | Standardized, WebCrypto-portable for the future extension client |

---

## 3. Target architecture

```
                          ┌───────────────────────── Veritee CVM (SEV-SNP) ─────────────────────────┐
                          │                                                                          │
 client (cli.py /         │   Caddy :443 → attestation_server (host, systemd, internal :8000)      │
 browser extension)       │   ┌───────────────────────────────────────────┐                        │
      │                   │   │  GET  /                (MAA or raw SEV-SNP evidence) │                        │
      │  1. GET /enclave-key   │  GET  /enclave-key     epoch pk + attest (cacheable/pollable)               │
      │─────────────────────► │  POST /session         ClientHello → S_sess + epoch-signed transcript│
      │  2. verify attest      │  POST /proxy           AEAD records → decrypt in-VM → forward       │──┐
      │     (via Warden)   │   └───────────────────────────────────────────┘                        │  │ loopback / bridge
      │  3. POST /session      │            │ akx crate (HPKE + Ed25519 + AEAD, TPM-free, unit-tested)│  ▼
      │◄─────────────────────► │            │ Attester: reuse generate_attestation (maa|raw), fake=tests │  DApp (:8080 loopback)
      │  4. POST /proxy (AEAD) │                                                                      │
      └───────────────────►    └──────────────────────────────────────────────────────────────────┘
```

The `akx` crate is transport-agnostic and TPM-free, so it builds and is fully unit-tested on
any platform (incl. CI) without a TEE. Platform evidence gathering lives behind an `Attester`
trait with a **fake** implementation for CI and a **real** implementation that calls
`generate_attestation` — the same path as `GET /` for both the `maa` and `raw-report`
features from PR #11. A free-form guest `/dev/sev-guest` report is **not** used; raw mode
binds via Azure HCL `get_report_with_report_data`.

---

## 4. The protocol (as implemented)

Notation follows `docs/tls-channel-binding.md` §6.

```
Epoch setup (once per epoch, cacheable):
  (sk_e, pk_e) ← Ed25519.KeyGen()                      # inside TEE, sk_e never leaves
  report_data  = H("temenos-akx-v1" ‖ epoch ‖ pk_e)
  attest       = generate_attestation(payload = report_data)  # maa or raw-report (PR #11)
  publish {epoch, pk_e, attest}                        # GET /enclave-key

Per session:
  Client → Server : ClientHello { sid, nonce_c }
  Server (TEE)    : (s, S_sess) ← X25519.KeyGen()
                    T   = H("temenos-akx-v1" ‖ sid ‖ nonce_c ‖ S_sess)
                    sig = Ed25519.Sign(sk_e, T)
  Server → Client : ServerHello { S_sess, sig }        # POST /session response
  Client          : verify attest binds pk_e (Warden); verify sig over recomputed T
                    (enc, ctx) = HPKE.SetupBaseS(S_sess, info = T)
  Client → Server : enc                                # carried on first POST /session
  Server          : ctx = HPKE.SetupBaseR(s, enc, info = T)
  Both            : k_c2s = HPKE.export(ctx, "…c2s"); k_s2c = HPKE.export(ctx, "…s2c")

Record layer (POST /proxy):
  AEAD_seal(k_dir, nonce = dir(1)‖0‖seq(8), aad = sid, plaintext)   # AES-256-GCM
  strictly monotonic per-direction seq (carried in the GCM nonce, not AAD).
  Authenticated close is **deferred** (request/response `/proxy` detects truncation
  via the next expected record failing AEAD; a typed close record is a follow-up).
```

This is HPKE (RFC 9180) with the enclave's ephemeral key as the recipient key and the
transcript hash as `info`, authenticated by the epoch signature.

---

## 5. Phased delivery

Each phase is a small, independently reviewable PR. "Testable off-CVM" means it runs in CI
without a TPM.

### Phase 0 — AKX crypto core ✅ (landed on `feat/attested-channel`)

- New standalone crate **`server/akx/`** (no TPM deps → builds & tests anywhere).
  - `epoch.rs` — Ed25519 `EpochKey`, `report_data_for(epoch, pk)` binding.
  - `session.rs` — `enclave_begin` / `enclave_complete` / `client_establish` (HPKE X25519/HKDF-SHA256/AES-256-GCM).
  - `record.rs` — directional `RecordKey` with monotonic sequence numbers.
  - `transcript.rs` — domain-separated, length-prefixed transcript hashing.
- **10 unit tests** covering the handshake round-trip and the §7 attacks the crypto owns:
  key substitution (A2/A8), stale/replayed attestation (A3), record tampering & AAD rebinding
  (A6), reorder/replay (A5), direction separation, forward secrecy, `report_data` binding.
- **`.github/workflows/ci.yml`** — fmt + clippy (`-D warnings`) + test (the repo had no CI).
- **Testable off-CVM:** yes.

### Phase 1 — Attester abstraction + epoch key + `GET /enclave-key` 🔄 (implemented; pending on-CVM validation)

- `akx` crate (tested off-CVM):
  - `Attester` trait — `fn attest(&self, report_data: &[u8;64]) -> Result<Vec<u8>, AkxError>`;
    returns an opaque bundle (verification delegated to Warden, D2).
  - `FakeAttester` — deterministic (`b"FAKE" ‖ report_data`) for tests/CI.
  - `EpochManager` — generates the `EpochKey` inside the TEE, attests `pk_e` once, caches the
    bundle, and begins per-session handshakes. `sk_e` never leaves the struct.
  - 3 new unit tests (epoch→attestation binding, manager-driven handshake round-trip, attester
    failure propagation) — **13 tests total**, all green.
- `azure_attestation_server` crate (validated on CVM):
  - `get_attestation` delegates to shared `generate_attestation(nonce, payload)` for both
    **`maa`** and **`raw-report`** features (PR #11) — the single evidence path used by
    `GET /` and by Charles'/Lace-style clients. **No SNP/vTPM evidence gathering is
    re-implemented.**
  - `PlatformAttester` (real) — binds `pk_e` by passing `report_data` (base64) as the
    attestation `payload` (with a fixed nonce) through `generate_attestation`; the returned
    `ResponseStruct` / `AttestationEvidence` is the opaque attestation bundle.
  - `GET /enclave-key` → `{ epoch, epochPublic, attestation }` (cacheable/pollable), served from
    the cached `EpochManager` state; wired in `main()` alongside the existing `GET /`.
- **`report_data` binding decision.** Guest code does not drive `/dev/sev-guest` directly.
  Binding uses PR #11's paths: MAA `client_payload`, or Azure HCL
  `get_report_with_report_data` under `raw-report`. Warden already verifies these evidence
  shapes; it binds the epoch key by recomputing
  `report_data = H("temenos-akx-v1" ‖ epoch ‖ pk_e)` from the returned `pk_e`.
- **Testable off-CVM:** `akx` side fully (fake attester); the `PlatformAttester` + route compile
  and are validated on the CVM (the server crate cannot build off-CVM due to `tss-esapi`).

### Phase 2 — Session store + `POST /session` ✅ (implemented)

- `akx` crate (tested off-CVM):
  - `SessionStore` — concurrent (`Mutex<HashMap>`), keyed by `sid`, entries transition
    `Pending → Established`; enforces a **TTL** and a **max-session cap** (mitigates setup-flood
    DoS, §7 A8), with `evict_expired`. Established keys are boxed so pending entries stay small.
  - `SessionError` (`Duplicate`/`Full`/`NotFound`/`WrongState`/`Akx`) and `SessionConfig`.
  - 6 new tests (store-driven full handshake incl. record exchange, duplicate-sid, capacity,
    unknown-complete, double-complete, eviction) — **19 tests total**, clippy `-D warnings` clean.
- `azure_attestation_server` crate (validated on CVM):
  - `AppState { epoch, sessions }` with `FromRef` so handlers extract sub-state.
  - `POST /session` — `ClientHello { sid, nonceC }` → `{ enclaveSessionPub, signature }` (stores pending).
  - `POST /session/complete` — `{ sid, enc }` → `204` (derives + stores directional record keys).
  - `SessionRouteError` maps store errors to HTTP status codes.
- **Testable off-CVM:** yes (store + handshake via `akx` + fake attester).

### Phase 3 — Record layer + decrypt-and-forward `POST /proxy` ✅ (implemented; superseded by Phase 7 HTTP tunnel)

- `azure_attestation_server` crate (validated on CVM):
  - `POST /proxy` — `{ sid, ciphertext }` → `{ ciphertext }`. The handler `open`s the client
    record in-VM (`with_records`, aad = `sid`), forwards the plaintext to the DApp, then `seal`s
    the response on the `s2c` key. The store lock is **not** held across the upstream await
    (open → forward → seal are separate `with_records` calls); a **per-`sid` async mutex**
    (`ProxyGates`) serialises the full round-trip so concurrent `/proxy` calls cannot
    desynchronise c2s/s2c sequence counters. Distinct sessions stay concurrent.
  - `DappUpstream` — cloneable `reqwest`-backed upstream in `AppState`, configured via
    `DAPP_UPSTREAM_URL` (default `http://127.0.0.1:8080`). The initial implementation posted
    plaintext as an `application/octet-stream` body; Phase 7 replaces that body-only contract
    with the versioned HTTP tunnel described below.
  - `ProxyError` maps failures to status codes: unknown/expired `sid` → `404`, not-yet-
    established → `409`, AEAD open/seal failure → `400`, upstream error → `502`. Any per-record
    failure **drops the session** (the record streams are desynchronised); errors are coarse to
    avoid padding-oracle-style probing.
- `akx` crate (tested off-CVM):
  - 2 new tests — multi round-trip sequence continuity across separate `with_records` calls
    (the exact open→forward→seal pattern the handler uses), and bad-record → session-drop —
    **21 tests total**, clippy `-D warnings` clean.
- **Forwarding path (D3):** the exact host→DApp hop (Caddy `api` endpoint vs. a loopback-
  published `app` port) is resolved in Phase 5 via `DAPP_UPSTREAM_URL`; the app is currently
  only reachable via Caddy / internal Docker networks.
- **Testable off-CVM:** record-layer wiring is covered in `akx` with a stub upstream; the axum
  handler compiles in CI (`attestation-server-build`) but runs only on the CVM.

### Phase 4 — Python reference client (`cli/veritee/attested_channel.py`) ✅ (implemented)

- New module `cli/veritee/attested_channel.py` (mirror of `akx`, client side):
  - `transcript_hash`, `report_data_for`, `verify_epoch_sig` (Ed25519), a from-scratch HPKE
    (RFC 9180, mode Base, `DHKEM(X25519,HKDF-SHA256)`/`HKDF-SHA256`/`AES-256-GCM`) **sender +
    export**, and the directional `RecordKey` — all WebCrypto-portable primitives so the
    Chromium extension can reuse the exact protocol.
  - `create_session()`: `GET /enclave-key` → verify attestation **via Warden** (D2, pluggable
    `AttestationVerifier` / `make_warden_verifier`) → `POST /session` → verify `sig` over the
    recomputed transcript → HPKE `SetupBaseS` → derive `k_c2s`/`k_s2c` → `POST /session/complete`.
  - `prove(...)`: AEAD-seal (aad = `sid`) → `POST /proxy` → AEAD-open the response.
  - `Transport` abstraction with `HttpTransport` (requests) for production.
- CLI: `veritee attested-prove` (establish + tunnel one request; Warden verification by default,
  `--skip-warden` for local testing).
- Tests (`cli/tests/test_attested_channel.py`, **13 tests**):
  - transcript / `report_data` vectors captured from the Rust `akx` crate (cross-impl agreement);
  - record-layer round-trip, tamper/AAD/direction rejection; HPKE export determinism;
  - **end-to-end interop** against the real Rust crypto via a new `akx` `enclave_stub` example
    (stdin/stdout enclave). This is the authoritative HPKE interop check — the proxied round-trip
    only succeeds if Python and Rust derive identical record keys.
- **Testable off-CVM:** yes — the `akx` `enclave_stub` example stands in for the CVM-only server
  (which cannot build off-CVM due to `tss-esapi`). New CI job `python-client` builds the harness
  and runs the pytest suite.

### Phase 5 — VM image integration ✅ (implemented; on-CVM e2e pending)

- Fixed `services/attestation_server.service`:
  - `ExecStart=/usr/local/bin/attestation_server` (matches the Earthly-installed binary;
    the old `target/debug` path under `/opt` was deleted by `mkosi.postinst`).
  - `After=network-online.target measured-setup.service`; `StateDirectory=attestation_server`.
  - Env: `DAPP_UPSTREAM_URL=http://127.0.0.1:8080`, `AKX_EPOCH_FILE=…`, refresh/rotate knobs.
- Enabled at boot: `copy_services.sh.j2` now installs
  `multi-user.target.wants/attestation_server.service` (and azure-provisioning).
- **Epoch key-gen timing:** at **process start** (systemd), not in `measured-setup`. Each
  boot increments a persisted counter in `/var/lib/attestation_server/epoch`.
- **Host → DApp hop (D3):** Caddy publishes **loopback-only** `127.0.0.1:8080:8080`
  and forwards to the app's private network. The host attestation server's
  port `8000` is accepted only from Docker bridge interfaces and is not exposed by the
  Azure NSG; public attestation and AKX traffic enters through Caddy on port `443`.
- On-CVM end-to-end validation with the real attester remains a deployment checklist item
  (cannot be automated off-CVM).

### Phase 6 — Latency optimization + spec sync ✅ (implemented)

- **Server:** `EpochManager::refresh_attestation` (same key, fresh evidence) and
  `::rotate` (new epoch key). Background tokio tasks driven by
  `AKX_ATTEST_REFRESH_SECS` (default 300) and optional `AKX_EPOCH_ROTATE_SECS`.
  `GET /enclave-key` stays non-blocking; the ~3 s MAA/HCL cost is paid out of band.
- **Client:** `EpochKeyCache` for pre-polling; `create_session` reuses the cache and
  refreshes once if the epoch rotated underfoot. New pytest covers cache reuse.
- **Spec:** `docs/tls-channel-binding.md` §6 marked pedagogical vs §6.1 plan-of-record;
  properties + A2 defense updated for the two-tier model; operational refresh/rotation
  documented in §6.1.
- `akx` tests: refresh keeps key / updates attestation; rotate changes key — **25 tests**.

### Phase 7 — General HTTP proxying for real DApp traffic ✅ (implemented)

Issue [#19](https://github.com/input-output-hk/veritee-vm/issues/19) tracks this
proxy improvement. The first proxy was enough to prove the encrypted channel worked, but
real clients need it to behave more like a small HTTP tunnel.

The intended behavior is:

- `DAPP_UPSTREAM_URL` is always the DApp base URL, for example `http://127.0.0.1:8080`.
  It should not point to one specific route like `/prove`.
- The client can request different upstream paths through the same attested session, for
  example `/check`, `/prove`, or `/health`.
- The proxy should preserve the upstream HTTP method, so `GET /check` remains a `GET` and
  `POST /prove` remains a `POST`.
- Request method, path, query values, allowlisted headers, and request body are carried inside
  the encrypted tunnel envelope. This keeps the outer proxy route stable while allowing the
  DApp to receive normal HTTP-shaped traffic.
- Normal DApp responses, including `400`, `404`, or `500`, should be returned to the
  client as DApp responses. They should not be hidden behind a generic proxy `502`.
- A normal DApp error should not destroy the attested session. Only cryptographic record
  failures, malformed tunnel records, or real proxy transport failures should force the
  client to create a new session.

The implementation replaces the current body-only proxy contract with a versioned
HTTP tunnel contract. The proxy represents the route explicitly for forwarding,
preserves request arguments, and always encrypts upstream response status/body back
to the client. This keeps one clear protocol shape instead of carrying a legacy
body-only mode that real clients have already outgrown.

Minimal tunnel envelope:

```json
{
  "version": 1,
  "request": {
    "method": "POST",
    "path": "/prove",
    "query": [["count", "10"]],
    "headers": {
      "content-type": "application/json"
    },
    "body": "base64..."
  }
}
```

Response envelope:

```json
{
  "version": 1,
  "response": {
    "status": 400,
    "headers": {
      "content-type": "application/json"
    },
    "body": "base64..."
  }
}
```

The proxy reconstructs the upstream URL by resolving `path` relative to
`DAPP_UPSTREAM_URL` and appending the encrypted query fields after decryption.

Headers are in scope for Phase 7, but only as an allowlisted set at first. `Content-Type`
is required immediately for proof-server `POST /prove`; forwarding arbitrary client headers
is intentionally out of scope until there is a concrete need.

Because Phase 7 introduces client-selected paths, the SSRF defense changes from "no
client-controlled destination" to "client-controlled relative path only":

- `DAPP_UPSTREAM_URL` remains the only upstream origin and must be loopback / local-network
  scoped by deployment policy;
- `path` must be absolute-path form (`/prove`, `/check`) and must reject `..`, encoded path
  traversal, scheme/host prefixes, and control characters;
- measured DApp `metadata.json` declares `proxy_allowed_paths`, for example
  `["/check", "/prove"]`. The CLI validates it, registration replays the exact
  packaged bytes, and measured setup publishes `/run/temenos/dapp-proxy.json`
  only after successful DApp startup. Both OS targets install the shared
  CLI/guest policy helper. The OS service sets `DAPP_PROXY_POLICY_FILE` to that
  file; missing/empty policy denies forwarding, and invalid policy fails server
  startup. A configured file never falls back to `DAPP_PROXY_ALLOWED_PATHS`.
  That comma-separated variable remains available for standalone development
  when no policy file is configured. The handshake authenticates the server;
  route configuration separately limits which internal routes it exposes;
- the proxy must not allow clients to override host, scheme, port, or destination IP.

Error handling:

| Failure | Session | Client-visible result |
| --- | --- | --- |
| DApp returns `2xx` | keep | encrypted response `{ status, headers, body }` |
| DApp returns `4xx` / `5xx` | keep | encrypted response `{ status, headers, body }` |
| DApp connection refused / timeout / invalid upstream URL | drop | proxy transport error, outer `502` |
| AEAD failure / malformed tunnel record / sequence mismatch | drop | proxy protocol error |
| Unknown or expired session | no session | proxy session error |

The generic Python `request()` API returns upstream status, headers and body,
including errors, without ending the session. The `prove()` convenience wrapper
raises `UpstreamHttpError` on a non-2xx response and retains that response on the
exception. `attested-prove` also exits non-zero instead of printing an error body
as a successful proof. Redirects are non-success responses and are not followed.

Client migration for Phase 7 touches the Python reference client
(`cli/veritee/attested_channel.py`), the Rust `akx` `enclave_stub` interop harness,
and the Lace client integration. All three should use the same envelope shape.

Minimum validation for this phase:

- `/check` can be called as `GET`;
- `/prove` can be called as `POST`;
- `Content-Type: application/json` can be forwarded for `POST /prove`;
- request arguments/query values are preserved according to the chosen privacy mode;
- responses are encrypted back to the client;
- upstream non-2xx responses are visible to the client and do not kill the session;
- transport/protocol failures still drop the session;
- path traversal and absolute-destination attempts are rejected;
- the proof-server demo still works through the new HTTP tunnel shape.

Privacy modes considered for this phase:

- **Strict mode:** encrypt method/path/query/body inside the tunnel. The outer route only says
  "attested proxy". This gives the cleanest confidentiality boundary, but is less like a normal
  reverse proxy.
- **Suggested middle ground:** keep method/path visible as routing metadata, but encrypt query
  values / request arguments and request bodies. Route names are treated as non-secret, while
  user/application inputs stay inside the attested channel.
- **Simple mode:** keep method/path/query visible and only encrypt request bodies plus
  responses. This is closest to normal reverse-proxy behavior, but clients must treat query
  strings as non-secret.

The implemented wire format uses the strict envelope shape: method, path, query values,
allowlisted headers, request bodies, and responses are inside the encrypted attested channel.

Responses should be encrypted back to the client in all modes.

---

## 6. Testing strategy

| Layer | Tests | Runs in CI? |
| --- | --- | --- |
| `akx` crypto core | Handshake round-trip, §7 attacks (tamper, replay, reorder, key substitution, transcript mismatch), FS, `report_data` binding, RFC 5869/9180 conformance | ✅ (Phase 0) |
| Attester | Fake attester unit tests; real SNP path smoke-tested on CVM | Fake: ✅ |
| Session store | TTL/eviction, max-sessions, pending→established transitions | ✅ |
| Record layer | Proxy-style sequence continuity across round-trips, bad-record → session drop, stub upstream forward | ✅ |
| Client ↔ server | pytest interop with fake attester (handshake + `prove` round trip) + negative cases | ✅ |
| End to end | Real attestation on the CVM; latency measurement | On-CVM |
| Epoch refresh / rotate | Same-key refresh updates attestation; rotate changes key + epoch | ✅ |
| Phase 7 HTTP tunnel (#19) | GET `/check`, POST `/prove` with `Content-Type`, encrypted non-2xx response propagation, session survival on DApp errors, session drop on transport/AEAD errors, path validation | ✅ |

---

## 7. Open items / risks

- **`report_data` binding on Azure CVMs.** Resolved by reusing PR #11's `generate_attestation`
  paths (MAA `client_payload` or raw HCL `get_report_with_report_data`). Remaining: on-CVM
  confirmation that the epoch `report_data` round-trips into the evidence where Warden reads it.
- **Warden binding check.** Warden already verifies both `AttestationEvidence` shapes; confirm it
  recomputes `report_data` from the returned `pk_e` (or accepts `expected_report_data` from
  the Python client).
- **On-CVM e2e** of Phases 1–6 (real `PlatformAttester`, systemd unit, loopback `/proxy` hop,
  Python `attested-prove`).
- **Cross-compile of the server** off-CVM is blocked by `tss-esapi`; the `akx` split keeps the
  crypto core independently buildable/testable regardless.
- **Phase 7 / issue #19 HTTP tunnel.** Remaining work is on-CVM validation with a real DApp
  and client migration outside this repository. The server, Python reference client, and
  Rust interop harness use the same versioned envelope.
