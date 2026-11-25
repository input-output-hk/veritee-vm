# OS Release Approval: Phase One

Phase one admits an immutable base-OS release after an enrolled developer
approves its manifest and the Warden checks its published files. It does not
rebuild the OS, attest a complete dependency inventory, or qualify a release as
`warden_reproduced`. No manifest or signature is added to the guest filesystem,
PCR inputs, or authored DApp metadata.

This feature requires the matching Warden and smart-contract changes. The ledger
layout is different: deploy a new version-matched registry before enabling it.
The old public `/os/build_os` route is disabled. Existing unlinked registrations
need app reproduction and fresh attestation; neither PCR4 nor a version string
is enough to backfill their association. Preserve the old ledger and its export.
The generic migration command refuses unsafe registration replay before writing.

## Release Producer

Use a clean source checkout for an approvable release. A dirty build may still
be built for development, but schema/recipe version one refuses to approve it.
The successful Azure SNP release build retains `local-base-os/os-build.json` with
its source identity, actual invocation, and output hashes. A changed source
tree during the build, or changed output files afterwards, prevents emission.

```bash
veritee build-base-os-image --azuresnp --attestation-mode raw-sev-snp
veritee push-base-os-image --input-dir local-base-os \
  --base-os-image registry.example/temenos/base-os:0.6.0-raw-sev-snp
veritee os-release manifest --input-dir local-base-os \
  --release-id temenos-0.6.0-release-1 --version 0.6.0-raw-sev-snp \
  --reference registry.example/temenos/base-os:0.6.0-raw-sev-snp@sha256:<published-digest> \
  --source-repository https://github.com/input-output-hk/veritee-vm \
  --output os-release-manifest.json
```

Replace the example registry with the configured release carrier and use the
digest reported by publication. A tag alone is rejected before manifest creation
or approval. The manifest
has canonical UTF-8 JSON bytes and no trailing newline. Its SHA-256, not the
Docker tag or PCR4, is the OS key. A modified manifest needs a new release ID.
The sidecar stays outside the scratch carrier it identifies.

Version one supports bound, non-debug Azure SNP releases, `maa` and
`raw-sev-snp`, the SHA-256 Azure CVM PCR4 profile, and exactly `disk.raw` plus
`pcrs.json`. Other recipes, dirty-source bundles, extra artifact types and
unknown measurement fields fail closed rather than being silently ignored.
The published JSON schemas are in `cli/veritee/schemas/os-release-v1.schema.json`.

## Developer Approval

Generate a separate developer key, not an application, wallet, or TLS key:

```bash
veritee os-release keygen \
  --private-key /secure/path/developer.pem \
  --public-key /secure/path/developer.pub.pem
```

The command prints the SHA-256 fingerprint of DER SubjectPublicKeyInfo. Have
the operator enroll that fingerprint and public key against your stable
developer identity with the `approve_release` operation. The private key is
created with mode 0600, never uploaded, and must stay outside the repository and
build context. The signing command refuses group/other-readable private keys.

```bash
veritee os-release sign --manifest os-release-manifest.json \
  --private-key /secure/path/developer.pem \
  --warden-id preprod-release-authority --network preprod \
  --registry <new-os-registry-address> --output approval.json
export VERITEE_WARDEN_URL=https://<configured-warden>
veritee os-release submit --envelope approval.json
veritee job-status <returned-job-id> --poll
```

After validating the signature and published files and retaining the evidence,
Warden returns 202 with the local approval, `chain_status: pending` and a job URL.
The OS is listed in memory while the worker publishes it on-chain. The job only
succeeds after confirmation. `os-release select` and DApp chain registration
still require the confirmed OS entry; local approval is not chain confirmation.

The audience identifies the Warden authority, ledger network and exact registry.
It is unrelated to the network served by a DApp: a mainnet proof server can be
registered on the configured preprod Veritee ledger. Signing uses flattened
ES256 JWS with canonical payload bytes and a raw 64-byte `R || S` signature.

The Warden authenticates before retrieving artifacts. Its anonymous approved
Docker/ACR reader never runs a container; it bounds transfer and extraction,
verifies carrier descriptors and refuses links, traversal and oversized
archive headers, then checks the exact signed file sizes/hashes and PCR4 file.
The supported scratch layout is the existing publisher's `/temenos/disk.raw`
and `/temenos/pcrs.json`, extracted into a private directory without executing it.
Only blob-download redirects from an approved ACR are allowed, at most three
times, to HTTPS Azure Blob storage or that registry's regional data endpoints.
Registry Authorization headers are removed before following them. Manifest and
token redirects remain forbidden. Direct connections reject non-public DNS
answers and pin the checked address while preserving TLS hostname verification.
With a configured HTTPS proxy, resolution/filtering belongs to that trusted proxy.
Private carriers requiring another credential flow are not supported by this
initial reader; it will not forward Azure or wallet credentials to a registry.

## Accepted OS Selection

Install the matching contract CLI and its locked dependencies, with Linux
Node.js available on PATH. Configure an explicit network and registry:

```bash
export VERITEE_ATTESTATION_CLI_DIR=/path/to/temenos-smart-contracts/attestation-cli
export VERITEE_OS_NETWORK=preprod
export VERITEE_OS_REGISTRY=<new-os-registry-address>
veritee os-release list
# Set metadata.json.base_os_image to the exact digest-pinned IMAGE from the list.
veritee package-dapp-deployable-vm-image --app-dir examples/my-app
veritee register-app --metadata-path local-azure-snp/metadata.json
```

The default listing shows OS version, attestation mode and exact image
reference; `--json` also includes the internal identifiers. Only confirmed,
digest-pinned releases are listed as available. Unknown and ambiguous image matches fail;
the CLI never silently chooses the newest release.
The listing warns and skips entries whose evidence cannot be retrieved or
verified. Automatic image selection remains strict when such an entry could
hide another match; an explicit verified `--os-release-key` can isolate that
selection. Repository plus digest determines carrier equality: an optional
tag before `@sha256:` does not change its identity or the signed manifest bytes.

Pull and packaging resolve the approval from the chosen `base_os_image`.
`--os-release-key`, `VERITEE_OS_RELEASE_KEY` and `os-release select` remain
advanced inspection/packaging controls, not normal DApp registration steps.
Even an explicit selector must match the project's image reference.

Registration sends the original DApp metadata, not an OS selector or signing
key. Warden resolves the exact digest-pinned carrier against confirmed entries
in its configured registry, checks the retained canonical manifest and its
typed identity, and checks PCR4/mode against fresh attestation. It derives the
OS link and version before reproducing the app and publishing the registration.
No local contract CLI, OS-registry environment variables or selection sidecar
are needed for the registration command. Optional hints from older clients
are rejected if they disagree with the server's result.

Selection reads confirmed typed contract state directly,
then obtains hash-checked manifest/acceptance evidence through the Warden. It
checks the historical developer signature without requiring that old key to
remain enrolled today. Packaging repeats published-file validation and checks
the resulting VM PCR4. A moved tag supplying different bytes fails.
Downloads and extraction have a 1,800-second deadline. Slow links may set
`VERITEE_OS_DOWNLOAD_TIMEOUT_SECONDS` to an integer from 1 to 86,400.

The project's `base_os_image` must agree with the selected manifest; the CLI
does not rewrite `metadata.json`. `os-release-selection.json` remains a separate
packaging sidecar and is not used as registration authority. The registration
stores the server-resolved typed OS link atomically with its
attestation, plus `base_os_version` and `base_os_release_manifest_digest` in
the bounded on-chain metadata projection. It does not add a PCR measurement.

Version labels and equal PCR4 values do not make two accepted releases
interchangeable. Registration requires exactly one approved manifest for the
exact image reference; an operator must resolve duplicate approvals.

## Evidence and Recovery

Evidence uses the existing verification WORM container under `os-releases/v1/`,
outside the runtime Merkle batches. It retains the original manifest/envelope,
developer public key and enrollment snapshot, file-validation report and
acceptance record. The acceptance digest is committed on-chain only after the
complete evidence graph is retained and read back under locked retention.
Public OS detail responses contain verified evidence, never storage credentials.

Request IDs are scoped by signer, audience and operation. Reusing an ID with
different bytes fails. Retain `approval.json`: resubmit the exact same bytes to
query its durable status, not a newly generated ECDSA signature. An expired
request can report retained status but cannot start new work.

The Warden resumes accepted pending approvals from WORM after restart. Artifact
validation and evidence retention do not hold the wallet-writer lock; only
publication of prepared evidence shares that lock with other chain writers.
Transient failures use at most five
attempts, with 30-second exponential backoff capped at ten minutes. A prepared
approval is reused after a chain timeout, with confirmed-state reconciliation
before another submission. Failed validation or exhausted retries requires
operator review; re-signing another request ID cannot reset the work history.
There is no public reset/override endpoint. Recovery enumerates retained work
without an age cutoff, under the configured process deadline. The receipt and
work-history fields `accepted_at`, `started_at`, `deadline` and `retry_after`
use UTC Unix seconds; signed payload timestamps use RFC 3339 whole seconds.

Removing a developer key prevents new approvals and pending commits, but does
not withdraw a completed OS release. OS withdrawal is not part of phase one.
`require_reproduced_os` defaults to false in trusted Warden configuration;
turning it on rejects phase-one entries for new registration and fresh
verification. No request can lower that setting. Phase-two receipt readers,
rebuild workers and qualification submission are intentionally not implemented.

## Before Deployment

Keep one signing writer per wallet. Stop/drain the original Warden and its
anchoring jobs before another instance or a deployment CLI uses the same
wallet. The in-process writer lock does not coordinate two VMs. Preserve seed
custody, private checkpoints, the old ledger and its audit archive during the
reviewed migration; this implementation does not perform that migration.

Use the matching source versions in all three repos and regenerate Compact
bindings/proving assets. Update the Warden image's pinned VM/contract revisions
only after those source revisions exist; never replace them with mutable branch
names. Configure enrollment, limits, archive retention and permissions as in the
Warden's `deploy/os-release-config.example.json` and approval documentation.

Rehearse an actual approval, archive inspection, accepted OS selection, DApp
registration and fresh verification on a disposable new registry. Offline
simulator and mocked archive tests are not a claim that that live rehearsal has
already occurred, or that any existing deployment was changed.
