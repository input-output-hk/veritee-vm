# Veritee VM operator guide

This guide covers the full build, package, deploy, register and verify
workflow for Veritee VM. The [README](../README.md) has the installation steps
and a short quick start; this document has the details and the options.

## Runtime networking

Outbound traffic is default-deny for runtime DApp containers. DApps declare
required TCP destinations in their metadata; the packaged, measured metadata
contains the hostname and literal-IP policy enforced by the guest firewall and
egress proxy.

Public inbound traffic is limited to Caddy on ports `80` and `443`. The guest
firewall permits port `8000` only from Docker bridge interfaces so Caddy can
reach the host attestation server.

Host egress retains only the Azure platform paths required for DHCP, IMDS, and
wireserver access. Only the two unprivileged egress-proxy users can query Azure
DNS or connect to measured application/platform destinations. Containers do not
inherit the host's platform grants. The measured `warden` profile is the narrow
exception: its fixed container IP receives direct Azure DNS, TCP 443, and IMDS
access for Warden dependencies that do not support HTTP CONNECT proxies. Its
dedicated builder bridge receives Azure DNS and proxy access for HTTPS; direct
public traffic and IMDS remain blocked.

## Environment Variables

| Variable | Purpose |
|----------|---------|
| `VERITEE_ACR_NAME` | Azure Container Registry name required by ACR-backed image operations |
| `VERITEE_WARDEN_URL` | Warden base URL used by registration and verification commands |
| `VERITEE_GUEST_ATTESTATION_IMAGE` | Optional override for the pinned guest helper image; also available as `--guest-attestation-image` |
| `DOCKERHUB_USER` / `DOCKERHUB_TOKEN` | Optional Docker Hub credentials for Earthly pulls; omit both for anonymous, rate-limited pulls |
| `ARM_SUBSCRIPTION_ID` | Azure subscription used by VM deployment inventory commands |
| `VERITEE_INVENTORY_STORAGE_ACCOUNT` | Optional override for the tagged inventory Storage account discovered by the CLI |
| `VERITEE_INVENTORY_CONTAINER` | Audit container name; defaults to `temenos-inventory` |

## Building the guest attestation helper

```bash
veritee build-guest-attestation
```

The local image is named `guest-attestation:local`. Packaging uses the pinned
published helper image. To select a different published image, set
`VERITEE_GUEST_ATTESTATION_IMAGE` or pass `--guest-attestation-image`. Warden must
use the same image when reproducing the app disk. Build inputs and dependency
checks are defined in the [helper Dockerfile](../server/guest_attestation/Dockerfile).

Use matching Veritee CLI versions and project templates for packaging and
Warden reproduction.

The DApp helper service is `guest-attestation`. It reads
`.guest-attestation.env` and shares `constrained-attestation` with Caddy.
Caddy uses the private DNS alias required by the pinned helper image.

## Building a Base Veritee OS Image

The CLI selects `veritee-os/config-azure.yaml` for release builds and
`veritee-os/config-azure.debug.yaml` with `--debug`. Both use the pinned Azure
kernel and package set. The debug profile enables SSH, a root account with
password `root`, and the serial console; use it only for troubleshooting.

Build an Azure SEV-SNP base OS image only (no DApp) with Microsoft Azure
Attestation (MAA), the default attestation mode:

```bash
veritee build-base-os-image --azuresnp --attestation-mode maa
```

Omitting `--attestation-mode` is equivalent to selecting `maa`. To build an
image whose in-guest attestation server returns raw SEV-SNP evidence instead:

```bash
veritee build-base-os-image --azuresnp --attestation-mode raw-sev-snp
```

By default, the in-guest attestation server rejects requests that omit `nonce`.
For debug inspection flows that need the old replayable behavior, build an
explicit debug image and opt in:

```bash
veritee build-base-os-image --azuresnp --debug --allow-unbound-attestation
veritee build-base-os-image --azuresnp --debug --attestation-mode raw-sev-snp --allow-unbound-attestation
```

Release images cannot enable unbound attestation. Their attestation-server
binary omits the development-only capability, so setting
`VERITEE_ALLOW_UNBOUND_ATTESTATION` at runtime has no effect.

The modes select which attestation flow is compiled into the base OS image:

- `maa` sends guest evidence to Microsoft Azure Attestation and returns
  MAA-backed evidence.
- `raw-sev-snp` returns the AMD SEV-SNP report, runtime data, and Azure-provided
  VCEK certificate chain so a verifier can validate the evidence directly,
  without MAA. This mode is still Azure-specific: it obtains the HCL report
  from the Azure vTPM and the VCEK chain from Azure Instance Metadata Service.

`--attestation-mode` applies to `--azuresnp` builds. Because the mode is part of
the resulting disk but is not encoded in the default output directory or ACR
image name, publish different modes under distinct tags. Build and push each
variant before building the next one, because both builds write to `local-base-os`:

```bash
veritee build-base-os-image --azuresnp --attestation-mode maa
veritee push-base-os-image --version 0.1.0-maa

veritee build-base-os-image --azuresnp --attestation-mode raw-sev-snp
veritee push-base-os-image --version 0.1.0-raw-sev-snp
```

Add `--debug` for an image with SSH and serial-console access. Debug images are
not guaranteed to be deterministic and must not be used for production deployments.
Release images refuse to start the DApp when PCR15 cannot be read, extended, or
verified. Debug images retain warning-and-continue behavior for PCR15 setup
failures only; other setup failures still prevent the DApp from starting.

## Packaging a Deployable VM Image

Packaging is **not** a plain `docker build`. Veritee pulls a **base Veritee OS image** and an **application container image** from Azure Container Registry, embeds the app into dm-verity partitions on an Azure SNP-ready VM image, and generates TEE metadata (application root hash and PCR4) used for attestation.

Configure your DApp in `projects/dapp/metadata.json`:

```json
{
    "name": "Example DApp",
    "description": "Demo DApp packaged for Veritee Azure SNP deployment",
    "app_container_image": "myregistry.azurecr.io/dapp/example:latest",
    "base_os_image": "myregistry.azurecr.io/temenos/base-os:0.1.0",
    "outbound": [
        { "host": "downloads.example.com", "ports": [443] }
    ]
}
```

`deployable_vm_image` is optional. If omitted, the CLI derives an ACR image
reference from the DApp name and `VERITEE_ACR_NAME`.

`outbound` is optional; an absent or empty list gives the DApp no external
network access. Each entry accepts a bare hostname or literal IP plus one or
more TCP ports. Hostnames remain in the measured `metadata.json` and HTTPS
traffic reaches them through the guest's restricted egress proxy. The proxy
resolves the hostname at request time and requires the TLS SNI name to match the
declared hostname. Literal IP entries also use the proxy, which provides a raw
TCP tunnel only to the exact measured IP and port. DApp clients therefore need
HTTP CONNECT proxy support for all external traffic.

`platform_outbound` and `outbound_policy_version` are generated during
packaging and must not be authored. When a digest-only base OS reference does
not expose its attestation mode, add `"attestation_mode": "raw-sev-snp"` (or
`"maa"`) to the source metadata so packaging grants only the platform path the
guest actually uses. The broad `"egress_profile": "warden"` profile is reserved
for the Warden image and requires the explicit
`--allow-warden-egress-profile` packaging flag.

The measured application disk is part of the trusted DApp computing base.
`setup.d/main` and `run.d/main` currently execute as host root during startup;
they are covered by the application root hash, but they are trusted lifecycle
hooks rather than subjects of the runtime egress sandbox. The outbound policy
constrains the containers launched by those hooks. It does not protect against
an intentionally malicious measured hook that changes host firewall or service
state. Clients must therefore verify the application measurement against the
expected registered policy, not treat the outbound declaration as an
independent substitute for application verification. Moving lifecycle
orchestration into platform-owned code is tracked in
[issue #42](https://github.com/input-output-hk/veritee-vm/issues/42).

For applications whose public destinations cannot be enumerated, use
`"egress_profile": "unrestricted"` instead of `outbound`. This measured profile
allows the DApp proxy to connect to any public TCP destination. It still blocks
private, loopback, link-local, and Azure metadata addresses, and validated
runtime containers cannot bypass the proxy. The profile does not provide UDP
or transparent proxying; clients must use HTTP CONNECT.

Package, generate TEE metadata, convert to VHD, and push to ACR:

Use `veritee os-release list` to browse confirmed OS releases and set the chosen
exact image reference in your project's `metadata.json.base_os_image`.
Packaging automatically resolves its approval using the configured OS
registry/network and matching contract CLI. No OS signing key or manifest hash
is required from a DApp developer. During registration, Warden independently
resolves the approved OS from that metadata and checks fresh attestation.
See the [phase-one OS approval runbook](os-release-approval.md) for setup
and the separate OS-maintainer signing workflow. This flow needs a
version-matched registry; it does not silently migrate an existing deployment.

```bash
export VERITEE_ACR_NAME=myregistry
veritee package-dapp-deployable-vm-image
```

Useful flags:

- `--no-push` — package locally without publishing to ACR
- `--verbose` — show full Earthly logs (hidden by default; the CLI focuses on TEE-specific steps)

To pull only the base Veritee OS image from ACR:

```bash
veritee pull-base-os-image
```

The base OS artifact contains `disk.raw` and `pcrs.json`; `policy.json` is
generated for the deployable VM image from a policy template, then can be
hydrated from live VM attestation. PCR0-3 are not treated as local golden
measurements; they are filled from the deployed VM's TPM quote during hydration.

## Deploying an Azure Confidential VM

Deploy an Azure SEV-SNP VM using the deployable VM image in `local-azure-snp/`:

```bash
export ARM_SUBSCRIPTION_ID=<subscription-id>
veritee init-inventory --location <azure-region>
veritee create-vm --azuresnp
```

`init-inventory` is a one-time, idempotent bootstrap. It creates or reuses a
private Storage account in `temenos-inventory-rg`, grants the current Azure
identity Blob Data access, and creates the `temenos-inventory` container. Later
deploy and destroy commands discover the account by its Azure tag. Set
`VERITEE_INVENTORY_STORAGE_ACCOUNT` only to override that discovery.

`create-vm` prompts for the Azure resource group, location, VM name, and Compute
Gallery name. For a non-interactive deployment, provide all four values:

```bash
veritee create-vm --azuresnp \
  --resource-group temenos-example-20260918-rg \
  --location eastus \
  --vm-name temenos-example-vm \
  --gallery-name temenos_example_gallery
```

By default, each invocation creates a new immutable deployment id and requires a new
resource group. The resource group is tagged with the DApp identity,
measurements, image references and digests, and Veritee commit. The CLI also
writes a creation record to the inventory container and keeps Terraform scratch state under
`.temenos/deploy-azure-snp/<deployment-id>/`; it never updates an existing VM.

If provisioning was interrupted before a VM was created, repeat the deployment
command with `--resume-deployment-id <deployment-id>`. This reuses the original
local Terraform state and preserves the allocated network resources and public
IP. The CLI checks the subscription, resource group, deployment and application
identity, and refuses to resume if a VM exists in Azure or Terraform state.
Repackaged VHD bytes trigger a fresh upload and image version before VM creation.

The inventory storage account is external durable infrastructure in the same
subscription and is never deleted with a VM deployment. For production use,
configure the container with the required Azure immutability/WORM policy. See
[the VM inventory runbook](vm-inventory.md).

List and destroy managed deployments using their Azure tags:

```bash
veritee list-deployments
veritee list-deployments --all
veritee deployment-history <deployment-id>
veritee destroy-vm --deployment-id <deployment-id>
```

The default list contains live deployments. `--all` also reads the durable
inventory records, so destroyed deployments remain discoverable after their
resource groups are gone. `deployment-history` displays the creation and
destruction records for one deployment; pass `--json` for their complete
contents.

`destroy-vm` displays a deployment summary and asks for confirmation. Use
`--yes` in CI. By default it deletes the complete per-deployment resource group,
including the uploaded VHD. `--keep-image` first copies that VHD into the durable
inventory container and records the retained blob path. A `destroy_requested`
record is written before deletion and a `destroyed` record only after Azure
confirms that the resource group is gone.

After the VM is running, `create-vm --azuresnp` tries to hydrate the policy
fields that are only known from live attestation evidence. If the attestation
server is not ready yet, the deployment still succeeds and you can rerun the
hydration step manually using the public Caddy endpoint:

```bash
veritee hydrate-policy-from-attestation \
  --attestation-url https://<attestation-domain>/tee_attestation \
  --resolve <vm-public-ip> \
  --template-policy policy.template.json \
  --output local-azure-snp/policy.json \
  --pcrs-output local-azure-snp/pcrs.json
```

The CLI reads the deployment TLS mode from `local-azure-snp/tls_mode`. In
`internal` mode it first obtains the Caddy root CA from the static attestation
document, checks the document's declared CA hash, and then fetches the live
attestation over TLS verified with that CA. The CA becomes trusted only after
the warden verifies that the attestation and PCR15 match the registered policy.
`--resolve` connects directly to the new VM while preserving the hostname for
TLS and Caddy routing, so DNS propagation is not required.

The hydrator supports both MAA and raw SEV-SNP attestation responses. It updates
platform-derived fields such as `attestation-type`, `imageId`,
`launch_measurement`, TCB SVN values, and raw SEV-SNP family/TCB policy fields,
while preserving security intent already present in the template, such as
debug-related policy. By default it parses quote-derived PCR0-3 from the TPM PCR
blob; pass `--use-tpm2-checkquote` to verify the quote with HCLAkPub during
hydration. The warden performs the required quote verification during
registration and verification. PCR4 remains disk-derived.

Online hydration sends a generated nonce to the attestation endpoint by default
so attestation evidence is bound to the request. For legacy/dev endpoints that
intentionally serve replayable unbound evidence, pass `--unbound-attestation`.
The in-guest attestation server only allows unbound evidence when the image was
built with `--debug --allow-unbound-attestation`. This compiles the
development-only capability and sets `VERITEE_ALLOW_UNBOUND_ATTESTATION=1`.

To deploy without the automatic post-deploy policy hydration attempt:

```bash
veritee create-vm --azuresnp --no-hydrate-policy
```

## Registering And Verifying A DApp

Configure the Warden trust endpoint, then register the packaged DApp:

```bash
export VERITEE_WARDEN_URL=https://warden.example.com
veritee register-app --metadata-path local-azure-snp/metadata.json
```

The Warden URL has no built-in default. Individual commands also accept an
explicit `--endpoint` (or `--warden-endpoint`) when an environment-level base
URL is not appropriate.

The command prints the Warden endpoint it contacts, then either prints the
queued job reference or polls it until completion. To inspect a queued job later:

```bash
veritee job-status <job-id-or-status-url>
```

Fetch a live attestation from a deployed VM with a caller-provided nonce:

```bash
veritee pull-attestation https://<attestation-domain>/tee_attestation \
  --resolve <vm-public-ip> \
  --nonce <client-nonce> \
  --payload <payload> \
  --output attestation.json
```

`pull-attestation` also reads `local-azure-snp/tls_mode`. Pass `--tls-mode`
only when that packaged artifact is not available.

Verify that attestation against the DApp policy registered with the Warden:

```bash
veritee verify-attestation \
  --dapp-id <registration-entry-id> \
  --expected-application-id <trusted-application-id> \
  --tee-attestation @attestation.json \
  --payload <payload> \
  --nonce <client-nonce>
```

`--expected-application-id` is optional during migration. With a supporting
Warden, it checks that the exact registration belongs to the caller's trusted
application ID. The same option is available on `attested-prove` and as
`expected_application_id=` in `make_warden_verifier`.

## DApp TLS modes

Veritee supports two DApp TLS modes for packaged DApp disks. The mode is chosen
when building the DApp disk and is later sent during registration so the warden
knows how to fetch and verify the attestation evidence.

| Mode | Behavior | When to use |
| --- | --- | --- |
| `internal` | Caddy uses `tls internal`; the VM-generated local root CA is written into the static `attestation.json` document and committed into PCR15. | Preferred mode when the client can trust the attested root CA. The TLS key material is generated inside the VM, so a verifier can prove the connection terminates at the measured enclave. |
| `azure_vault` | The VM fetches `fullchain.pem` and `privkey.pem` from Azure Key Vault at boot with its managed identity. The PEM files are not written to the DApp disk. The static `attestation.json` document records SPKI evidence for the serving certificates and commits it into PCR15. | Browser-compatible HTTPS where the certificate must already chain to a public trust root. |

Public certificates must be issued outside the DApp disk flow and supplied through 
`azure_vault`. This avoids putting certificate private keys in the measured app disk 
and avoids changing the disk hash just because TLS material changed.

### `internal`

`internal` is the preferred security mode when the client can consume and trust
the root CA from the attested static document. Since Caddy generates the CA/key
inside the VM and the generator commits that evidence into PCR15, a verifier can
bind the TLS endpoint to the measured enclave rather than to an external
certificate authority or Key Vault secret. Use it when browser trust is not
required:

```bash
veritee package-dapp-deployable-vm-image \
  --app-dir projects/dapp \
  --tls-mode internal
```

In this mode the static attestation document contains:

- `webserver_rootca`, the Caddy internal root CA PEM;
- `webserver_tls.mode = internal_ca`;
- `webserver_tls.root_ca_sha256`;
- the TPM quote after PCR15 has been extended with the app root hash and the
  internal TLS evidence.

### `azure_vault`

Use `azure_vault` when the DApp must be reachable by stock browsers or browser
extensions over normal HTTPS. The certificate must already be issued, and its
SANs must cover the Caddy hosts in `run.d/Caddyfile.template`.

Upload the certificate material before packaging/deploying:

```bash
veritee upload-tls-certs \
  --app-dir projects/dapp \
  --fullchain /path/to/fullchain.pem \
  --privkey /path/to/privkey.pem
```

If omitted, the command interactively asks for the Key Vault name, resource
group, location, and certificate paths. It stores the files as:

- `temenos-tls-fullchain-pem`;
- `temenos-tls-privkey-pem`.

Then package and deploy with the same TLS mode:

```bash
veritee package-dapp-deployable-vm-image \
  --app-dir projects/dapp \
  --tls-mode azure_vault

veritee create-vm --azuresnp
```

If the deployable metadata says the DApp uses `azure_vault`, `create-vm` asks
for the Key Vault name when it is not passed with `--tls-keyvault-name`. The VM
receives only the Key Vault name as deployment metadata. At boot, the run script
uses Azure Instance Metadata Service to get a managed identity token and fetches
the two secrets from Key Vault into `/run/temenos/tls`. The certificate files are
runtime-only and are not part of the measured DApp disk.

In this mode the static attestation document contains:

- `webserver_tls.mode = spki`;
- the attestation and API hostnames discovered from the rendered Caddyfile;
- `spki_sha256` for each configured serving certificate;
- the TPM quote after PCR15 has been extended with the app root hash and the
  SPKI evidence.

The document does not store the private key. It also does not replace normal
WebPKI checks: clients that rely on public HTTPS still need the certificate
chain and SAN to validate for the requested hostname.

### Registration

`register-app` uses the packaged `tls_mode` file when present, otherwise it asks
for the TLS mode interactively. In `internal` mode it still asks for the DApp
IP/address used to reach the VM-local attestation endpoint. In `azure_vault`
mode it can use the public hostnames from the Caddyfile and does not need a
separate unsafe TLS bypass.

Registration sends selected app-disk files to the warden as raw text:

- the packaged `metadata.json`, including its measured outbound policy, from
  `local-azure-snp/`;
- `run.d/Caddyfile.template`;
- `run.d/docker-compose.yml`.

Do not put private material in those files. The certificate private key is never
sent to the warden and is not needed for reproduction.

Legacy `compatibility_mode=legacy` deployments are not supported by current
Veritee VM or Warden releases. Use the matching older releases to rebuild or
verify those deployments. Current deployments must expose live attestation at
`https://<attestation-domain>/tee_attestation`.

### Rotation

Certificate rotation is not automatic. If a certificate is renewed with the same
private key, the SPKI hash stays the same. If the private key changes, the SPKI
evidence changes and the static attestation document must be regenerated; treat
that as a redeploy/re-registration event instead of silently changing the key
under an existing registered measurement.

### Public Ports

The Azure deployment intentionally opens:

- port `80`, so Caddy can accept HTTP and redirect to HTTPS;
- port `443`, for the public DApp API and `/tee_attestation` path.

The attestation server still listens on port `8000` inside the VM because Caddy
runs in Docker and reaches it through the host gateway. Azure does not expose
that port, and the guest firewall accepts it only from Docker bridge interfaces.
