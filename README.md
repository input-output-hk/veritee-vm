# Veritee VM

Veritee VM builds deterministic, attestable virtual machine images for running
applications inside a Trusted Execution Environment, and deploys them as Azure
Confidential VMs (AMD SEV-SNP). It is the VM layer of the Veritee protocol: the
base OS image, the in-guest attestation server and egress proxy, and the
`veritee` CLI that packages, deploys and registers DApps.

Copyright 2026 Input Output Global, Inc. Original Veritee contributions are
licensed under [Apache 2.0](LICENSE); third-party notices are in [NOTICE](NOTICE).

> **Disclaimer:** This software is experimental and has not been audited. It is
> provided "AS IS", without warranties or conditions of any kind, express or
> implied, and is not intended for production use. See sections 7 and 8 of the
> [license](LICENSE).

## The Veritee project

Veritee is split across several repositories:

| Repository | What it is |
|---|---|
| [veritee-vm](https://github.com/input-output-hk/veritee-vm) | This repository. Deterministic base OS image, in-guest attestation server, measured egress proxy, and the `veritee` CLI for packaging, deploying and registering DApps on Azure Confidential VMs. |
| [veritee-warden](https://github.com/input-output-hk/veritee-warden) | The Warden service. Reproduces registered DApp images, verifies their TEE attestations, and signs verified results in a form that Midnight smart contracts can check. |
| [veritee-smart-contracts](https://github.com/input-output-hk/veritee-smart-contracts) | Compact smart contracts on the Midnight blockchain that record DApp registrations and their attestation measurements. |
| [veritee-explorer](https://github.com/input-output-hk/veritee-explorer) | Web explorer and JSON API over the on-chain attestation records. |
| [veritee-attestation-verifier-ts](https://github.com/input-output-hk/veritee-attestation-verifier-ts) | TypeScript library for verifying Veritee TEE attestations in a client, as used by the Lace wallet. |
| [veritee-spec](https://github.com/input-output-hk/veritee-spec) | Protocol specification, trust boundaries and threat model. |

## How it works

1. **Base OS image.** `veritee-os/` is an mkosi project, driven by Earthly, that
   produces an immutable Ubuntu-based guest with a dm-verity protected root
   filesystem. The image includes the attestation server, the measured egress
   proxy and the measured-setup service. Builds are reproducible, so a third
   party can rebuild the image and derive the same PCR4 measurement.
2. **Packaging.** `veritee package-dapp-deployable-vm-image` takes a base OS
   image and an application container image from Azure Container Registry,
   embeds the application into a dm-verity partition, and records the
   application root hash and PCR4 as TEE metadata. Outbound network access is
   declared in the DApp metadata and enforced in the guest.
3. **Deployment.** `veritee create-vm` deploys the packaged image as an
   immutable Azure Confidential VM through Terraform and records it in a
   durable deployment inventory.
4. **Registration.** `veritee register-app` sends the measured DApp inputs to a
   Warden, which reproduces the application disk, verifies live attestation
   from the VM, and records the registration on the Midnight ledger.
5. **Verification.** Clients fetch a nonce-bound attestation from the running
   VM over HTTPS and verify it locally or through the Warden against the
   registered measurements.

## Repository layout

| Path | Contents |
|---|---|
| `cli/` | The `veritee` Python CLI, Azure deployment templates and CLI tests. |
| `veritee-os/` | mkosi project for the base OS image, plus the measured-setup service that runs in the guest. |
| `server/azure_attestation_server/` | Attestation server running inside the VM. |
| `server/egress_proxy/` | Measured-policy outbound CONNECT proxy for the guest. |
| `server/akx/` | Attested key-exchange crypto core for the attested channel. |
| `server/guest_attestation/` | Guest helper image that collects boot and TLS evidence for the DApp. |
| `services/` | systemd units installed into the base OS image. |
| `projects/` | DApp projects. `projects/dapp` is the default; `projects/templates/` holds the shared setup and startup hooks. |
| `docs/` | Design notes and runbooks. |
| `Earthfile` | Build targets for the base OS image, the deployable VM image and the guest binaries. |

Select a project with `--app-dir projects/<name>`. See
[project configuration](docs/project-configuration.md) for the app port,
hostnames and internal proxy connection.

## Installing the CLI

Install the required system dependencies:

```bash
sudo apt update
sudo apt install qemu-utils python3-venv
```

Then install the CLI into a virtual environment:

```bash
python3 -m venv cli/env
source cli/env/bin/activate
python -m pip install --editable ./cli
```

The CLI package is in `cli/`; the command and the Python package are both
named `veritee`. Rerun the `pip install` command from the repository root to
refresh the installation.

`qemu-img` is required to produce Azure-compatible fixed VHD files. The CLI
patches the VHD footer timestamp, checksum and disk UUID deterministically.

You also need these tools on your `PATH`:

- [Earthly](https://earthly.dev/) and Docker, for image builds and packaging
- the Azure CLI (`az`), for ACR and deployment workflows
- [Terraform](https://developer.hashicorp.com/terraform/install), for `create-vm`

## Quick start

Build or pull a base OS image, package a DApp, deploy it and register it:

First configure `projects/dapp/metadata.json` with actual digest-pinned image
references; its placeholders are not ready to package.

```bash
# 1. Base OS image (or `veritee pull-base-os-image` for an approved release)
veritee build-base-os-image --azuresnp

# 2. Package the DApp in projects/dapp into a deployable VM image
export VERITEE_ACR_NAME=myregistry
veritee package-dapp-deployable-vm-image

# 3. Deploy an Azure Confidential VM
export ARM_SUBSCRIPTION_ID=<subscription-id>
veritee init-inventory --location <azure-region>   # once per subscription
veritee create-vm --azuresnp

# 4. Register the DApp with a Warden
export VERITEE_WARDEN_URL=https://warden.example.com
veritee register-app --metadata-path local-azure-snp/metadata.json
```

Each step has options for attestation modes, TLS modes, outbound network
policy, OS release approval and deployment lifecycle. They are described in the
[operator guide](docs/operator-guide.md).

Packaging checks bundled registration limits and rebuild inputs locally before
pulling images. Replace the example metadata's placeholder image references with
digest pins, then run `veritee validate-dapp --app-dir projects/dapp` to check
them independently, without contacting Warden. Packages record input hashes
outside the measured disk and exclude generated `run.d/certs/`. Operator images
that will not be registered can use `--no-registration-preflight`.

## Terminology

| Term | Meaning |
|------|---------|
| **base Veritee OS image** | Bootable VM image containing the Veritee platform |
| **application container image** | Docker/OCI image for the DApp workload |
| **deployable VM image** | Packaged output: extended VM image with embedded app, plus TEE metadata |

## Documentation

- [Operator guide](docs/operator-guide.md): building, packaging, deploying,
  registering and verifying, including runtime networking, environment
  variables and DApp TLS modes.
- [Project configuration](docs/project-configuration.md): app port, hostnames
  and the internal proxy connection of a DApp project.
- [OS release approval](docs/os-release-approval.md): how approved base OS
  releases are published, signed and resolved.
- [VM inventory](docs/vm-inventory.md): the immutable deployment inventory
  behind `create-vm`, `list-deployments` and `destroy-vm`.
- [TLS channel binding](docs/tls-channel-binding.md) and the
  [attested channel implementation plan](docs/attested-channel-implementation-plan.md):
  design notes for binding a TLS session to the attested enclave.
- [Egress proxy](server/egress_proxy/README.md) and its
  [security notes](server/egress_proxy/SECURITY.md); the
  [guest attestation helper](server/guest_attestation/).
- Example projects: [Midnight proof server](docs/proof-server-preview.md) and
  [Midnight indexer](docs/indexer-standalone.md).

## Development

The CLI tests are offline unit tests. Run them from the repository root:

```bash
PYTHONPATH=cli python -m unittest discover -s cli/tests -v
```

Contributor conventions, including what must stay outside the measured
application disk, are in [AGENTS.md](AGENTS.md).

For a kernel-level egress integration test, bake
`scripts/test-proof-server-kernel-egress.sh` into a dedicated debug image and
run it inside the guest. Release images do not run the Azure VM Agent or expose
an administrative shell, so Azure Run Command cannot be used to inject it.
