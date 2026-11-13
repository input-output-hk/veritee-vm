# Temenos Warden DApp

This project packages the complete Warden image as a privileged, measured
Temenos workload at `https://warden.wastedp.io`. The same host serves live
attestation at `/tee_attestation` and the Warden API on every other route.

The measured `warden` egress profile is required. It grants the Warden app's
fixed container IP direct Azure DNS, HTTPS, and IMDS access because the Midnight
Node clients do not honor HTTP CONNECT proxy settings. It also permits the exact
Docker socket mount so Earthly can reproduce submitted DApps. The socket makes
the Warden container part of the guest host TCB; it is not a container-isolation
boundary.

The pinned Midnight proof server is started by Compose on the private
`constrained-app` network, with no published port. The Warden waits for its
health check and passes `TEMENOS_PROOF_SERVER_URL=http://proof-server:6300` to
the attestation CLI. SRS downloads use the existing measured egress proxy.

Earthly's managed BuildKit daemon runs on the platform-owned
`temenos-builder` bridge. That bridge can use Azure DNS and the measured HTTPS
proxy, but cannot reach IMDS directly. The measured Earthly configuration also
passes that proxy to BuildKit and build steps explicitly; Earthly does not
inherit those settings on its own. The pinned Debian CA bootstrap keeps the
snapshot on HTTPS without granting the builder direct public egress. Docker Hub
credentials are optional; without them, rebuilds use anonymous pulls and may
encounter Docker Hub rate limits.

Wallet files live only on `/mnt/persist/temenos-warden/wallet-state`. The Warden
backs up the three saved sub-wallets every twelve hours to the private
`warden-wallet-checkpoints` container in `temenoswardenrecords`; a locked
seven-day policy protects each unique object against overwrite and deletion.
Checkpoint uploads use the same in-process lock as chain writes. No wallet
state or seed is included in the Docker image or application disk.

The preprod indexer and RPC services use Blockfrost. The project token is
fetched from Azure Key Vault at container startup; it is never part of the
image or application disk. The vault name is discovered from the VM's TLS
configuration unless `WARDEN_BLOCKFROST_KEYVAULT_NAME` supplies a separate vault.
`WARDEN_BLOCKFROST_SECRET_NAME` selects the secret, defaulting to
`blockfrost-midnight-preprod-project-id`. Endpoint overrides contain public URLs
only, and authentication is added inside the CLI at runtime.

This provider migration omits the old bootstrap checkpoint: cursor/event
identifiers can differ between indexers. Preserve the existing seed, contract,
and old state for rollback, then deploy with a fresh persistent wallet-state
directory. Existing complete state is never reset automatically. Stop the old
Warden before enabling writes in its replacement. Fresh synchronization can
take over an hour. A future bootstrap pin must be explicitly validated against
the new provider; never select the latest uploaded object blindly.

The Azure Vault selected during packaging must contain these secrets:

- `temenos-tls-fullchain-pem`
- `temenos-tls-privkey-pem`
- `preprod-warden-wallet-seed-v2`
- `blockfrost-midnight-preprod-project-id`

The CVM managed identity also needs `AcrPull` on `temenostest`, plus Storage
Blob Data Contributor and Storage Table Data Contributor on
`temenoswardenrecords`. The deployer's Azure Vault role assignment already
provides access to the secrets above when the same vault is used. A separate
Blockfrost vault also needs a Key Vault Secrets User role assignment.

The production Warden CVM requires 64 GiB of memory. Image reproduction through
Earthly can overlap with the Midnight attestation CLI used for anchoring; a
16 GiB VM has produced V8 heap exhaustion and kernel OOM kills, while 32 GiB
leaves limited headroom for concurrent builds and chain writes. Deploy with
`--vm-size Standard_DC16ads_v5` (or a larger confidential-VM size available in
the target region). `Standard_DC8ads_v5` (32 GiB) is the minimum supported size
for development and isolated-path testing.

The Warden metadata requests a 32 GiB persistent partition. Startup binds
Earthly's `earthly-cache` Docker volume to
`/mnt/persist/temenos-warden/earthly-cache`; without that binding Docker stores
the cache under the guest's RAM-backed `/var/lib/docker`. The cache is
disposable build working state and is never a source of trusted measurements.
The Warden runs `earthly prune --all` after every rebuild attempt, including
failed builds, so the persistent partition does not accumulate stale layers.

Package with:

```sh
temenos package-dapp-deployable-vm-image \
  --app-dir application_disk/warden \
  --tls-mode azure_vault \
  --tls-keyvault-name <warden-key-vault> \
  --allow-warden-egress-profile \
  --no-push
```

Both images in `metadata.json` are pinned by registry digest. Update those
digests only when publishing a new Warden or base OS release.
