# Midnight Indexer (Preprod)

Veritee project for the pinned upstream standalone indexer in
[issue #47](https://github.com/input-output-hk/veritee-vm/issues/47#issuecomment-5947945805).
The indexer image is not rebuilt or modified. The application disk measures its
configuration and the RPC transport adapter.

The runtime helpers are inline in Compose. The application source directory
matches the shared DApp template's file layout. Runtime `run.d/certs/` files and
their README are excluded from packaging, so registration can reproduce it using
metadata, Caddyfile and Compose. This document stays outside the measured disk.

The GraphQL endpoint is `https://indexer.preprod.wastedp.io/api/v3/graphql`.
Live attestation is served at
`https://attestation.indexer.preprod.wastedp.io/tee_attestation`.
Both hostnames must resolve to the deployment's public IP.

## TLS And Packaging

Use a publicly trusted certificate covering both hostnames. Certificate keys
are stored in Azure Key Vault and fetched at runtime, not included in the app
disk or repository.

```sh
export VERITEE_ACR_NAME=temenostest
veritee upload-tls-certs \
  --app-dir projects/indexer-standalone \
  --tls-keyvault-name <indexer-tls-vault> \
  --resource-group <tls-resource-group> \
  --location westus \
  --fullchain /path/to/fullchain.pem \
  --privkey /path/to/privkey.pem

veritee package-dapp-deployable-vm-image \
  --app-dir projects/indexer-standalone \
  --persist-size 32G \
  --tls-mode azure_vault \
  --tls-keyvault-name <indexer-tls-vault> \
  --no-push
```

Deploy on a 4-vCPU/16-GiB confidential VM, for example with
`--vm-size Standard_DC4ads_v5`. The shared Key Vault must survive deployment
teardown. Initial synchronization starts from genesis and is not instantaneous;
verify caught-up state before switching any verifier or Warden endpoint.

## Readiness

```sh
curl -i https://indexer.preprod.wastedp.io/ready
```

The pinned 3.0.0 image returns HTTP 200 when caught up with its node, or HTTP
503 with `indexer has not yet caught up with the node` during synchronization.
It has no `/health` route. A responding GraphQL API alone does not mean the
indexer is ready; also check that stored block heights keep advancing.

## RPC Transport

The upstream WebSocket client does not use `HTTPS_PROXY`. A private forwarder
therefore has the Docker DNS alias `rpc.preprod.midnight.network` on the internal
app network. It connects only to that real host's port 443 through the existing
Veritee HTTP CONNECT proxy. The indexer's node URL, TLS hostname verification
and upstream certificate validation remain unchanged. There is no direct
internet route or public forwarder port. The adapter reuses the pinned Python
runtime already packaged as `guest-attestation`; no extra image is pulled
at boot.

The application outbound declaration contains only the RPC hostname on 443.
Packaging adds the separate platform permission needed to fetch TLS secrets.
This 3.0.0 image has no SPO indexer configuration; do not add a Blockfrost key
or outbound destination.

## Persistent State

SQLite state and the runtime-generated 32-byte secret are stored under
`/mnt/persist/indexer-standalone`, owned by UID/GID 10001. The secret is created
only when absent and is never baked into the image or printed. Restarting the
container preserves both the secret and indexed chain state.

The TEE attests the code and configuration, not the unencrypted, unmeasured
persistent database. The indexer also trusts its configured upstream node; it
does not independently establish consensus. Do not describe its chain data as
protected against persistent-disk tampering or a dishonest upstream node.
