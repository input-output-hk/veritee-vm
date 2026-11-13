# Midnight Proof Server — Preview

This is a separate Veritee application for the Preview proof-server endpoint:

- API: `https://api.proofserver.preview.wastedp.io`
- Attestation: `https://attestation.proofserver.preview.wastedp.io/tee_attestation`

The container and base OS are pinned by digest in `metadata.json`. The app
can reach only `srs.midnight.network:443`; Azure Vault TLS adds the platform
destinations needed to load certificates at runtime.

The proof server is stateless and has no network-selection flag. The calling
wallet or DApp selects Preview through its network ID, RPC and indexer.
The preview endpoint has a separate application key and application ID from
mainnet and preprod. Preserve its key privately for later registrations.

Package through the normal CLI, supplying the operator's vault name privately:

```sh
veritee package-dapp-deployable-vm-image \
  --app-dir examples/proof_server_preview \
  --persist-size 2G \
  --tls-mode azure_vault \
  --tls-keyvault-name "$PREVIEW_TLS_VAULT" \
  --no-push
```

After deployment and registration, exercise the TypeScript library's complete
verification pipeline using a built checkout of `temenos-attestation-verifier-ts`:

```sh
node scripts/test-proof-server-verifier-ts.mjs \
  --verifier-module /path/to/temenos-attestation-verifier-ts/dist/index.js \
  --application-id "$PREVIEW_APPLICATION_ID" \
  --pointer-address "$VERITEE_POINTER_ADDRESS" \
  --api-host api.proofserver.preview.wastedp.io \
  --attestation-host attestation.proofserver.preview.wastedp.io \
  --warden-url "$VERITEE_WARDEN_URL" \
  --indexer-url "$VERITEE_INDEXER_URL"
```

These indexer and pointer settings refer to the Veritee registration ledger.
The proof server's Preview label does not select a different Warden contract.
If that ledger uses Blockfrost Preprod, supply `BLOCKFROST_PROJECT_ID` through
a private environment variable. Keep tokens and vault names out of Git and
never put a project token in the indexer URL.

The test uses real evidence, on-chain expected values, the library's shipped
AMD roots, all local checks, Warden verification and an encrypted `/prove`
request. The supplied ledger8.1 fixture exercises proof generation and
response serialization; it is not an independent mathematical proof check.
Use `scripts/test-proof-server-proxy.py` with the matching HTTP client to also
exercise `/check`, `/prove` and session survival after an application error.
