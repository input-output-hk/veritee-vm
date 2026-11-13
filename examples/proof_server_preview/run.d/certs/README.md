Optional Caddy TLS certificates.

Default behavior uses Caddy internal certificates. To provide certificates, add:

- certs/fullchain.pem and certs/privkey.pem for both Caddy sites
- certs/api/fullchain.pem and certs/api/privkey.pem for the API site only
- certs/attestation/fullchain.pem and certs/attestation/privkey.pem for the attestation site only

Per-site files take precedence over the shared files.
