# Configuring a DApp project

Copy `examples/dapp` to an application folder, including outside this checkout.
Set the application name and digest-pinned application/approved base OS image
references in `metadata.json`; the reference app's placeholder images need
replacing before validation.
Configure the app's command, environment and volumes in the Compose `app` service.

`projects/proof_server_preprod` is a complete proof-server project with pinned
images and `/check` and `/prove` enabled for the attested proxy. Replace its
example hostnames before deploying it.

From the Veritee checkout:

```sh
cp -a examples/dapp ../my-app
# Edit ../my-app/metadata.json and its run.d files.
veritee validate-dapp --app-dir ../my-app --tls-mode internal
veritee package-dapp-deployable-vm-image --app-dir ../my-app --tls-mode internal
veritee register-app --app-dir ../my-app --metadata-path local-azure-snp/metadata.json
```

Absolute paths work too. Relative paths resolve from the caller's directory;
the default app resolves to the checkout's `examples/dapp`. Build commands run
against the checkout's Earthfile and write their usual checkout-local outputs.
Registration requires the explicit `--app-dir` used for packaging.

The CLI stages external files inside the checkout build context. Partition
definitions and fallback hooks come only from `veritee-os/app-disk/`, never the
application's parent. Apps need no sibling `.conf` files or copied hooks; source
hooks still override the fallback hooks. Root `.git` metadata (a directory or
worktree pointer) and generated `run.d/certs/` files are excluded consistently
from staging, validation and input snapshots. Other source files remain subject
to Warden's existing submitted-file/rebuild boundary.

Using the CLI without a Veritee checkout is not supported. Direct Earthly
invocations still require an app path inside their build context; use the CLI
for an external app folder.

In `run.d/Caddyfile.template`, replace the attestation and API hostnames.
Set the application's container port once, in the Compose `caddy` service.
For an app listening on port 6300:

```yaml
caddy:
  environment:
    APP_UPSTREAM: "app:6300"
```

The app must listen on its container network interface, for example
`0.0.0.0:6300`, so Caddy can reach it.

Both the public HTTPS API and the attested proxy read this value. There is
one upstream port to maintain; no additional CLI option or shell export is
needed. The template already provides the required routing.

The Compose mapping `127.0.0.1:8080:8080` belongs to Caddy. Port 8080 is the
fixed internal connection from the host attestation server, regardless of the
app's container port. Use the supplied listener and network definitions as-is:
the attestation server decrypts the request, sends it to loopback Caddy, and
Caddy forwards it to the app on its private Docker network.
This hop is needed because a port published directly from an internal Docker
network can be unreachable from the host.

Outbound connections use the separate measured egress policy declared in
`metadata.json`. The loopback listener serves incoming application requests.

Package and register with the same project files. Keep operator notes, test
harnesses and documentation under `docs/` or elsewhere outside the project;
files placed inside a project can change its measured application root.

When updating a Warden's bundled VM checkout to this layout, its
`run_deployer_app_disk` template argument in `src/routes/os.rs` must change from
`projects/dapp` to `examples/dapp`, alongside the bundled VM revision pin. Its
temporary override folder and `build-app-disk --app-dir <folder>` invocation
remain supported. The registration protocol still submits only metadata,
Caddyfile and Compose. This layout change does not update a running Warden.
