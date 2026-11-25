#!/usr/bin/env bash
set -euo pipefail
trap 'chown -R --no-dereference "$OUTPUT_UID:$OUTPUT_GID" /workdir' EXIT

# The CLI selects one of the two Azure profiles. Build in the container's
# disposable filesystem; only completed artifacts are copied to /workdir/out.
case "$OS_CONFIG" in config-azure.yaml|config-azure.debug.yaml) ;; *) exit 2 ;; esac
case "$ATTESTATION_MODE" in maa|raw-sev-snp) ;; *) exit 2 ;; esac
case "$ALLOW_UNBOUND_ATTESTATION" in true|false) ;; *) exit 2 ;; esac
if [[ "$ALLOW_UNBOUND_ATTESTATION" == true && "$OS_CONFIG" != config-azure.debug.yaml ]]; then
    echo 'Unbound attestation requires the debug profile' >&2
    exit 2
fi
cp -a /src/project/. .
for phase in initrd rootfs; do
    (
        cd "$phase"
        while IFS= read -r -d '' template; do
            /root/.local/bin/render_template "../$OS_CONFIG" "$template"
            chmod --reference="$template" "${template%.j2}"
            rm "$template"
        done < <(find . -type f -name '*.j2' -print0)
        /root/.local/bin/mkosi --debug
    )
done
cp --sparse=always rootfs/image.raw /workdir/out/disk.raw
cp rootfs/image.manifest /workdir/out/disk.manifest
cp initrd/image /workdir/out/initrd_image.cpio.zst
cp initrd/image.manifest /workdir/out/initrd.manifest
chown "$OUTPUT_UID:$OUTPUT_GID" /workdir/out/disk.raw /workdir/out/disk.manifest /workdir/out/initrd_image.cpio.zst /workdir/out/initrd.manifest
