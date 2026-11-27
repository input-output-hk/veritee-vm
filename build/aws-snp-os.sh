#!/usr/bin/env bash
set -euo pipefail
trap 'chown -R --no-dereference "$OUTPUT_UID:$OUTPUT_GID" /workdir' EXIT

[[ "$OS_CONFIG" == config-aws.yaml ]] || exit 2
cp -a /src/project/. .
cd rootfs
while IFS= read -r -d '' template; do
    /root/.local/bin/render_template "../$OS_CONFIG" "$template"
    chmod --reference="$template" "${template%.j2}"
    rm "$template"
done < <(find . -type f -name '*.j2' -print0)
mkdir -p /workdir/workspace
/root/.local/bin/mkosi --debug --workspace-directory=/workdir/workspace
cp --sparse=always image.raw /workdir/out/disk.raw
cp image.manifest /workdir/out/disk.manifest
chown "$OUTPUT_UID:$OUTPUT_GID" /workdir/out/disk.raw /workdir/out/disk.manifest
