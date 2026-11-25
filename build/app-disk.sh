#!/usr/bin/env bash
set -euo pipefail

# A private, disposable daemon avoids host image tags, concurrent-build races
# and dependence on the host daemon's image-export implementation.
export DOCKER_HOST=unix:///tmp/veritee-docker.sock
export DOCKER_CONFIG=/workdir/docker-auth
dockerd --host "$DOCKER_HOST" --data-root /workdir/.docker-data \
    --exec-root /tmp/docker-exec --pidfile /tmp/docker.pid \
    --storage-driver overlayfs --iptables=false --ip6tables=false --bridge=none \
    --ip-forward=false --ip-masq=false --feature containerd-snapshotter=true \
    > /tmp/dockerd.log 2>&1 &
daemon_pid=$!
cleanup() {
    kill "$daemon_pid" 2>/dev/null || true
    wait "$daemon_pid" 2>/dev/null || true
    chown -R --no-dereference "$OUTPUT_UID:$OUTPUT_GID" /workdir
}
trap cleanup EXIT
ready=false
for ((attempt=0; attempt<120; attempt++)); do
    if docker info >/dev/null 2>&1; then ready=true; break; fi
    if ! kill -0 "$daemon_pid" 2>/dev/null; then break; fi
    sleep 0.25
done
if [[ "$ready" != true ]]; then
    cat /tmp/dockerd.log >&2
    exit 1
fi

cp -a /workdir/inputs/project disk
chown -R 0:0 disk
mkdir -p disk/container-images
export_image() {
    local reference=$1 alias=$2 destination=$3
    docker pull --platform linux/amd64 "$reference"
    local image_id
    image_id=$(docker image inspect --format '{{.Id}}' "$reference")
    docker tag "$image_id" "$alias"
    docker save --output "$destination" "$alias"
}
declare -A archives
while read -r reference alias archive extra; do
    [[ -z "$reference" || "$reference" == \#* ]] && continue
    if [[ -z "$alias" || ! "$archive" =~ ^[a-zA-Z0-9][a-zA-Z0-9_.-]*\.tar$ || -n "$extra" || -v "archives[$archive]" ]]; then
        echo "Invalid or duplicate entry in app-images.conf" >&2
        exit 2
    fi
    archives[$archive]=1
    if [[ "$reference" == \$* ]]; then
        variable=${reference:1}
        [[ "$variable" =~ ^[A-Z][A-Z0-9_]*$ ]] || { echo "Invalid image variable" >&2; exit 2; }
        reference=${!variable:?Missing image reference}
    fi
    export_image "$reference" "$alias" "disk/container-images/$archive"
done < /src/app-images.conf

if [[ ! -f disk/run.d/main ]]; then
    install -D -m 0755 /src/app-disk/run.d/main disk/run.d/main
fi
if [[ ! -f disk/setup.d/main ]]; then
    install -D -m 0755 /src/app-disk/setup.d/main disk/setup.d/main
fi
printf '%s\n' "$VERITEE_TLS_MODE" > disk/run.d/.temenos-tls-mode
chmod 0755 disk
chmod 0644 disk/metadata.json
find disk/run.d disk/setup.d -type d -exec chmod 0755 {} +
find disk/run.d disk/setup.d -type f -exec chmod 0644 {} +
chmod 0755 disk/run.d/main disk/setup.d/main
# Filesystem timestamps must not depend on the checkout or preparation time.
find disk -exec touch --no-dereference --date="@$SOURCE_DATE_EPOCH" {} +

mkdir repart
if [[ "$BUILD_ACTION" == app ]]; then
    cp /src/app-disk/*.conf repart/
    touch disk.raw
elif [[ "$BUILD_ACTION" == extend ]]; then
    cp --sparse=always /workdir/inputs/os.raw disk.raw
    cp /src/extend-os.repart/* /src/combined.repart/* repart/
    sed -i -e "s/^SizeMinBytes=.*/SizeMinBytes=$PERSIST_SIZE/" \
        -e "s/^SizeMaxBytes=.*/SizeMaxBytes=$PERSIST_SIZE/" repart/30-persist.conf
    truncate -s "$PERSIST_SIZE" persist.img
    E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" mke2fs -q -t ext4 -L persist \
        -U cc428aef-829d-4387-94e8-fb81df661bd8 \
        -E lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=cc428aef-829d-4387-94e8-fb81df661bd8 persist.img
else
    exit 2
fi
systemd-repart --empty=allow --size=auto --dry-run=no --json=pretty \
    --no-pager --offline=yes --seed dbdda217-e7c1-4970-91b2-0f08656570f1 \
    --definitions=repart disk.raw > disk.manifest
if [[ "$BUILD_ACTION" == app ]]; then
    cp --sparse=always disk.raw /workdir/out/application_disk.raw
    cp disk.manifest /workdir/out/application_disk_info.json
    chown "$OUTPUT_UID:$OUTPUT_GID" /workdir/out/application_disk.raw /workdir/out/application_disk_info.json
else
    cp --sparse=always disk.raw /workdir/out/disk.raw
    cp disk.manifest /workdir/out/disk.manifest
    chown "$OUTPUT_UID:$OUTPUT_GID" /workdir/out/disk.raw /workdir/out/disk.manifest
fi
