#!/bin/bash
set -euo pipefail

# Keep the SOURCE_DATE_EPOCH-aware tools at the same upstream version, using
# packages from the Debian snapshot configured by the Earthfile.
apt-get install --assume-yes --no-install-recommends \
  systemd=257.9-1~deb13u1 \
  systemd-boot-tools=257.9-1~deb13u1 \
  systemd-container=257.9-1~deb13u1 \
  systemd-repart=257.9-1~deb13u1 \
  systemd-ukify=257.9-1~deb13u1

# Include libexec tools such as systemd-measure in the version checks.
export PATH="/usr/lib/systemd:$PATH"
BINARIES=(
  bootctl
  systemctl
  systemd-dissect
  systemd-firstboot
  systemd-measure
  systemd-nspawn
  systemd-repart
  ukify
)
for BINARY in "${BINARIES[@]}"; do
  "$BINARY" --version
done
