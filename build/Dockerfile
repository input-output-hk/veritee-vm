# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG ALLOW_UNBOUND_ATTESTATION=false

# debian:trixie-20251208-slim
FROM debian@sha256:e711a7b30ec1261130d0a121050b4ed81d7fb28aeabcf4ea0c7876d4e9f5aca2 AS tools

# The pinned slim base has no CA bundle. Bootstrap only the trust roots
# from the exact Debian package later installed from the HTTPS snapshot.
COPY veritee-os/bootstrap/ca-certificates_20250419_all.deb /tmp/ca-certificates.deb
RUN echo 'ef590f89563aa4b46c8260d49d1cea0fc1b181d19e8df3782694706adf05c184  /tmp/ca-certificates.deb' | sha256sum -c - && \
    mkdir -p /tmp/ca-bootstrap /usr/local/share/veritee && \
    dpkg-deb -x /tmp/ca-certificates.deb /tmp/ca-bootstrap && \
    find /tmp/ca-bootstrap/usr/share/ca-certificates/mozilla \
        -type f -name '*.crt' -print0 \
        | sort -z \
        | xargs -0 cat > /usr/local/share/veritee/bootstrap-ca.crt && \
    printf '%s\n' \
        'Acquire::https::CaInfo "/usr/local/share/veritee/bootstrap-ca.crt";' \
        > /etc/apt/apt.conf.d/00veritee-bootstrap-ca && \
    rm -rf /tmp/ca-bootstrap /tmp/ca-certificates.deb

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
printf '%s\n' \
'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie main contrib non-free non-free-firmware' \
'deb-src [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie main contrib non-free non-free-firmware' \
'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie-backports main contrib non-free non-free-firmware' \
> /etc/apt/sources.list && \
apt-get update
ENV DEBIAN_FRONTEND=noninteractive

RUN apt-get install --assume-yes --no-install-recommends \
    ca-certificates=20250419 && \
    rm -f /etc/apt/apt.conf.d/00veritee-bootstrap-ca \
        /usr/local/share/veritee/bootstrap-ca.crt && \
    test -s /etc/ssl/certs/ca-certificates.crt && \
    apt-get update
RUN apt-get install --assume-yes --no-install-recommends \
    cryptsetup=2:2.7.5-2 libcryptsetup-dev=2:2.7.5-2 \
    git=1:2.47.3-0+deb13u1 \
    meson=1.7.0-1 \
    gcc=4:14.2.0-1 \
    gperf=3.2.1-1 \
    libcap-dev=1:2.75-10+b1 \
    libmount-dev=2.41-5 \
    libssl-dev=3.5.4-1~deb13u1 \
    python3-jinja2=3.1.6-1 \
    pkg-config=1.8.1-4 \
    btrfs-progs=6.14-1 \
    bubblewrap=0.11.0-2 \
    debian-archive-keyring=2025.1 \
    dnf=4.23.0-1 \
    e2fsprogs=1.47.2-3+b3 \
    erofs-utils=1.8.6-1 \
    mtools=4.0.48-1 \
    ovmf=2025.02-8 \
    python3-pefile=2024.8.26-2.1 \
    python3-pyelftools=0.32-1 \
    squashfs-tools=1:4.6.1-1 \
    systemd-container=257.9-1~deb13u1 \
    xfsprogs=6.13.0-2+b1 \
    zypper=1.14.89-1
COPY update_systemd.sh .
RUN bash update_systemd.sh

# This is ubuntu:jammy-20251013
FROM ubuntu@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb AS attestation-server

# Freeze epoch for reproducibility
ENV SOURCE_DATE_EPOCH=946684800
ENV TZ=UTC

# Ca-certificates
# Needed to pull stuff from the snapshots, unfortunately
RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        ca-certificates=20211016 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

# Frozen snapshot
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-updates main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-security main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-backports main restricted universe' \
    > /etc/apt/sources.list && \
    apt-get update

RUN apt-get update && apt-get install --no-install-recommends -y \
    curl=7.81.0-1ubuntu1.21 build-essential=12.9ubuntu3 pkg-config=0.29.2-1ubuntu3 libssl-dev=3.0.2-0ubuntu1.20 \
    libtss2-dev=3.2.0-1ubuntu1.1 libxmlsec1=1.2.33-1build2 libxmlsec1-dev=1.2.33-1build2 libxml2-dev=2.9.13+dfsg-1ubuntu0.9 clang=1:14.0-55~exp2

ARG RUSTUP_VERSION="1.28.1"
ARG RUST_TOOLCHAIN="1.89.0"

RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"

ENV PATH="/root/.cargo/bin:${PATH}"
ARG ATTESTATION_MODE="maa"
ARG ALLOW_UNBOUND_ATTESTATION="false"

WORKDIR /build
COPY server/azure_attestation_server attestation_server
COPY server/akx akx

RUN cd attestation_server && \
    case "$ATTESTATION_MODE" in \
        maa) cargo_feature="maa" ;; \
        raw-sev-snp) cargo_feature="raw-report" ;; \
        *) echo "Unsupported ATTESTATION_MODE: $ATTESTATION_MODE (expected maa or raw-sev-snp)" >&2; exit 2 ;; \
    esac && \
    case "$ALLOW_UNBOUND_ATTESTATION" in \
        false) ;; \
        true) cargo_feature="$cargo_feature,dev-unbound-attestation" ;; \
        *) echo "Unsupported ALLOW_UNBOUND_ATTESTATION: $ALLOW_UNBOUND_ATTESTATION (expected true or false)" >&2; exit 2 ;; \
    esac && \
    cargo build --release --locked --no-default-features --features "$cargo_feature"

# Keep the gateway build independent from TPM/attestation dependencies.
# This is ubuntu:jammy-20251013.
FROM ubuntu@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb AS egress-proxy

ENV SOURCE_DATE_EPOCH=946684800
ENV TZ=UTC

RUN --mount=type=cache,target=/var/cache/apt \
    apt-get update && \
    DEBIAN_FRONTEND=noninteractive \
    apt-get install -y --no-install-recommends \
        ca-certificates=20211016 && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/*

RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-updates main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-security main restricted universe' \
    'deb [signed-by=/usr/share/keyrings/ubuntu-archive-keyring.gpg] https://snapshot.ubuntu.com/ubuntu/20251013T000000Z jammy-backports main restricted universe' \
    > /etc/apt/sources.list && \
    apt-get update

RUN apt-get install --no-install-recommends -y \
    curl=7.81.0-1ubuntu1.21 build-essential=12.9ubuntu3

ARG RUSTUP_VERSION="1.28.1"
ARG RUST_TOOLCHAIN="1.89.0"
ARG RUSTUP_SHA256="a3339fb004c3d0bb9862ba0bce001861fe5cbde9c10d16591eb3f39ee6cd3e7f"
RUN curl -fsSL -o /tmp/rustup-init "https://static.rust-lang.org/rustup/archive/${RUSTUP_VERSION}/x86_64-unknown-linux-gnu/rustup-init" && \
    echo "${RUSTUP_SHA256}  /tmp/rustup-init" | sha256sum -c - && \
    chmod +x /tmp/rustup-init && \
    /tmp/rustup-init -y --profile minimal --default-toolchain "${RUST_TOOLCHAIN}"

ENV PATH="/root/.cargo/bin:${PATH}"
WORKDIR /build/egress_proxy
COPY server/egress_proxy .
RUN cargo build --release --locked

FROM tools AS verified-docker-apt
RUN apt-get install --assume-yes --no-install-recommends gpgv=2.4.7-21+b3
WORKDIR /workdir
COPY veritee-os/docker-apt docker-apt
RUN python3 docker-apt/verify.py stage docker-apt/packages docker-packages

# Assemble the mkosi project here: component builds and destinations belong
# together, and new files do not need another copy command in the runner.
FROM scratch AS os-project-common
COPY veritee-os/config-azure*.yaml /
COPY veritee-os/mkosi/initrd /initrd
COPY veritee-os/mkosi/rootfs /rootfs
COPY --from=verified-docker-apt /workdir/docker-packages /docker-packages
COPY veritee-os/measured_setup/main.py veritee-os/measured_setup/egress.py /rootfs/mkosi.extra/opt/measured_setup/
COPY cli/veritee/proxy_policy.py /rootfs/mkosi.extra/opt/measured_setup/proxy_policy.py
COPY --chmod=0755 --from=attestation-server /build/attestation_server/target/release/attestation_server /rootfs/mkosi.extra/usr/local/bin/attestation_server
COPY --chmod=0755 --from=egress-proxy /build/egress_proxy/target/release/temenos-egress-proxy /rootfs/mkosi.extra/usr/local/bin/temenos-egress-proxy
COPY services/azure-provisioning.service services/attestation_server.service /rootfs/mkosi.extra/etc/systemd/system/
COPY services/start_ssh.service services/restart-serial-console.service /rootfs/mkosi.debug/etc/systemd/system/
COPY services/measured-setup-allow-pcr15-failure.conf /rootfs/mkosi.debug/etc/systemd/system/measured-setup.service.d/allow-pcr15-failure.conf

FROM os-project-common AS os-project-false

FROM os-project-common AS os-project-true
COPY build/allow-unbound-attestation.conf /rootfs/mkosi.debug/etc/systemd/system/attestation_server.service.d/allow-unbound-attestation.conf

FROM os-project-${ALLOW_UNBOUND_ATTESTATION} AS os-project

FROM tools AS azure-snp-os-builder
ENV SOURCE_DATE_EPOCH=946684800 TZ=UTC
WORKDIR /workdir
RUN apt-get install --assume-yes --no-install-recommends \
    python3-pip=25.1.1+dfsg-1 python3-venv=3.13.5-1 pipx=1.7.1-1
RUN pipx install git+https://github.com/systemd/mkosi.git@0f11ffe01a96fd0f6731bd2c98246ee19f2add16
RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' 'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie main contrib non-free non-free-firmware' > /etc/apt/sources.list && \
    apt-get update && apt-get install --assume-yes --no-install-recommends \
    dosfstools=4.2-1.2 cpio=2.15+dfsg-2 zstd=1.5.7+dfsg-1 kmod=34.2-2 \
    ubuntu-keyring=2023.11.28.1-0.2 curl=8.14.1-2+deb13u2 wget=1.25.0-2 \
    reprepro=5.4.6+really5.3.2-1 apt-utils=3.0.3
# APT 3.0.3 can exhaust memory while retrying slow downloads (Debian #1111554).
# These security-update bytes were checked against Debian's signed package index.
ADD --checksum=sha256:15c2030e0fb46580af4f1b4cc303f4bd26da781b004e99763bc9eff7cf8e19b8 https://snapshot.debian.org/archive/debian-security/20261105T000000Z/pool/updates/main/a/apt/apt_3.0.4_amd64.deb /tmp/apt-update/apt.deb
ADD --checksum=sha256:577eb8f489de419290102364892dbd13ca256297b61f96d61b114fd4ac18be41 https://snapshot.debian.org/archive/debian-security/20261105T000000Z/pool/updates/main/a/apt/libapt-pkg7.0_3.0.4_amd64.deb /tmp/apt-update/libapt.deb
ADD --checksum=sha256:a77b3af564bb5143e7babb6aa6b098c6426be56b3811623748afc700a0af0e8c https://snapshot.debian.org/archive/debian-security/20261105T000000Z/pool/updates/main/a/apt/apt-utils_3.0.4_amd64.deb /tmp/apt-update/apt-utils.deb
RUN dpkg --install /tmp/apt-update/libapt.deb /tmp/apt-update/apt.deb /tmp/apt-update/apt-utils.deb && \
    rm -rf /tmp/apt-update && apt-get --version
COPY veritee-os/render_template /src/render_template
RUN pipx install /src/render_template
COPY --from=os-project / /src/project
COPY build/azure-snp-os.sh /usr/local/bin/build-azure-snp-os
WORKDIR /workdir
ENTRYPOINT ["bash", "/usr/local/bin/build-azure-snp-os"]

FROM tools AS app-disk-builder
ENV SOURCE_DATE_EPOCH=946684800 TZ=UTC
# dockerd links libnftables even when its bridge/firewall integration is disabled.
RUN apt-get install --assume-yes --no-install-recommends libnftables1
COPY --from=verified-docker-apt /workdir/docker-packages /tmp/docker-packages
# Use the same verified Docker version in every isolated image exporter.
RUN for package in /tmp/docker-packages/*.deb; do dpkg-deb -x "$package" /; done && \
    rm -rf /tmp/docker-packages && dockerd --version
COPY veritee-os/app-disk /src/app-disk
COPY veritee-os/mkosi/extend-os.repart /src/extend-os.repart
COPY veritee-os/mkosi/combined.repart /src/combined.repart
COPY build/app-images.conf /src/app-images.conf
COPY build/app-disk.sh /usr/local/bin/build-app-disk
WORKDIR /workdir
ENTRYPOINT ["bash", "/usr/local/bin/build-app-disk"]

