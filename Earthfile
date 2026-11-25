VERSION 0.8

# Optional network-transport settings. They remain empty for ordinary builds;
# measured workloads such as the Warden can supply them through an Earthly
# argument file without changing any build recipe.
ARG --global HTTP_PROXY=""
ARG --global HTTPS_PROXY=""
ARG --global NO_PROXY=""
ARG --global http_proxy=""
ARG --global https_proxy=""
ARG --global no_proxy=""

debian-systemd:
    # debian:trixie-20251208-slim
    FROM debian@sha256:e711a7b30ec1261130d0a121050b4ed81d7fb28aeabcf4ea0c7876d4e9f5aca2

    # Imported Earthly commands do not inherit ARG values as environment
    # variables. Persist the optional transport settings so INSTALL_DIND and
    # the dockerd it starts use the measured builder proxy as well.
    ENV HTTP_PROXY=$HTTP_PROXY
    ENV HTTPS_PROXY=$HTTPS_PROXY
    ENV NO_PROXY=$NO_PROXY
    ENV http_proxy=$http_proxy
    ENV https_proxy=$https_proxy
    ENV no_proxy=$no_proxy

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
        qemu-system-x86=1:10.0.6+ds-0+deb13u2 \
        squashfs-tools=1:4.6.1-1 \
        swtpm=0.7.1-1.5 \
        systemd-container=257.9-1~deb13u1 \
        xfsprogs=6.13.0-2+b1 \
        zypper=1.14.89-1
    COPY update_systemd.sh .
    RUN bash update_systemd.sh
    SAVE IMAGE debian-systemd

build-attestation-server:
    # This is ubuntu:jammy-20251013
    FROM ubuntu@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb

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
    # `attestation_server` has a path dependency on the `akx` crate (../akx);
    # copy it so the relative path resolves inside the build context.
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
        
    SAVE ARTIFACT attestation_server/target/release/attestation_server /attestation_server_bin

build-egress-proxy:
    # Keep the gateway build independent from TPM/attestation dependencies.
    # This is ubuntu:jammy-20251013.
    FROM ubuntu@sha256:104ae83764a5119017b8e8d6218fa0832b09df65aae7d5a6de29a85d813da2fb

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

    SAVE ARTIFACT target/release/temenos-egress-proxy /egress_proxy_bin

veritee-os-azure-snp:
    FROM +debian-systemd

    # Ensure reproducible builds by fixing the source date epoch
    # Fixed to 2000-01-01T00:00:00Z.
    ENV SOURCE_DATE_EPOCH=946684800
    ENV TZ=UTC

    # Pin Rust
    ARG RUSTUP_VERSION="1.28.1"
    ARG RUST_TOOLCHAIN="1.89.0"

    RUN apt install --assume-yes --no-install-recommends \
        python3-pip=25.1.1+dfsg-1 python3-venv=3.13.5-1 pipx=1.7.1-1

    #mkosi v23.1
    RUN pipx install git+https://github.com/systemd/mkosi.git@0f11ffe01a96fd0f6731bd2c98246ee19f2add16
        RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie main contrib non-free non-free-firmware' \
    > /etc/apt/sources.list && \
    apt-get update
    RUN apt-get install --assume-yes --no-install-recommends dosfstools=4.2-1.2 cpio=2.15+dfsg-2 zstd=1.5.7+dfsg-1 kmod=34.2-2 ubuntu-keyring=2023.11.28.1-0.2 curl=8.14.1-2+deb13u2 wget=1.25.0-2 reprepro=5.4.6+really5.3.2-1
    WORKDIR /workdir

    COPY veritee-os/render_template ./render_template
    RUN pipx install render_template/

    COPY veritee-os/*.yaml .

    ARG OS_CONFIG="config-azure.yaml"
    ARG ATTESTATION_MODE="maa"
    ARG ALLOW_UNBOUND_ATTESTATION="false"
    
    WORKDIR /workdir/initrd
    CACHE mkosi.cache
    COPY veritee-os/mkosi/initrd .
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.conf.j2
    
    RUN --privileged /root/.local/bin/mkosi --debug

    SAVE ARTIFACT image AS LOCAL local-base-os/initrd_image.cpio.zst
    SAVE ARTIFACT image.manifest AS LOCAL local-base-os/initrd.manifest

    # RUN --privileged error

    WORKDIR /workdir/rootfs
    CACHE mkosi.cache

    COPY veritee-os/mkosi/rootfs .
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.conf.j2
    RUN find mkosi.extra -type f -name '*.j2' -print | while IFS= read -r template; do \
            /root/.local/bin/render_template "../$OS_CONFIG" "$template" && rm "$template" || exit 1; \
        done && \
        test -z "$(find mkosi.extra -type f -name '*.j2' -print -quit)"
    COPY veritee-os/measured_setup/main.py mkosi.extra/opt/measured_setup/main.py
    COPY veritee-os/measured_setup/egress.py mkosi.extra/opt/measured_setup/egress.py
    COPY cli/veritee/proxy_policy.py mkosi.extra/opt/measured_setup/proxy_policy.py
    
    # Copies appropriate services
    RUN /root/.local/bin/render_template "../$OS_CONFIG" copy_services.sh.j2
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.postinst.j2
    RUN chmod +x mkosi.postinst
    COPY --dir services services
    RUN case "$ALLOW_UNBOUND_ATTESTATION" in \
            true|false) ;; \
            *) echo "Unsupported ALLOW_UNBOUND_ATTESTATION: $ALLOW_UNBOUND_ATTESTATION (expected true or false)" >&2; exit 2 ;; \
        esac && \
        if [ "$ALLOW_UNBOUND_ATTESTATION" = "true" ] && \
           ! grep -Eq '^[[:space:]]*debug:[[:space:]]*true[[:space:]]*(#.*)?$' "../$OS_CONFIG"; then \
            echo "ALLOW_UNBOUND_ATTESTATION=true requires an OS profile with debug: true" >&2; \
            exit 2; \
        fi && \
        if [ "$ALLOW_UNBOUND_ATTESTATION" = "true" ]; then \
            mkdir -p mkosi.extra/etc/systemd/system/attestation_server.service.d && \
            printf '%s\n' \
                '[Service]' \
                'Environment=TEMENOS_ALLOW_UNBOUND_ATTESTATION=1' \
                > mkosi.extra/etc/systemd/system/attestation_server.service.d/allow-unbound-attestation.conf; \
        fi

    RUN mkdir -p mkosi.extra/usr/local/bin/ mkosi.extra/usr/lib/
    
    COPY (+build-attestation-server/attestation_server_bin --ATTESTATION_MODE=$ATTESTATION_MODE --ALLOW_UNBOUND_ATTESTATION=$ALLOW_UNBOUND_ATTESTATION) mkosi.extra/usr/local/bin/attestation_server
    COPY (+build-egress-proxy/egress_proxy_bin) mkosi.extra/usr/local/bin/temenos-egress-proxy

    RUN chmod +x mkosi.extra/usr/local/bin/attestation_server mkosi.extra/usr/local/bin/temenos-egress-proxy

    # RUN --privileged error

    RUN --privileged /root/.local/bin/mkosi --debug

    # RUN  --privileged error

    SAVE ARTIFACT image.raw AS LOCAL local-base-os/disk.raw
    SAVE ARTIFACT image.manifest AS LOCAL local-base-os/disk.manifest


veritee-os-azure-snp-combined:
    ARG --required APP_DIR
    FROM +debian-systemd

    DO github.com/earthly/lib:18cd0072824d86e77ed3ab3ad350f7ba34d33e84+INSTALL_DIND

    # Ensure reproducible builds by fixing the source date epoch
    # Fixed to 2000-01-01T00:00:00Z.
    ENV SOURCE_DATE_EPOCH=946684800
    ENV TZ=UTC

    # Pin Rust
    ARG RUSTUP_VERSION="1.28.1"
    ARG RUST_TOOLCHAIN="1.89.0"

    # To be replaced with a image hosted on IOG/Midnight?
    ARG GUEST_ATTESTATION_IMAGE="temenostest.azurecr.io/veritee/guest-attestation@sha256:9426ac1dce1c3501c70252ab37d9d591ebfaca252f853e31da747acf541d6b1a"
    # This should of course not have a default value. This is mainly here for demo purposes.
    ARG USER_DOCKER="snowder/temenos@sha256:ce071a393d8b289eef004412249250dd0ccf0d5969d2a28ca0037ad51b9a3d66"
    ARG PERSIST_SIZE="2G"
    ARG VERITEE_TLS_MODE="internal"
    ARG ATTESTATION_MODE="maa"
    ARG ALLOW_UNBOUND_ATTESTATION="false"

    RUN apt install --assume-yes --no-install-recommends \
        python3-pip=25.1.1+dfsg-1 python3-venv=3.13.5-1 pipx=1.7.1-1

    #mkosi v23.1
    RUN pipx install git+https://github.com/systemd/mkosi.git@0f11ffe01a96fd0f6731bd2c98246ee19f2add16
    RUN rm -f /etc/apt/sources.list /etc/apt/sources.list.d/* && \
    printf '%s\n' \
    'deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/20251208T000000Z/ trixie main contrib non-free non-free-firmware' \
    > /etc/apt/sources.list && \
    apt-get update
    RUN apt-get install --assume-yes --no-install-recommends dosfstools=4.2-1.2 cpio=2.15+dfsg-2 zstd=1.5.7+dfsg-1 kmod=34.2-2 ubuntu-keyring=2023.11.28.1-0.2 curl=8.14.1-2+deb13u2 wget=1.25.0-2 reprepro=5.4.6+really5.3.2-1
    WORKDIR /workdir

    COPY veritee-os/render_template ./render_template
    RUN pipx install render_template/

    COPY veritee-os/*.yaml .

    ARG OS_CONFIG="config-azure.yaml"

    WORKDIR /workdir/disk/container-images

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$GUEST_ATTESTATION_IMAGE" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$GUEST_ATTESTATION_IMAGE")" && \
            docker tag "$attestation_id" guest-attestation:latest && \
            docker save -o guest-attestation-image.tar guest-attestation:latest
    END

    WITH DOCKER
        RUN docker pull caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562 && \
            caddy_id="$(docker image inspect --format '{{.Id}}' caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562)" && \
            docker tag "$caddy_id" caddy:latest && \
            docker save -o caddy-image.tar caddy:latest
    END

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$USER_DOCKER" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$USER_DOCKER")" && \
            docker tag "$attestation_id" dapp:tee && \
            docker save -o app-image.tar dapp:tee
    END

    WORKDIR /workdir
    COPY $APP_DIR/ ./disk
    # Runtime certificates and source Git metadata are never app-disk inputs.
    RUN rm -rf ./disk/run.d/certs ./disk/.git
    # Use shared app scripts unless the DApp source provides overrides.
    # Permission normalization below also applies to source-provided overrides.
    COPY veritee-os/app-disk/run.d/main ./default-run-main
    COPY veritee-os/app-disk/setup.d/main ./default-setup-main
    RUN if [ ! -f ./disk/run.d/main ]; then \
            install -D -m 0755 ./default-run-main ./disk/run.d/main; \
        fi && \
        if [ ! -f ./disk/setup.d/main ]; then \
            install -D -m 0755 ./default-setup-main ./disk/setup.d/main; \
        fi
    RUN printf '%s\n' "$VERITEE_TLS_MODE" > ./disk/run.d/.temenos-tls-mode && \
        chmod 0644 ./disk/run.d/.temenos-tls-mode
    RUN chmod 0755 ./disk && \
        chmod 0644 ./disk/metadata.json && \
        find ./disk/run.d ./disk/setup.d -type d -exec chmod 0755 {} + && \
        find ./disk/run.d ./disk/setup.d -type f -exec chmod 0644 {} + && \
        chmod 0755 ./disk/run.d/main ./disk/setup.d/main
    RUN truncate -s "$PERSIST_SIZE" persist.img && \
        E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" \
        mke2fs -q -t ext4 \
            -L persist \
            -U cc428aef-829d-4387-94e8-fb81df661bd8 \
            -E lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=cc428aef-829d-4387-94e8-fb81df661bd8 \
            persist.img

    WORKDIR /workdir/initrd
    CACHE mkosi.cache
    COPY veritee-os/mkosi/initrd .
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.conf.j2

    RUN --privileged /root/.local/bin/mkosi --debug

    SAVE ARTIFACT image AS LOCAL local-azure-snp/combined_initrd_image.cpio.zst
    SAVE ARTIFACT image.manifest AS LOCAL local-azure-snp/combined_initrd.manifest

    WORKDIR /workdir/rootfs
    CACHE mkosi.cache

    COPY veritee-os/mkosi/rootfs .
    COPY veritee-os/mkosi/combined.repart/*.conf mkosi.repart/
    COPY veritee-os/mkosi/combined.extra/ mkosi.extra/
    RUN sed -i \
        -e "s/^SizeMinBytes=.*/SizeMinBytes=$PERSIST_SIZE/" \
        -e "s/^SizeMaxBytes=.*/SizeMaxBytes=$PERSIST_SIZE/" \
        mkosi.repart/30-persist.conf
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.conf.j2
    RUN find mkosi.extra -type f -name '*.j2' -print | while IFS= read -r template; do \
            /root/.local/bin/render_template "../$OS_CONFIG" "$template" && rm "$template" || exit 1; \
        done && \
        test -z "$(find mkosi.extra -type f -name '*.j2' -print -quit)"
    COPY veritee-os/measured_setup/main.py mkosi.extra/opt/measured_setup/main.py
    COPY veritee-os/measured_setup/egress.py mkosi.extra/opt/measured_setup/egress.py
    COPY cli/veritee/proxy_policy.py mkosi.extra/opt/measured_setup/proxy_policy.py

    # Copies appropriate services
    RUN /root/.local/bin/render_template "../$OS_CONFIG" copy_services.sh.j2
    RUN /root/.local/bin/render_template "../$OS_CONFIG" mkosi.postinst.j2
    RUN chmod +x mkosi.postinst
    COPY --dir services services
    RUN case "$ALLOW_UNBOUND_ATTESTATION" in \
            true|false) ;; \
            *) echo "Unsupported ALLOW_UNBOUND_ATTESTATION: $ALLOW_UNBOUND_ATTESTATION (expected true or false)" >&2; exit 2 ;; \
        esac && \
        if [ "$ALLOW_UNBOUND_ATTESTATION" = "true" ] && \
           ! grep -Eq '^[[:space:]]*debug:[[:space:]]*true[[:space:]]*(#.*)?$' "../$OS_CONFIG"; then \
            echo "ALLOW_UNBOUND_ATTESTATION=true requires an OS profile with debug: true" >&2; \
            exit 2; \
        fi && \
        if [ "$ALLOW_UNBOUND_ATTESTATION" = "true" ]; then \
            mkdir -p mkosi.extra/etc/systemd/system/attestation_server.service.d && \
            printf '%s\n' \
                '[Service]' \
                'Environment=TEMENOS_ALLOW_UNBOUND_ATTESTATION=1' \
                > mkosi.extra/etc/systemd/system/attestation_server.service.d/allow-unbound-attestation.conf; \
        fi

    RUN mkdir -p mkosi.extra/usr/local/bin/ mkosi.extra/usr/lib/

    COPY (+build-attestation-server/attestation_server_bin --ATTESTATION_MODE=$ATTESTATION_MODE --ALLOW_UNBOUND_ATTESTATION=$ALLOW_UNBOUND_ATTESTATION) mkosi.extra/usr/local/bin/attestation_server
    COPY (+build-egress-proxy/egress_proxy_bin) mkosi.extra/usr/local/bin/temenos-egress-proxy

    RUN chmod +x mkosi.extra/usr/local/bin/attestation_server mkosi.extra/usr/local/bin/temenos-egress-proxy

    RUN --privileged /root/.local/bin/mkosi --debug

    SAVE ARTIFACT image.raw AS LOCAL local-azure-snp/disk.raw
    SAVE ARTIFACT image.manifest AS LOCAL local-azure-snp/disk.manifest


veritee-os-azure-snp-extend-os:
    ARG --required APP_DIR
    FROM +debian-systemd

    DO github.com/earthly/lib:18cd0072824d86e77ed3ab3ad350f7ba34d33e84+INSTALL_DIND

    # Ensure reproducible builds by fixing the source date epoch
    # Fixed to 2000-01-01T00:00:00Z.
    ENV SOURCE_DATE_EPOCH=946684800
    ENV TZ=UTC

    # To be replaced with a image hosted on IOG/Midnight?
    ARG GUEST_ATTESTATION_IMAGE="temenostest.azurecr.io/veritee/guest-attestation@sha256:9426ac1dce1c3501c70252ab37d9d591ebfaca252f853e31da747acf541d6b1a"
    # This should of course not have a default value. This is mainly here for demo purposes.
    ARG USER_DOCKER="snowder/temenos@sha256:ce071a393d8b289eef004412249250dd0ccf0d5969d2a28ca0037ad51b9a3d66"
    ARG OS_RAW="local-base-os/disk.raw"
    ARG PERSIST_SIZE="2G"
    ARG ACR_REGISTRY=""
    ARG VERITEE_TLS_MODE="internal"

    RUN apt-get update
    RUN apt-get install --assume-yes --no-install-recommends \
        squashfs-tools=1:4.6.1-1 \
        e2fsprogs=1.47.2-3+b3 \
        systemd-container=257.9-1~deb13u1

    WORKDIR /workdir/disk/container-images

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$GUEST_ATTESTATION_IMAGE" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$GUEST_ATTESTATION_IMAGE")" && \
            docker tag "$attestation_id" guest-attestation:latest && \
            docker save -o guest-attestation-image.tar guest-attestation:latest
    END

    WITH DOCKER
        RUN docker pull caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562 && \
            caddy_id="$(docker image inspect --format '{{.Id}}' caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562)" && \
            docker tag "$caddy_id" caddy:latest && \
            docker save -o caddy-image.tar caddy:latest
    END

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            --secret ACR_TOKEN=acr_token \
            if [ -n "$ACR_REGISTRY" ]; then \
                echo "$ACR_TOKEN" | docker login "$ACR_REGISTRY" -u 00000000-0000-0000-0000-000000000000 --password-stdin; \
            elif [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$USER_DOCKER" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$USER_DOCKER")" && \
            docker tag "$attestation_id" dapp:tee && \
            docker save -o app-image.tar dapp:tee
    END

    WORKDIR /workdir
    COPY $APP_DIR/ ./disk
    # Runtime certificates and source Git metadata are never app-disk inputs.
    RUN rm -rf ./disk/run.d/certs ./disk/.git
    # Use shared app scripts unless the DApp source provides overrides.
    # Permission normalization below also applies to source-provided overrides.
    COPY veritee-os/app-disk/run.d/main ./default-run-main
    COPY veritee-os/app-disk/setup.d/main ./default-setup-main
    RUN if [ ! -f ./disk/run.d/main ]; then \
            install -D -m 0755 ./default-run-main ./disk/run.d/main; \
        fi && \
        if [ ! -f ./disk/setup.d/main ]; then \
            install -D -m 0755 ./default-setup-main ./disk/setup.d/main; \
        fi
    RUN printf '%s\n' "$VERITEE_TLS_MODE" > ./disk/run.d/.temenos-tls-mode && \
        chmod 0644 ./disk/run.d/.temenos-tls-mode
    RUN chmod 0755 ./disk && \
        chmod 0644 ./disk/metadata.json && \
        find ./disk/run.d ./disk/setup.d -type d -exec chmod 0755 {} + && \
        find ./disk/run.d ./disk/setup.d -type f -exec chmod 0644 {} + && \
        chmod 0755 ./disk/run.d/main ./disk/setup.d/main
    COPY $OS_RAW disk.raw
    COPY veritee-os/mkosi/extend-os.repart ./repart
    COPY veritee-os/mkosi/combined.repart ./repart
    RUN sed -i \
        -e "s/^SizeMinBytes=.*/SizeMinBytes=$PERSIST_SIZE/" \
        -e "s/^SizeMaxBytes=.*/SizeMaxBytes=$PERSIST_SIZE/" \
        repart/30-persist.conf
    RUN truncate -s "$PERSIST_SIZE" persist.img && \
        E2FSPROGS_FAKE_TIME="$SOURCE_DATE_EPOCH" \
        mke2fs -q -t ext4 \
            -L persist \
            -U cc428aef-829d-4387-94e8-fb81df661bd8 \
            -E lazy_itable_init=0,lazy_journal_init=0,root_owner=0:0,hash_seed=cc428aef-829d-4387-94e8-fb81df661bd8 \
            persist.img

    RUN systemd-repart \
        --empty=allow \
        --size=auto \
        --dry-run=no \
        --json=pretty \
        --no-pager \
        --offline=yes \
        --seed dbdda217-e7c1-4970-91b2-0f08656570f1 \
        --definitions=repart \
        disk.raw > extended_disk.manifest

    SAVE ARTIFACT disk.raw AS LOCAL local-azure-snp/disk.raw
    SAVE ARTIFACT extended_disk.manifest AS LOCAL local-azure-snp/disk.manifest


guest-attestation-image:
    FROM DOCKERFILE server/guest_attestation

dapp-appdisk:
    ARG --required APP_DIR
    FROM +debian-systemd

    DO github.com/earthly/lib:18cd0072824d86e77ed3ab3ad350f7ba34d33e84+INSTALL_DIND

    # To be replaced with a image hosted on IOG/Midnight?
    ARG GUEST_ATTESTATION_IMAGE="temenostest.azurecr.io/veritee/guest-attestation@sha256:9426ac1dce1c3501c70252ab37d9d591ebfaca252f853e31da747acf541d6b1a"
    # This should of course not have a default value. This is mainly here for demo purposes.
    ARG USER_DOCKER="snowder/temenos@sha256:ce071a393d8b289eef004412249250dd0ccf0d5969d2a28ca0037ad51b9a3d66"
    ARG VERITEE_TLS_MODE="internal"

    WORKDIR /workdir/disk/container-images

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$GUEST_ATTESTATION_IMAGE" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$GUEST_ATTESTATION_IMAGE")" && \
            docker tag "$attestation_id" guest-attestation:latest && \
            docker save -o guest-attestation-image.tar guest-attestation:latest
    END

    WITH DOCKER
        RUN docker pull caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562 && \
            caddy_id="$(docker image inspect --format '{{.Id}}' caddy@sha256:25cdc846626b62d05f6b633b9b40c2c9f6ef89b515dc76133cefd920f7dbe562)" && \
            docker tag "$caddy_id" caddy:latest && \
            docker save -o caddy-image.tar caddy:latest
    END

    WITH DOCKER
        RUN --secret DOCKERHUB_USER=dockerhub_user \
            --secret DOCKERHUB_TOKEN=dockerhub_token \
            if [ -n "$DOCKERHUB_USER" ] && [ -n "$DOCKERHUB_TOKEN" ]; then \
                echo "$DOCKERHUB_TOKEN" | docker login -u "$DOCKERHUB_USER" --password-stdin; \
            else \
                echo "WARNING: Docker Hub credentials are unset; pulling anonymously" >&2; \
            fi && \
            docker pull "$USER_DOCKER" && \
            attestation_id="$(docker image inspect --format '{{.Id}}' "$USER_DOCKER")" && \
            docker tag "$attestation_id" dapp:tee && \
            docker save -o app-image.tar dapp:tee
    END

    WORKDIR /workdir
    COPY veritee-os/app-disk/*.conf .
    COPY $APP_DIR/ ./disk
    # Runtime certificates and source Git metadata are never app-disk inputs.
    RUN rm -rf ./disk/run.d/certs ./disk/.git
    # Use shared app scripts unless the DApp source provides overrides.
    # Permission normalization below also applies to source-provided overrides.
    COPY veritee-os/app-disk/run.d/main ./default-run-main
    COPY veritee-os/app-disk/setup.d/main ./default-setup-main
    RUN if [ ! -f ./disk/run.d/main ]; then \
            install -D -m 0755 ./default-run-main ./disk/run.d/main; \
        fi && \
        if [ ! -f ./disk/setup.d/main ]; then \
            install -D -m 0755 ./default-setup-main ./disk/setup.d/main; \
        fi
    RUN printf '%s\n' "$VERITEE_TLS_MODE" > ./disk/run.d/.temenos-tls-mode && \
        chmod 0644 ./disk/run.d/.temenos-tls-mode
    RUN chmod 0755 ./disk && \
        chmod 0644 ./disk/metadata.json && \
        find ./disk/run.d ./disk/setup.d -type d -exec chmod 0755 {} + && \
        find ./disk/run.d ./disk/setup.d -type f -exec chmod 0644 {} + && \
        chmod 0755 ./disk/run.d/main ./disk/setup.d/main

    RUN touch disk.raw

    ENV SOURCE_DATE_EPOCH=946684800

    # The seed is fixed to produce reproducible disk image
    RUN  systemd-repart \
        --empty=allow \
        --size=auto \
        --dry-run=no \
        --json=pretty \
        --no-pager \
        --offline=yes \
        --seed dbdda217-e7c1-4970-91b2-0f08656570f1 \
        --definitions=. \
        disk.raw > application_disk_info.json

    SAVE ARTIFACT application_disk_info.json AS LOCAL local/application_disk_info.json
    SAVE ARTIFACT disk.raw AS LOCAL local/application_disk.raw
