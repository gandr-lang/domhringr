# The Linux CI image carries this workspace's pinned Rust toolchain, CI mise
# subset, runtime and Dylint driver. No engine SDK or LLVM pin exists here.
# Pin files are copied, never retyped; image-tag.sh hashes the build inputs.
#
# Every container job extracts the whole image before its first step, and
# extraction, not the download, is most of that time (gandr-lang/gandr#1999:
# 2.6 s to download, 32 s to extract). The image therefore carries only what
# most jobs run. The toolchain is the pin's channel with clippy and rustfmt;
# the components few jobs use (rustc-dev and llvm-tools for Dylint,
# llvm-tools for coverage, rust-src for `build-dist`) are added by the task
# that needs them. `RUSTUP_TOOLCHAIN` names the channel, so rustup reads no
# component list from rust-toolchain.toml, and mise leaves rust alone
# (below): nothing installs the rest on first use. Build caches (Cargo's
# registry, mise's downloads) leave in the layer that made them.
ARG UBUNTU_BASE=docker.io/library/ubuntu:26.04@sha256:da6fc2be547864451aa253836dd926da33623312df4a9a243e35dc877c378a78
FROM ${UBUNTU_BASE} AS tools
# The pin's channel, passed by ci-image.yml and checked against the pin below.
ARG RUST_CHANNEL

SHELL ["/bin/bash", "-o", "pipefail", "-c"]
ENV DEBIAN_FRONTEND=noninteractive

# rustup needs curl and certificates; Rust linking needs build-essential.
# git2's openssl-sys needs pkg-config and libssl-dev; Cargo Git sources need git.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl git build-essential pkg-config libssl-dev zstd \
    && rm -rf /var/lib/apt/lists/*

# Build tools as UID 1000. Job steps run as root to write runner-owned mounts.
RUN userdel --remove ubuntu && useradd --create-home --home-dir /opt/ci --uid 1000 ci
USER 1000

ENV RUSTUP_HOME=/opt/ci/.rustup \
    CARGO_HOME=/opt/ci/.cargo \
    RUSTUP_TOOLCHAIN=${RUST_CHANNEL} \
    PATH=/opt/ci/.local/bin:/opt/ci/.cargo/bin:$PATH

# This must match ci.yml: workstation-only tools never enter CI installs.
# mise's rust backend would install every component rust-toolchain.toml
# lists, at build time and again on a job's first mise command, since it
# counts the pin missing until all are present. With the version file off,
# mise leaves rust alone and rustup serves `RUSTUP_TOOLCHAIN` from the layer
# below; no workflow sets this variable, so it holds in every container job.
ENV MISE_DISABLE_TOOLS=github:orhun/git-cliff,github:max-sixty/worktrunk,github:j178/prek,github:nektos/act \
    MISE_IDIOMATIC_VERSION_FILE_ENABLE_TOOLS= \
    MISE_CARGO_BINSTALL_QUICKINSTALL=true \
    MISE_CARGO_BINSTALL_NATIVE=true

# mise may rewrite its lockfile while installing, so the build user owns pins.
# The version-2 lockfile is two parts: mise.lock and the per-npm-tool sidecars
# under .mise/locks, which the npm backend reads to install from lock.
COPY --chown=1000:1000 rust-toolchain.toml mise.toml mise.lock .github/workflows/ci.yml /opt/pins/
COPY --chown=1000:1000 .mise/locks /opt/pins/.mise/locks
COPY --chown=1000:1000 .config/mise/tasks/mise-tasks-fmt.toml .config/mise/tasks/mise-tasks-check.toml /opt/pins/.config/mise/tasks/
WORKDIR /opt/pins

# The pin supplies the channel; the image installs clippy and rustfmt alone.
RUN set -eux; \
    [ -n "$RUST_CHANNEL" ]; \
    [ "$RUST_CHANNEL" = "$(sed -n 's/^channel = "\(.*\)"/\1/p' rust-toolchain.toml)" ]; \
    curl -fsSL https://sh.rustup.rs -o /tmp/rustup-init.sh; \
    sh /tmp/rustup-init.sh -y --no-modify-path --default-toolchain none; \
    rm /tmp/rustup-init.sh; \
    rustup toolchain install "$RUST_CHANNEL" --profile minimal --component clippy,rustfmt; \
    rustup default "$RUST_CHANNEL"

# ci.yml selects mise's version. A BuildKit secret authenticates release
# attestations without persisting a credential in any layer.
RUN --mount=type=secret,id=github_token,uid=1000,required=false set -eux; \
    if [ -s /run/secrets/github_token ]; then GITHUB_TOKEN="$(cat /run/secrets/github_token)"; export GITHUB_TOKEN; fi; \
    expected="$(sed -n 's/^  MISE_DISABLE_TOOLS: "\(.*\)"$/\1/p' /opt/pins/ci.yml)"; \
    [ "$MISE_DISABLE_TOOLS" = "$expected" ] || { echo "MISE_DISABLE_TOOLS drifts from ci.yml: image='$MISE_DISABLE_TOOLS' ci='$expected'" >&2; exit 1; }; \
    MISE_VERSION="$(grep -A2 'uses: jdx/mise-action' /opt/pins/ci.yml | sed -n 's/^ *version: *//p' | head -n1 | tr -d '"')"; \
    [ -n "$MISE_VERSION" ]; \
    case "$(uname -m)" in \
        x86_64) ARCH=x64 ;; \
        aarch64) ARCH=arm64 ;; \
        *) echo "unsupported architecture $(uname -m)" >&2; exit 1 ;; \
    esac; \
    mkdir -p /opt/ci/.local/bin; \
    curl -fsSL "https://github.com/jdx/mise/releases/download/v${MISE_VERSION}/mise-v${MISE_VERSION}-linux-${ARCH}" -o /opt/ci/.local/bin/mise; \
    chmod +x /opt/ci/.local/bin/mise; \
    mise install; \
    rm -rf /opt/ci/.cargo/registry /opt/ci/.cargo/git /opt/ci/.cache

# Cargo resolves its subcommands by name; expose pinned binaries without shims.
RUN set -eux; \
    for tool in cargo-dylint dylint-link cargo-nextest; do \
        ln -sf "$(mise which "$tool")" "/opt/ci/.cargo/bin/$tool"; \
    done

# act invokes JavaScript actions through PATH rather than the hosted runner's
# bundled Node. Expose the pinned interpreter.
RUN ln -sf "$(mise which node)" /opt/ci/.local/bin/node

# A bare `cargo dylint list` does not build the compiler driver. Load a small
# disposable library against a stub crate to bake the rustc-private driver for
# the toolchain pin; the external quenchant library stays an exact CI cache.
# Building the driver needs rustc-dev, so it builds in a stage of its own and
# only the driver reaches the image: it runs on the toolchain's own rustc
# library, and rustup cannot remove a component inside a layer.
FROM tools AS driver
WORKDIR /opt/ci/warmup/app
RUN set -eux; \
    TC="$(rustup show active-toolchain | awk '{print $1}')"; \
    rustup component add rustc-dev llvm-tools; \
    mkdir -p /opt/ci/warmup/gates/src /opt/ci/warmup/app/src; \
    printf '[package]\nname = "dylint-warmup-gates"\nversion = "0.1.0"\nedition = "2021"\n\n[lib]\ncrate-type = ["cdylib"]\n' > /opt/ci/warmup/gates/Cargo.toml; \
    printf '%s\n' \
        '#![feature(rustc_private)]' \
        '' \
        'extern crate rustc_driver;' \
        'extern crate rustc_lint;' \
        'extern crate rustc_session;' \
        '' \
        'use std::ffi::CString;' \
        'use std::os::raw::c_char;' \
        '' \
        'use rustc_lint::LintStore;' \
        'use rustc_session::Session;' \
        '' \
        '#[no_mangle]' \
        'pub extern "C" fn dylint_version() -> *mut c_char {' \
        '    CString::new("0.1.0").unwrap().into_raw()' \
        '}' \
        '' \
        '#[no_mangle]' \
        'pub extern "C" fn register_lints(_sess: &Session, _store: &mut LintStore) {}' \
        > /opt/ci/warmup/gates/src/lib.rs; \
    printf '[package]\nname = "dylint-warmup-app"\nversion = "0.1.0"\nedition = "2021"\n' > /opt/ci/warmup/app/Cargo.toml; \
    printf 'fn main() {}\n' > /opt/ci/warmup/app/src/main.rs; \
    cargo build --manifest-path /opt/ci/warmup/gates/Cargo.toml --release; \
    mv "/opt/ci/warmup/gates/target/release/libdylint_warmup_gates.so" "/opt/ci/warmup/gates/target/release/libdylint_warmup_gates@${TC}.so"; \
    DYLINT_LIBRARY_PATH=/opt/ci/warmup/gates/target/release cargo dylint --lib dylint_warmup_gates --no-deps; \
    ls -l "/opt/ci/.dylint_drivers/${TC}/dylint-driver"

FROM tools
COPY --from=driver --chown=1000:1000 /opt/ci/.dylint_drivers /opt/ci/.dylint_drivers

# The runner overrides HOME. Explicit homes retain the image's populated
# tools, while root can write the workspace and runner file-command mounts.
ENV MISE_DATA_DIR=/opt/ci/.local/share/mise \
    MISE_CACHE_DIR=/opt/ci/.cache/mise \
    DYLINT_DRIVER_PATH=/opt/ci/.dylint_drivers
USER root
WORKDIR /opt/ci
