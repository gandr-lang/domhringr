#!/usr/bin/env bash
# Hash the ordered tracked pin bytes, including npm sidecars, and image sources.
# Both publication and lookup call this script, so a tag cannot drift between
# them. ci.yml supplies the baked mise version and CI subset; both are inputs.
set -euo pipefail
printf 'tag='
git ls-files -z -- mise.toml mise.lock rust-toolchain.toml .mise/locks \
    .config/mise/tasks/mise-tasks-fmt.toml .config/mise/tasks/mise-tasks-check.toml \
    .github/docker .github/workflows/ci-image.yml .github/workflows/ci.yml \
    | sort -z | xargs -0 sha256sum | sha256sum | cut -d ' ' -f 1
