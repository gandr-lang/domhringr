# AGENTS.md

Repository facts for an agent working here. Conventions arrive through the harness, not this tree; this file states only what is specific to this repository.

- Public repository: everything committed, written in an issue, a pull request or a review is public. Configuration, deployment settings, machine facts and secrets never enter the tree.
- Every change passes `mise run check` before it is proposed: format (`treefmt`), the clippy wall and quenchant's dylint policy, private-item rustdoc, tests over every target, spelling. CI runs the same gates (`.github/workflows/ci.yml`); `mise run ci:act` runs that workflow locally, and `wt merge` runs it as the merge gate (`.config/wt.toml`) until the repository has hosted CI.
- Dependencies live once, in the root `Cargo.toml`, one table each with `# features:` and `# consumers:` blocks and defaults off; a feature is enabled only when a build or test fails without it. The build is measured: a dependency that costs more than it carries is a review finding.
- Commits are signed and pass commitlint (`commitlint.config.mjs`); hooks install with `mise exec -- prek install`.
- Crates are named by `crates/README.md`: `crates/<category>-<name>`, package `domhringr-<category>-<name>`, categories in layering order; the driver `crates/surface-driver` is the one exception, package `domhringr`. A new crate adds its row there in the same change.
