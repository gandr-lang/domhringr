# AGENTS.md

Repository facts for an agent working here. Conventions arrive through the harness, not this tree; this file states only what is specific to this repository.

- Public repository: everything committed, written in an issue, a pull request or a review is public. Configuration, deployment settings, machine facts and secrets never enter the tree.
- Every change passes `mise run check` before it is proposed: format (`treefmt`), the clippy wall and quenchant's dylint policy, private-item rustdoc, tests over every target, spelling. CI runs the same gates (`.github/workflows/ci.yml`); `mise run ci:act` runs that workflow locally.
- Dependencies live once, in the root `Cargo.toml`, one table each with `# features:` and `# consumers:` blocks and defaults off; a feature is enabled only when a build or test fails without it. The build is measured: a dependency that costs more than it carries is a review finding.
- Commits are signed and pass commitlint (`commitlint.config.mjs`); hooks install with `mise exec -- prek install`.
