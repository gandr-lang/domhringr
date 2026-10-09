# domhringr

A software factory: seats (agent sessions) that talk to each other over [iroh](https://www.iroh.computer/), judges that grade their work against rubrics, and playbooks that say what a seat does. Built one crate at a time.

## Status

`0.0.0`. The `domhringr` crate claims the name and reports its version. The record plane has its first piece: `domhringr-record-tree` stores a [sedimentree](https://crates.io/crates/sedimentree_core) on disk and syncs it with a peer over iroh through [subduction](https://crates.io/crates/subduction_core), and the `domhringr-peer` binary (`crates/surface-peer`) drives it from the command line. The seat, the judge, and the playbooks and rubrics a task is checked by stand on it; [`crates/README.md`](crates/README.md) lists every crate, and [`rubrics/README.md`](rubrics/README.md) the rubric set a change is graded by.

## Build

```sh
mise install           # the pinned toolchain and tools
mise run sibling:sync  # vendor/gandr: link the gandr checkout beside this one
mise run check         # every gate: format, clippy, dylint, rustdoc, tests, typos
cargo build-dist       # the shipped binary: fat LTO, size-optimized std
```

`cargo build --release` is the everyday optimized build; `cargo build-dist` (`.cargo/config.toml`) is the whole-program one.

Use `mise run test -- <nextest args>` for test runs; on macOS, setting `CODESIGN_IDENTITY` signs rebuilt executables before they run.

`mise run ci:act` runs the committed Linux CI workflow in a disposable checkout. Each invocation uses distinct container names, so gates can run concurrently across repositories and worktrees. Cached actions run without GitHub fetches; missing actions download on first use.

Each gate snapshots the shared action cache. Successful gates publish only new cache entries under a directory lock; a 30-second lock timeout fails the gate.

## Landing changes

Install the hooks with `mise exec -- prek install`. Sign every commit and pass commitlint locally; the ruleset requires signatures on every commit in the pull request range. Run `mise run check` before opening the pull request.

Push the branch to `origin`, open a pull request against `main`, then enable automatic merging:

```sh
git push -u origin <branch>
gh pr create --base main --fill
gh pr merge --merge --auto <n>
```

The merge queue runs the merge-group lanes and lands the change by merge commit. The repository allows only merge commits and deletes the branch after merging.

## License

Apache-2.0 WITH LLVM-exception. See `LICENSE.Apache-2.0.txt` and `LICENSE.LLVM-exception.txt`.
