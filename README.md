# domhringr

A software factory: seats (agent sessions) that talk to each other over [iroh](https://www.iroh.computer/), judges that grade their work against rubrics, and playbooks that say what a seat does. Built one crate at a time.

## Status

`0.0.0`. The `domhringr` crate claims the name and reports its version. The record plane has its first piece: `domhringr-record-tree` stores a [sedimentree](https://crates.io/crates/sedimentree_core) on disk and syncs it with a peer over iroh through [subduction](https://crates.io/crates/subduction_core), and the `domhringr-peer` binary (`crates/surface-peer`) drives it from the command line. The seat, the judge, and the playbooks and rubrics a task is checked by stand on it; [`crates/README.md`](crates/README.md) lists every crate, and [`rubrics/README.md`](rubrics/README.md) the rubric set a change is graded by.

The first arena, [`domhringr-arena-session`](crates/arena-session/README.md), states the Seat protocol and its dual as session types. The record fold checks conformance by replay, retains named move refusals, and interprets pause through a kernel-certified widening without rewriting old receipts.

## Build

```sh
mise install           # the pinned toolchain and tools
mise run sibling:sync  # vendor/gandr: link the gandr checkout beside this one
mise run check         # every gate: format, clippy, dylint, rustdoc, tests, typos
cargo build-dist       # the shipped binary: fat LTO, size-optimized std
```

`cargo build --release` is the everyday optimized build; `cargo build-dist` (`.cargo/config.toml`) is the whole-program one.

Use `mise run test -- <nextest args>` for test runs. On macOS, set `CODESIGN_IDENTITY` to a local, test-only code-signing identity in the login keychain. Trust its certificate for code signing once, then check that the identity is valid:

```sh
cert=$(mktemp)
security find-certificate -c "$CODESIGN_IDENTITY" -p \
  "$HOME/Library/Keychains/login.keychain-db" > "$cert"
security add-trusted-cert -p codeSign \
  -k "$HOME/Library/Keychains/login.keychain-db" "$cert"
rm "$cert"
security find-identity -v -p codesigning
```

The test task signs both test executables and the binaries they launch with `org.gandr-lang.domhringr.test`. Allow the first firewall prompt if one appears; the same certificate and identifier let the firewall recognize later builds and worktrees. User-domain trust is sufficient for this workflow; administrator-domain trust is not required. Keep this identity out of release signing. With `CODESIGN_IDENTITY` unset, or on Linux, tests run as built.

CI builds every target under the test profile: size-optimized `release` code without debuginfo, with debug assertions and overflow checks explicitly enabled. `mise run test -- --profile ci` runs the existing test task against that build; private-item rustdoc uses the same Cargo profile. `release` and the aggressive, uncached `dist` profile are unchanged.

The complete test artifact set is archived with zstd and uploaded without recompression. The archive contains `target/debug`, not unrelated profiles or generated documentation. Its cache retains integration-test binaries independently of dependency-cache cleanup, and Cargo checks source contents rather than checkout mtimes. Main promotes verified queue artifacts; hosted manual runs warm branch-local caches. The locked mise cache supplies installed policy tools, including sizelint, without rebuilding them on warm runs.

Archive creation stops the job if either tar or zstd fails.

`mise run ci:act` runs the committed Linux CI workflow in a disposable checkout. Two host-wide slots bound concurrent gates across repositories and worktrees; further invocations wait until a slot frees. Dead holders are reclaimed. Each invocation uses distinct container names. Cached actions run without GitHub fetches; missing actions download on first use.

Completed and interrupted gates remove their containers, networks and volumes. Before starting, each gate reaps resources from abandoned runs whose workflow process is gone; live runs and the shared `act-toolcache` volume remain untouched.

Each gate snapshots the shared action cache. Successful gates publish only new cache entries under a directory lock; a 30-second lock timeout fails the gate.

## Landing changes

Install the hooks with `mise exec -- prek install`. Run `mise run check`, then sign the commit and pass commitlint locally; the ruleset requires signatures on every commit in the pull request range. For changes to `.github/` (including `.github/docker/`) or `.config/mise/tasks/`, also run `mise run ci:act` after committing. Other changes use the native gates and the hosted merge queue.

Push the branch, open a pull request, then wait for its landing:

```sh
git push -u origin <branch>
gh pr create --base main --fill
mise run pr:land
```

`pr:land [<n>]` defaults to the current branch's pull request. It enables auto-merge and watches both the pull request and its queue entry every 30 seconds, printing state changes.

| Outcome | Exit | Output |
| ------- | ---- | ------ |
| Merged | `0` | Merge commit, merge-group run URL and each job's wall time |
| Failed checks or dequeue | `1` | Failing run's logs |
| 90-minute timeout | `2` | Last observed state |
| `UNMERGEABLE` queue entry | `3` | Entries ahead and shared files |

For an `UNMERGEABLE` entry, rebase onto `main` after the entries ahead merge, then run the task again.

The merge queue runs the merge-group lanes and lands the change by merge commit. The repository allows only merge commits and deletes the branch after merging.

## License

Apache-2.0 WITH LLVM-exception. See `LICENSE.Apache-2.0.txt` and `LICENSE.LLVM-exception.txt`.
