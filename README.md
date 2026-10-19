# domhringr

[![CI](https://github.com/gandr-lang/domhringr/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/gandr-lang/domhringr/actions/workflows/ci.yml) [![codecov](https://codecov.io/gh/gandr-lang/domhringr/graph/badge.svg)](https://codecov.io/gh/gandr-lang/domhringr) [![licence](https://img.shields.io/badge/license-Apache--2.0_WITH_LLVM--exception-blue)](LICENSE.Apache-2.0.txt) [![rustc](https://img.shields.io/badge/rustc-nightly--2026--06--25-blue)](rust-toolchain.toml)

A software factory: seats (agent sessions) that talk to each other over [iroh](https://www.iroh.computer/), judges that grade their work against rubrics, and playbooks that say what a seat does. Every step of a task is a signed receipt in a [sedimentree](https://crates.io/crates/sedimentree_core) the peers sync, so the loop runs from the record alone.

## Status

`0.0.0`, pre-release. Every layer has a crate. The arena states the Seat protocol and its dual as session types and checks a seat's record by replay. The record plane keeps receipts in a sedimentree stored in redb and synced through [subduction](https://crates.io/crates/subduction_core), commits reports, verifier outputs and transcripts as evidence into gandr's value plane, and derives a keyed index over both. A seat answers a dispatch, acts through a program and reports; the judge reads a lettered question from a model's next-token distribution; playbooks and rubrics are TOML documents run and graded against a task. [`crates/README.md`](crates/README.md) lists every crate, and [`rubrics/README.md`](rubrics/README.md) the rubric set a change is graded by.

## Usage

`domhringr` runs the task loop for one operator:

```text
domhringr open [--project <tree>]
domhringr dispatch <task> --seat <peer-id> --brief <anchor|content-hash>
domhringr verify <task> --playbook <file>
domhringr decide <task> --rubric <file>...
domhringr land <task> --repo <dir>
```

`domhringr-peer` operates a peer's trees: it opens, grants on, writes to, binds in, resolves, views and syncs a tree, serves as a seat, rules on a task as its judge, and runs playbooks and grades rubrics on a task. The [driver](crates/surface-driver/README.md) and [peer](crates/surface-peer/README.md) crates document every command and its output.

## Build

```sh
mise install            # the pinned toolchain and tools
mise run sibling:sync   # vendor/gandr at the pinned revision
cargo build --release
```

## License

Apache-2.0 WITH LLVM-exception. See `LICENSE.Apache-2.0.txt` and `LICENSE.LLVM-exception.txt`.
