# domhringr-record-index

Derived dialogue, project and provenance indexes, authenticated by manifests, replayed through named session protocols and checked against the receipt fold.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** The keyed plane over the receipt fold: a task's admitted moves as a dialogue keyed by `(attempt, seq)`, a project's task bindings with their standings and refusals, and the evidence and landed revisions each move names, each derived into an ordered record tree of `gandr-storage-records`, named by a kind-bound manifest, attested by an `Indexed` receipt and proved to a reader that holds only the manifest.

**Why.** A reader asking where a task stands, which move named a piece of evidence or which revision landed should not fold every task tree it reaches. An attested index answers with a proof checked against one manifest digest, and the historical check rebuilds what the attestation claims from the receipts it names, so an index is never authority over the fold.

**How.** Derivation runs above the fold and reuses a task's entry only at an identical frontier. Node files are content-addressed and published before their manifest. Proofs travel one question per stream under `domhringr/index/0`, within a 1 MiB answer cap, and verify against the resealed root alone. Attested replay feeds an attempt's proved moves to the arena monitor under the dispatch's edition.

## Provided features

- `dialogue::derive`, `project::build` and the `provenance` records: the three index kinds, each an `Index` of a `Manifest` and its record tree.
- `derive::at` and `derive::held`: per-task derivation at a frontier, reused only when the heads are unchanged.
- `prove::answer`, `prove::play`, `prove::later` and `prove::Answer::verify`: membership, absence and complete-range proofs and their root-only verification.
- `replay::replay`: an attested attempt admitted through the arena's session protocols, refused at the `(attempt, seq)` that breaks them.
- `check::check`: an attestation compared with independent folds at its named frontiers.
- `store::Store` and `stream::ask` / `stream::answer`: node and manifest files under the peer's state, and the proof protocol between peers.
- `measure::measure`: record count, root and leaf extents, and the largest single-key answer.

## Expected features

- A peer from `domhringr-record-tree` holding the receipt trees an index derives from.
- A Tokio runtime and an iroh endpoint for the proof protocol.

## Examples

The [peer commands](../surface-peer/README.md) derive and attest a project, prove its entries and dialogue coordinates, resolve provenance and check historical claims. Run the crate's tests:

```sh
mise exec -- cargo nextest run -p domhringr-record-index
```

## Where the detail lives

| Topic | Module |
| ----- | ------ |
| Decisions, with alternatives and reversals | [`src/lib.rs`](src/lib.rs) |
| Dialogue coordinates and move values | [`src/dialogue.rs`](src/dialogue.rs), [`src/key.rs`](src/key.rs) |
| Project entries and standings | [`src/project.rs`](src/project.rs) |
| Provenance keys | [`src/provenance.rs`](src/provenance.rs) |
| Manifests, layouts and trust | [`src/manifest.rs`](src/manifest.rs), [`src/check.rs`](src/check.rs) |
| Attested replay | [`src/replay.rs`](src/replay.rs) |
| Storage, cursors and the serving cache | [`src/store.rs`](src/store.rs) |
| The proof protocol | [`src/stream.rs`](src/stream.rs) |
| Measurements and their pinned crossings | [`src/measure.rs`](src/measure.rs) |

Attested replay is also written in gandr, in [`domhringr/arena/replay.gandr`](../../domhringr/arena/replay.gandr), whose exemplars give the refusals and standings this crate's replay tests give.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
