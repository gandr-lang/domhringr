# domhringr-record-index

A project's derived index as one store of gandr's keyed schema, attested by its root, proved question by question, replayed through named session protocols and checked against the receipt fold.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** The keyed plane over the receipt fold: a project's tasks, their attempts and admitted moves, their refusals, and the evidence and landed revisions each move names, derived into one store of `gandr_storage_schema::keyed::schema()`, attested by an `Indexed` receipt naming the store's root, and proved to a reader that holds only that root.

**Why.** A reader asking where a task stands, which move named a piece of evidence or which revision landed should not fold every task tree it reaches. An attested store answers each question with a proof checked against one root, and the historical check rebuilds what the attestation claims from the receipts it names, so an index is never authority over the fold.

**How.** Derivation runs above the fold, edits the previous store and reuses a task's parts only at an identical frontier. A task holds its standing's kind; the rest of the standing is recomputed from its last attempt's play. Node files are content-addressed and published before their manifest. Questions travel one per stream under `domhringr/index/0`, within a 1 MiB answer cap, and their proofs verify against the attested root alone. Attested replay feeds an attempt's proved moves to the arena monitor under the dispatch's edition.

## Provided features

- `keyed::Keyed`: the schema's objects, arrows and attributes, and the codecs of their values.
- `derive::Deriver`, `derive::at` and `derive::held`: a project's store, refreshed task by task, reused only when the heads are unchanged.
- `prove::Ask` with `prove::task`, `prove::claim`, `prove::play`, `prove::later`, `prove::current`, `prove::named` and `prove::contents`: readers over any asker, local or remote.
- `replay::replay`: an attested attempt admitted through the arena's session protocols, refused at the `(attempt, seq)` that breaks them.
- `check::check`: an attestation compared with independent folds at its named frontiers.
- `store::Store` and `stream::Remote` / `stream::fetch` / `stream::answer`: node and manifest files under the peer's state, and the proof protocol between peers.
- `measure::measure`: each table's record count, root and leaf extents, and its largest framed answer.

## Expected features

- A peer from `domhringr-record-tree` holding the receipt trees an index derives from.
- A Tokio runtime and an iroh endpoint for the proof protocol.

## Examples

The [peer commands](../surface-peer/README.md) derive and attest a project, prove its tasks and move coordinates, resolve provenance and check historical claims. Run the crate's tests:

```sh
mise exec -- cargo nextest run -p domhringr-record-index
```

## Where the detail lives

| Topic | Module |
| ----- | ------ |
| Decisions, with alternatives and reversals | [`src/lib.rs`](src/lib.rs) |
| The schema's ids and value codecs | [`src/keyed.rs`](src/keyed.rs) |
| Move coordinates and move values | [`src/dialogue.rs`](src/dialogue.rs), [`src/key.rs`](src/key.rs) |
| Tasks, aliases and refreshes | [`src/project.rs`](src/project.rs), [`src/derive.rs`](src/derive.rs) |
| Subjects and their fields | [`src/provenance.rs`](src/provenance.rs) |
| Readers and trust | [`src/prove.rs`](src/prove.rs), [`src/check.rs`](src/check.rs) |
| Attested replay | [`src/replay.rs`](src/replay.rs) |
| Storage, cursors and the serving cache | [`src/store.rs`](src/store.rs) |
| The proof protocol | [`src/stream.rs`](src/stream.rs) |
| Measurements and their pinned crossings | [`src/measure.rs`](src/measure.rs) |

Attested replay and the dialogue are also written in gandr. [`domhringr/arena/replay.gandr`](../../domhringr/arena/replay.gandr)'s exemplars give the refusals and standings this crate's replay tests give, and [`domhringr/record/dialogue.gandr`](../../domhringr/record/dialogue.gandr)'s give the coordinates `dialogue::derive` gives to the fold's steps.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
