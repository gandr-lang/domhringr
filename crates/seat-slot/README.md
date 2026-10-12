# domhringr-seat-slot

The seat answers an operator's wake for a dispatch it holds, acts on the brief through a command surface, keeps the result as evidence and reports it into the task's tree.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-seat-slot` is the Player participant's exchange around a task tree. `wake` is the operator's side: it names a dispatch to the seat holding it and pulls back what the seat committed. `serve` is the seat's side: it answers wakes, presents the seat in the task's book, runs a program on the brief, keeps its output as evidence and commits a report naming it, answers fetches of that evidence, and resumes on start every dispatch it holds unreported. It reports each step as an `Event`.

**Why.** A dispatch, a report, a handoff and a retirement are receipts, and the record plane's fold decides which of them count (see [`domhringr-record-tree`](../record-tree/src/task.rs)). Something still has to tell a seat that a dispatch waits for it, get the seat the tree, run the work and write the report. Each side must survive a restart with no state outside its store.

**How.** The operator links to the seat over subduction, opens a second connection under the ALPN `domhringr/seat/0`, and writes one line: the dispatch's commit anchor and its own peer id. The seat pulls the task over the operator's link and folds it. It checks that the dispatch is current and that the seat holds its slot, presents itself if the task's book lacks it, and replies `woken` or `declined <reason>`. A woken operator pulls the task back, which carries the seat's presence. The seat then runs its program as `<program> anchor|content <brief>` on a blocking thread, commits the program's standard output to its evidence store ([`domhringr-record-evidence`](../record-evidence/README.md)), and commits a `Report` naming that output by its value manifest, with its first line as the summary. Any reader holding the report fetches the output from the seat under `domhringr/evidence/0`.

## Provided features

- `PROTOCOL`, the ALPN a seat answers wakes under, for `Peer::bind`.
- `Wake`, the line naming a dispatch and its operator, and `Reply`, the line answering it, each with its text form and its named refusals.
- `wake`, the operator's side of one wake. It links, asks, pulls the task back on `woken`, and drops the link, and it reports a decline by its reason.
- `serve`, the seat's side. It reports accepted links, wakes, acts, evidence fetches, index proof connections and resumption as `Event` values. Index connections end as `Proved` with their answer count or `Unproved` with the stream failure.
- `Surface`, what a seat acts through: `Hold`, which keeps the slot and never reports, or a `Program`.

## Expected features

- A Tokio runtime with the multi-threaded scheduler, timers and the blocking pool.
- A node bound with `PROTOCOL`, the evidence protocol and `domhringr_record_index::stream::PROTOCOL`, so wakes, fetches and proofs reach `serve`; evidence and index stores opened beneath the seat's state directory.
- For `wake`, the dispatch already committed in the operator's store and a route to the seat: its endpoint named by hand, or its presence in the book.
- For `Surface::Program`, an executable that takes `anchor <anchor>` or `content <hash>` as its two arguments. It reads the task's and the dispatch's anchors from `DOMHRINGR_TASK` and `DOMHRINGR_DISPATCH`, exits 0 when it has a report, and writes the report to standard output with a first line of at most 256 bytes and no control character.

## Examples

With `domhringr-record-evidence`, `domhringr-record-index`, `domhringr-record-tree`, `domhringr-seat-slot` and Tokio's `rt-multi-thread`, `sync` and `time` features as dependencies, this program opens a task, dispatches its own peer, serves through `echo` and prints the report's commit id:

```rust
use std::sync::Arc;

use domhringr_record_evidence::{Evidence, PROTOCOL as EVIDENCE};
use domhringr_record_index::{store::Store, stream::PROTOCOL as INDEX};
use domhringr_record_tree::{BindPort, Brief, Content, ContentHash, Identity, Peer, Receipt, StateDir, TreeKey};
use domhringr_seat_slot::{Event, PROTOCOL, Surface, serve};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let identity = Identity::load_or_create(&state)?;
        let me = identity.peer_key();
        let node = Arc::new(Peer::open(&state, identity)?.bind(BindPort::Ephemeral, &[PROTOCOL, EVIDENCE, INDEX]).await?);
        let key = TreeKey::mint(&state)?;
        let tree = key.tree();
        node.peer().commit(tree, Receipt::open(&key, me)?).await?;
        let brief = Brief::Content(ContentHash::of(&Content::from(b"the brief".to_vec())));
        node.peer().commit(tree, Receipt::dispatch(tree, me, domhringr_record_tree::Edition::ONE, brief)?).await?;
        let mut events = serve(Arc::clone(&node), Surface::Program("echo".into()), Evidence::open(&state), Store::open(&state));
        while let Some(event) = events.recv().await {
            if let Event::Reported { report, .. } = event {
                println!("{report}");
                break;
            }
        }
        node.close().await;
        Ok(())
    })
}
```

The [`domhringr-peer` binary](../surface-peer/README.md) puts both sides on the command line: `dispatch` wakes a seat, `serve --surface <program>` serves as one, and `replay` prints the task. Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-seat-slot
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| The wake | [`wake`](src/wake.rs) |
| Presence, the command surface, resuming | [`seat`](src/seat.rs) |
| Dependencies, references | [`src/lib.rs`](src/lib.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
