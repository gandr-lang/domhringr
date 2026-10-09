# domhringr-seat-slot

The seat answers an operator's wake for a dispatch it holds, acts on the brief through a command surface, and reports the result into the task's tree.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [The wake](#the-wake)
- [Presence](#presence)
- [The command surface](#the-command-surface)
- [Resuming](#resuming)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-seat-slot` is the Player participant's exchange around a task tree. `wake` is the operator's side: it names a dispatch to the seat holding it and pulls back what the seat committed. `serve` is the seat's side: it answers wakes, presents the seat in the task's book, runs a program on the brief, commits a report of its output, and resumes on start every dispatch it holds unreported. It reports each step as an `Event`.

**Why.** A dispatch, a report, a handoff and a retirement are receipts, and the record plane's fold decides which of them count (see [`domhringr-record-tree`](../record-tree/README.md#tasks)). Something still has to tell a seat that a dispatch waits for it, get the seat the tree, run the work and write the report. Each side must survive a restart with no state outside its store.

**How.** The operator links to the seat over subduction, opens a second connection under the ALPN `domhringr/seat/0`, and writes one line: the dispatch's commit anchor and its own peer id. The seat pulls the task over the operator's link and folds it. It checks that the dispatch is current and that the seat holds its slot, presents itself if the task's book lacks it, and replies `woken` or `declined <reason>`. A woken operator pulls the task back, which carries the seat's presence. The seat then runs its program as `<program> anchor|content <brief>` on a blocking thread and commits a `Report` holding the BLAKE3 hash of the program's standard output and its first line as the summary.

## References

| Artifact | Use |
| -------- | --- |
| S. Friedl, A. Popov, A. Langley, E. Stephan, _Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension_, IETF RFC 7301, July 2014, [doi:10.17487/RFC7301](https://doi.org/10.17487/RFC7301) | The protocol name a connection carries, by which the node routes the wake apart from subduction's sync. |
| `iroh`, [crate documentation](https://docs.rs/iroh) | QUIC connections and their bidirectional streams. |
| `tokio`, [crate documentation](https://docs.rs/tokio) | Tasks, the event channel, blocking threads for the program, and the reply deadline. |

## Provided features

- `PROTOCOL`, the ALPN a seat answers wakes under, for `Peer::bind`.
- `Wake`, the line naming a dispatch and its operator, and `Reply`, the line answering it, each with its text form and its named refusals.
- `wake`, the operator's side of one wake. It links, asks, pulls the task back on `woken`, and drops the link, and it reports a decline by its reason.
- `serve`, the seat's side. It handles accepted links, wakes answered or declined, acts reported or not, and resumption on start, and it reports each as an `Event` on an unbounded channel.
- `Surface`, what a seat acts through: `Hold`, which keeps the slot and never reports, or a `Program`.

## Expected features

- A Tokio runtime with the multi-threaded scheduler, timers and the blocking pool.
- A node bound with `PROTOCOL` among its protocols (`Peer::bind`), so that wakes reach `serve`.
- For `wake`, the dispatch already committed in the operator's store and a route to the seat: its endpoint named by hand, or its presence in the book.
- For `Surface::Program`, an executable that takes `anchor <anchor>` or `content <hash>` as its two arguments. It reads the task's and the dispatch's anchors from `DOMHRINGR_TASK` and `DOMHRINGR_DISPATCH`, exits 0 when it has a report, and writes the report to standard output with a first line of at most 256 bytes and no control character.

## Examples

With `domhringr-record-tree`, `domhringr-seat-slot` and Tokio's `rt-multi-thread`, `sync` and `time` features as dependencies, this program opens a task in a fresh state directory supplied as its first argument and dispatches its own peer to a brief. It then serves as that seat through `echo`, which resumes the dispatch on start and reports on it, and prints the report's commit id:

```rust
use std::sync::Arc;

use domhringr_record_tree::{BindPort, Brief, Content, ContentHash, Identity, Peer, Receipt, StateDir, TreeKey};
use domhringr_seat_slot::{Event, PROTOCOL, Surface, serve};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let runtime = tokio::runtime::Builder::new_multi_thread().enable_all().build()?;
    runtime.block_on(async {
        let identity = Identity::load_or_create(&state)?;
        let me = identity.peer_key();
        let node = Arc::new(Peer::open(&state, identity)?.bind(BindPort::Ephemeral, &[PROTOCOL]).await?);
        let key = TreeKey::mint(&state)?;
        let tree = key.tree();
        node.peer().commit(tree, Receipt::open(&key, me)?).await?;
        let brief = Brief::Content(ContentHash::of(&Content::from(b"the brief".to_vec())));
        node.peer().commit(tree, Receipt::dispatch(tree, me, brief)?).await?;
        let mut events = serve(Arc::clone(&node), Surface::Program("echo".into()));
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

## The wake

**A wake is one line naming the dispatch by its commit anchor and the operator by its peer id.** The record holds the dispatch, and the line only says which one to read. The seat folds the task it pulled and does not trust the line for anything the fold decides. The line is 512 bytes at most, UTF-8, ending in its one newline. The reply is `woken`, or `declined` with its reason: `malformed`, `unsynced`, `unfolded`, `not current`, `not held` or `unpresented`. Neither line is stored or hashed.

- a value-plane token stream for the line: a second canonical encoding for bytes that are never stored and that a person reading a capture can already read.
- the dispatch's receipt carried in the line: a second copy of a record the seat must fold anyway, to judge it in its causal past.

Reversal: a wake that carries something the record cannot, such as a capability, when it needs a canonical form.

**The seat pulls the task over the operator's link; the operator does not push it.** The operator links over subduction first and only then opens the wake's connection. The node admits links one at a time, so the link is registered before the wake is handed over, and the seat pulls over it without dialing back. On `woken` the operator pulls in turn, and the seat's presence, committed while it answered, comes back with it.

- the operator pushing the task before it wakes the seat: a sync's batch round goes both ways, so the push and the pull are one round. The seat still has to fold what arrived, and the push could not include a presence the seat has not yet committed.
- the seat dialing the operator back: the operator would need a presence or a reachable endpoint of its own, and a short-lived command line has neither.

Reversal: an operator that serves, reachable at its own presence, when the seat can sync on its own schedule.

**The operator waits thirty seconds for the reply.** In that time the seat pulls, folds and, when it has no presence in the book, presents itself. Presenting waits up to five seconds for the seat's endpoint to reach its home relay. The seat waits up to ten seconds after replying for the operator to close the connection, so that the reply is read before the connection is dropped.

## Presence

**A seat presents itself in the task's book when the book lacks it, during the wake.** An operator reaches the seat at an endpoint it names by hand once. After that, the task's book names where the seat is, for the next dispatch, a replay, or another operator. A seat already in the book is not presented again, so a wake commits nothing when nothing changed.

- presenting on every wake: a commit per wake for an endpoint that has not moved.
- presenting at `serve` start in every tree the store holds: commits in trees whose dispatch went to another seat.

Reversal: a seat whose addresses change between wakes. It then presents again whenever its endpoint differs from its book entry.

## The command surface

**A seat acts by running a program, and its standard output is the report.** The report holds the BLAKE3 hash of the whole output and its first line as the summary. A report is committed only when the program exits 0 with a first line that is a summary, and the hash names exactly the bytes the program printed. The seat does not keep those bytes; a report records what was produced, not where it lives. The program runs on Tokio's blocking pool through `std::process`.

- Tokio's `process` feature: an async child for one blocking wait per act, at the cost of a feature and its signal handling.
- a long-running harness over a pipe: the harness shim. A program per act is enough to act and report, and the shim replaces it.

Reversal: the harness shim, which drives a persistent agent session instead of one program per act.

**A failed act leaves the slot held and the report awaited.** A program that cannot start, exits non-zero, or prints no summary is reported as `Unreported` with its reason, and nothing is committed. The next wake for the same dispatch, or the seat's next start, acts again. Only a retirement or a handoff moves the slot.

- committing a retirement on failure: a transient fault would give the slot up, and the operator would have to dispatch again.

Reversal: a failure kind the operator must see in the record, such as a brief the program refuses. It needs a receipt of its own.

## Resuming

**On start a seat acts again on every dispatch it holds unreported, in every tree its store holds.** The store is the seat's only state. A seat killed while acting resumes the act, and a seat whose act failed retries it when it next starts. While an act runs, a wake for the same dispatch replies `woken` and starts no second act. An act interrupted by a kill runs its program again on resume, so a program sees each dispatch at least once.

- a journal of acts in progress beside the store: a second record for what the task's tree already says. A dispatch held and awaited is exactly a dispatch to act on.

Reversal: a program whose effects must not repeat. It then needs an act receipt committed before it runs.

## Dependencies

**Tokio's `sync` feature carries the event channel and the set of dispatches being acted on.** The feature is already in the graph through iroh and subduction, so it adds nothing to the build. The set sits behind `tokio::sync::Mutex`, whose lock does not poison.

- `std::sync::Mutex`: poisoning makes every lock a `Result` the seat has no use for, and the lock is held across no await either way.

Reversal: a single-threaded seat, which needs no lock.

**`iroh` is a direct dependency for the connection the wake runs on.** `Node::accept` hands over an `iroh::endpoint::Connection`, and the seat opens and reads its streams. iroh is the transport the record plane already binds.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
