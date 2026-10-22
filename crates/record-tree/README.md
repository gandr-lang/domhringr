# domhringr-record-tree

The record plane stores signed receipts in sedimentrees, folds them into views, and syncs them over iroh.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-record-tree` is the record plane's durable, replicated receipt store. It provides one sedimentree per tree, named by the tree's own verifying key, a view of each tree's owner, delegated write authority, admitted notes, bound paths, claimed DNS names, introduced trees, the book of which member is reachable at which endpoint, the task its seat receipts, judges' verdicts, runners' verifications, verdicts' gradings and the operator's decisions and landings make of the tree, and admitted and refused commits, and the resolution against those views of an anchor naming a tree, a path in it, `domhringr://<authority>/<path>`, or a commit in it, `domhringr://<authority>/.commit/<commit-id>`, whose authority takes three forms: the tree's key, a DNS name, or a label.

**Why.** Peers need the same interpretation of signed operations regardless of arrival order. Authority depends on a commit's causal past; retaining refused commits lets peers replicate the same evidence without treating every stored write as authorized.

**How.** Published subduction crates store signed commits in redb and sync them over iroh. This crate supplies identity files, Tokio spawner and timer adapters, the value-plane receipt grammar, a deterministic fold, and a single-batch sync operation.

## Provided features

- Persistent endpoint and signing identities in a state directory, and one minted key per tree opened.
- Durable commits carrying `Open`, `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, `Withdraw`, `Dispatch`, `Report`, `Handoff`, `Retire`, `Pause`, `Verdict`, `Verified`, `Graded`, `Decide`, `Landed` or `Indexed` receipts; an `Open` carries the tree key’s proof, a `Present` the presented endpoint key’s; a report’s content, a verdict’s transcript and a verification’s output are named by their value manifest’s digest, and `Task::evidence` lists each with the peer that holds it.
- Canonical views with causal authority checks, path bindings, owner-only name claims, label introductions, a book of each member's own presented endpoint, a task of seat receipts, verdicts, verifications, gradings, decisions and landings with its current attempt and how far it has progressed, and explicit refusals.
- A judge's `Ruling` on a lettered question: read, as the answer `Letter` and each option's `Probability` with the mass outside the options (`Readout`), or unread for a named reason (`Unread`).
- Anchors naming a tree, a path in it, or a commit in it by key, by DNS name, or by label, resolved by fold to a binding, to unbound, to a commit's verdict, to unknown, or to a named refusal; a `Reference` may abbreviate a commit id to a unique prefix of at least eight hex digits.
- A `Witness` trait for a DNS name's candidate trees, with the `Dns` witness over `_domhringr.<domain>` TXT records and the `Static` witness supplied by hand.
- Sorted tree heads, the trees a store holds, and one-round peer synchronization.
- Ephemeral or fixed UDP binding beside other application protocols, presenting the bound endpoint in a tree, routing a dial for a tree through its book or to an endpoint named by hand, dialing an endpoint by its id and any addresses, a link held open for pulls, and selected-path reporting.

## Expected features

- A writable state directory, with exclusive access to its tree store.
- A Tokio runtime when opening a `Peer` and while its engine runs.
- A native target with an operating-system random source.
- For synchronization, network access and the remote's endpoint and signing identities: named by hand at first contact, or read from the tree's book once a sync has carried the remote's presence.
- For a DNS-form anchor, a witness: DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, or a `Static` map.
- For the ignored test `witness::tests::the_dns_witness_reads_a_real_record`, `DOMHRINGR_WITNESS=<domain>=<tree id>` naming a published witness record; the test fails naming the variable when it is unset, and CI does not run it.

## Examples

With `domhringr-record-tree` and Tokio's `rt` and `time` features as dependencies, this program opens a tree in a fresh state directory supplied as its first argument, binds a path in it to a note's commit, claims a DNS name for the tree, resolves the path's anchor by key and by the DNS name under a witness supplied by hand, and resolves the note's commit by a prefix of its id:

```rust
use domhringr_record_tree::{Anchor, Domain, Identity, Peer, Receipt, Reference, Resolution, Scope, StateDir, Static, Target, TreeKey, Verdict};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let identity = Identity::load_or_create(&state)?;
        let owner = identity.peer_key();
        let peer = Peer::open(&state, identity)?;
        let key = TreeKey::mint(&state)?;
        let tree = key.tree();
        peer.commit(tree, Receipt::open(&key, owner)?).await?;
        let note = peer.commit(tree, Receipt::note(tree, "hello".into())?).await?;
        let target = Target::Anchor(Anchor::commit(tree, note));
        let bind = Receipt::bind(tree, "greeting".parse()?, target.clone())?;
        peer.commit(tree, bind).await?;
        let domain: Domain = "example.test".parse()?;
        peer.commit(tree, Receipt::claim(tree, domain.clone())?).await?;
        let witness: Static = [(domain, tree)].into_iter().collect();
        let bound = Resolution::Bound(owner, target);
        for text in [format!("{}greeting", Anchor::key(tree)), "domhringr://example.test/greeting".into()] {
            let reference: Reference = text.parse()?;
            assert_eq!(peer.whence(&reference, &witness, Scope::Unscoped).await?, bound);
        }
        let prefix: String = note.to_string().chars().take(12).collect();
        let commit: Reference = format!("{}.commit/{prefix}", Anchor::key(tree)).parse()?;
        let located = Resolution::Commit { id: note, verdict: Verdict::Admitted };
        assert_eq!(peer.whence(&commit, &witness, Scope::Unscoped).await?, located);
        Ok(())
    })
}
```

The tree id is the tree key's verifying key, written in an anchor as 52 z-base-32 characters; it selects a sedimentree and is not a commit digest. The [`domhringr-peer` binary](../surface-peer/README.md) names trees by anchor and peer, endpoint and commit ids in hex.

Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-tree
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| Receipts, views and the codec | [`receipt`](src/receipt.rs) |
| Index attestations | [`fold`](src/fold.rs) |
| Anchors and witnesses | [`anchor`](src/anchor.rs) |
| Presence | [`presence`](src/presence.rs) |
| Tasks | [`task`](src/task.rs) |
| Networking | [`node`](src/node.rs) |
| Dependencies, references | [`src/lib.rs`](src/lib.rs) |

The fold is also written in gandr. [`domhringr/record/`](../../domhringr/record/) states the receipt kinds, the authority checks with their refusals, and the fold into the view as gandr sources; their `runs` exemplars give the views this crate's fold gives on its test sequences. `mise run check:gandr` checks and runs them with the driver built from the gandr sibling at its pin.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
