# domhringr-record-tree

The record plane stores signed receipts in sedimentrees, folds them into views, and syncs them over iroh.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Receipts and views](#receipts-and-views)
- [Networking](#networking)
- [Codec](#codec)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-record-tree` is the record plane's durable, replicated receipt store. It provides one sedimentree per tree, named by the tree's own verifying key, a view of each tree's owner, delegated write authority, admitted notes, bound paths, and refused commits, and the resolution of an anchor `domhringr://<tree-id>/<path>` against that view.

**Why.** Peers need the same interpretation of signed operations regardless of arrival order. Authority depends on a commit's causal past; retaining refused commits lets peers replicate the same evidence without treating every stored write as authorized.

**How.** Published subduction crates store signed commits in redb and sync them over iroh. This crate supplies identity files, Tokio spawner and timer adapters, the value-plane receipt grammar, a deterministic fold, and a single-batch sync operation.

## References

| Artifact | Use |
| -------- | --- |
| `subduction_core`, [crate documentation](https://docs.rs/subduction_core) | Signed commit storage and batch synchronization. |
| `sedimentree_core`, [crate documentation](https://docs.rs/sedimentree_core) | Causal trees, commit ids, and signed payloads. |
| `subduction_redb_storage`, [crate documentation](https://docs.rs/subduction_redb_storage) | Durable redb storage. |
| `iroh`, [crate documentation](https://docs.rs/iroh) | Endpoint discovery, direct connections, and relays. |
| `tokio`, [crate documentation](https://docs.rs/tokio) | Runtime, task spawning, and timers. |
| `gandr-storage-values`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-values) | Canonical receipt tokens and flat encoding. |
| `getrandom`, [crate documentation](https://docs.rs/getrandom/0.4) | Operating-system randomness for operation fences. |

## Provided features

- Persistent endpoint and signing identities in a state directory, and one minted key per tree opened.
- Durable commits carrying `Open`, `Grant`, `Note`, or `Bind` receipts; an `Open` carries the tree key's proof.
- Canonical views with causal authority checks, path bindings, and explicit refusals.
- Anchors naming a tree or a path in it, resolved by fold to a binding or to unbound.
- Sorted tree heads and one-round peer synchronization.
- Ephemeral or fixed UDP binding, dialing by endpoint id or at a direct address, and selected-path reporting.

## Expected features

- A writable state directory, with exclusive access to its tree store.
- A Tokio runtime when opening a `Peer` and while its engine runs.
- A native target with an operating-system random source.
- For synchronization, network access and the remote's endpoint and signing identities.

## Examples

With `domhringr-record-tree` and Tokio's `rt` and `time` features as dependencies, this program opens a tree in a fresh state directory supplied as its first argument, binds a path in it to a note, and resolves the path's anchor:

```rust
use domhringr_record_tree::{Anchor, Identity, Peer, Receipt, Resolution, StateDir, Target, TreeKey};

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
        let bind = Receipt::bind(tree, "greeting".parse()?, Target::Commit(note))?;
        peer.commit(tree, bind).await?;
        let anchor: Anchor = format!("{}greeting", Anchor::Tree(tree)).parse()?;
        assert_eq!(peer.whence(&anchor).await?, Resolution::Bound(owner, Target::Commit(note)));
        Ok(())
    })
}
```

The tree id is the tree key's verifying key, written in an anchor as 52 z-base-32 characters; it selects a sedimentree and is not a commit digest. The [`domhringr-peer` binary](../surface-peer/README.md) names trees by anchor and peer, endpoint and commit ids in hex.

Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-tree
```

## Receipts and views

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, the key of every tree it opened, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open { proof }` (the tree's root; its author owns the tree, and the proof is the tree key's signature naming that author), `Grant { to }` (write authority delegated to a peer), `Note { text }`, or `Bind { path, target }` (a path in the tree bound to a commit, another tree, an endpoint, or an opaque datum). The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, second Open, bad proof. The tree's Open is the root Open with the smallest commit id among those whose proof holds under the tree id, so a tree id names exactly the tree its key opened. Among the admitted binds of one path, the last in canonical order binds it; an anchor's path resolves to that binding or to unbound. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

## Networking

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; a dialer that knows the remote's direct address names it, and the dial does not wait on the lookups. Each side reports the network path iroh selected — direct, relayed, or not yet chosen.

## Codec

**Receipts use the value plane's flat form, `gandr-storage-values` at the pinned sibling revision.** `Receipt` implements `CanonicalValue` using the token grammar in [`src/receipt.rs`](src/receipt.rs). A commit's blob is the flat form written by `encode_flat` and read by `decode_flat`. This is the token stream `cam_commit` cuts, so committing a receipt through the value plane's chunk DAG requires no re-encoding; a receipt fitting one chunk is exactly the body that chunk frames. The decoder admits exactly what the encoder writes, giving each receipt one blob and one commit id.

Two identities name a receipt and neither stands in for the other. The `CommitId` is sedimentree's: the BLAKE3 digest of the blob, the flat bytes alone. A value-plane `ContentPtr` names the framed chunk: BLAKE3 over the chunk image, the plane's domain and frame header included. A commit is found by its `CommitId`; a `ContentPtr` names a receipt committed into the value plane.

- postcard over a serde mirror of the receipt: compact, but requires re-encoding for the value plane and maintains a second canonical form.
- sedimentree's `codec`: the format of its signed payloads (schema header, issuer key, fields, signature) with big-endian integers; it already seals the commit that carries the blob, and as a receipt form it would be a second canonical form in another byte order.
- a hand-rolled fixed layout: one more canonical form to keep in step with the value plane's.

Reversal: an incompatible change to the value plane's token grammar or flat form requires a matching receipt version change; moving receipts into the value plane's store makes the blob a `ContentPtr` and changes what the commit id hashes.

## Dependencies

**Operation fences use `getrandom` 0.4 with no features.** `getrandom::fill` draws the 16 fence bytes from the operating system's source. iroh already brings the crate into the dependency graph, so it adds no crate to the build; native targets require no feature.

- `rand`: a seeded generator and its traits where one read from the OS source suffices.
- `uuid` with `v4`: a crate and a UUID type for what is 16 opaque bytes.

Reversal: a high-risk advisory against `getrandom`, its departure from the dependency graph, or a fence source the value plane supplies.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
