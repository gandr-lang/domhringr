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

**What.** `domhringr-record-tree` is the record plane's durable, replicated receipt store. It provides one sedimentree per tree id and a view of each tree's owner, delegated write authority, admitted notes, and refused commits.

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

- Persistent endpoint and signing identities in a state directory.
- Durable commits carrying `Open`, `Grant`, or `Note` receipts.
- Canonical views with causal authority checks and explicit refusals.
- Sorted tree heads and one-round peer synchronization.
- Ephemeral or fixed UDP binding and selected-path reporting.

## Expected features

- A writable state directory, with exclusive access to its tree store.
- A Tokio runtime when opening a `Peer` and while its engine runs.
- A native target with an operating-system random source.
- For synchronization, network access and the remote's endpoint and signing identities.

## Examples

With `domhringr-record-tree` and Tokio's `rt` and `time` features as dependencies, this program opens a tree in a fresh state directory supplied as its first argument and verifies its note:

```rust
use domhringr_record_tree::{Identity, Peer, Receipt, StateDir, TreeId};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let tree: TreeId = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef".parse()?;
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let peer = Peer::open(&state, Identity::load_or_create(&state)?)?;
        peer.commit(tree, Receipt::open(tree)?).await?;
        peer.commit(tree, Receipt::note(tree, "hello".into())?).await?;
        let view = peer.view(tree).await?;
        assert_eq!(view.notes(), &[(view.owner(), "hello".into())]);
        Ok(())
    })
}
```

The example's tree id selects a sedimentree; it is not a commit digest. The [`domhringr-peer` binary](../surface-peer/README.md) uses hex for ids in its command-line interface.

Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-tree
```

## Receipts and views

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open` (the tree's root; its author owns the tree), `Grant { to }` (write authority delegated to a peer), or `Note { text }`. The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, second Open. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

## Networking

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; each side reports the network path iroh selected — direct, relayed, or not yet chosen.

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
