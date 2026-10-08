# domhringr-record-tree

The record plane's sedimentree: one tree per id, stored durably in a redb file, folded into a view, and synced with another peer over iroh, on [subduction](https://crates.io/crates/subduction_core) as published.

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open` (the tree's root; its author owns the tree), `Grant { to }` (write authority delegated to a peer), or `Note { text }`. The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, second Open. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; each side reports the network path iroh selected — direct, relayed, or not yet chosen.

The `domhringr-peer` binary (`crates/face-peer`) is the command-line face of this crate.

## Codec decision

**Receipts: the value plane's flat form, `gandr-storage-values` at the pinned sibling revision.** `Receipt` implements the value plane's `CanonicalValue`: it walks itself into the canonical token records (the grammar heads `src/receipt.rs`), and a commit's blob is the flat form `encode_flat` writes, read back by `decode_flat`. The flat form was chosen so a receipt stored today commits through the value plane's chunk DAG later without re-encoding: it is the token stream `cam_commit` cuts, and for a receipt that fits one chunk it is exactly the body that chunk frames. The decoder admits exactly what the encoder writes, so a receipt has one blob and one commit id.

Two identities name a receipt and neither stands in for the other. The `CommitId` is sedimentree's: the BLAKE3 digest of the blob, the flat bytes alone. A value-plane `ContentPtr` names the framed chunk: BLAKE3 over the chunk image, the plane's domain and frame header included. A commit is found by its `CommitId`; a `ContentPtr` arrives when the receipt is committed into the value plane.

- postcard over a serde mirror of the receipt: the stand-in this replaces; a compact wire format, but bytes the value plane would re-encode, and a second canonical form beside the plane's.
- sedimentree's `codec`: the format of its signed payloads (schema header, issuer key, fields, signature) with big-endian integers; it already seals the commit that carries the blob, and as a receipt form it would be a second canonical form in another byte order.
- a hand-rolled fixed layout: one more canonical form to keep in step with the value plane's.

Reversal: the value plane changing its token grammar or flat form incompatibly, at which point the receipt version word moves with it; or receipts leaving the record plane for the value plane's store, where the blob becomes a `ContentPtr` and the commit id stops being the receipt's digest.

## Dependency decisions

**Operation fences: `getrandom` 0.4, no features.** `getrandom::fill` draws the 16 fence bytes straight from the operating system's source; the crate is already in the graph through iroh, so it adds no crate to the build, and no feature is needed for the native targets this crate builds for.

- `rand`: a seeded generator and its traits where one read from the OS source suffices.
- `uuid` with `v4`: a crate and a UUID type for what is 16 opaque bytes.

Reversal: a high-risk advisory against `getrandom`, its departure from the dependency graph, or a fence source the value plane supplies.
