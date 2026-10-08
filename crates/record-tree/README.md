# domhringr-record-tree

The record plane's sedimentree: one tree per id, stored durably in a redb file, folded into a view, and synced with another peer over iroh, on [subduction](https://crates.io/crates/subduction_core) as published.

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open` (the tree's root; its author owns the tree), `Grant { to }` (write authority delegated to a peer), or `Note { text }`. The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, second Open. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; each side reports the network path iroh selected — direct, relayed, or not yet chosen.

The `domhringr-peer` binary (`crates/face-peer`) is the command-line face of this crate.

## Receipt codec

Pending the value plane: receipts will encode through its canonical value stream once that crate is available as a path dependency. Until then postcard (with serde's derive) stands in, confined to `Receipt::encode` and `Receipt::decode` and a private mirror of the receipt; no public type carries a serde or postcard trait, so the swap changes those two functions, the error sources they report, and the manifest, and nothing else.

## Dependency decisions

**Operation fences: `getrandom` 0.4, no features.** `getrandom::fill` draws the 16 fence bytes straight from the operating system's source; the crate is already in the graph through iroh, so it adds no crate to the build, and no feature is needed for the native targets this crate builds for.

- `rand`: a seeded generator and its traits where one read from the OS source suffices.
- `uuid` with `v4`: a crate and a UUID type for what is 16 opaque bytes.

Reversal: a high-risk advisory against `getrandom`, its departure from the dependency graph, or a fence source the value plane supplies.
