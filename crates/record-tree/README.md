# domhringr-record-tree

The record plane's sedimentree: one tree per id, stored durably in a redb file and synced with another peer over iroh, on [subduction](https://crates.io/crates/subduction_core) as published.

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, and the tree store. A commit's id is the BLAKE3 digest of its bytes and its parents are the tree's heads when it is made. A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. A sync dials the remote, runs one batch round for one tree, and disconnects.

The `domhringr-peer` binary (`crates/face-peer`) is the command-line face of this crate.
