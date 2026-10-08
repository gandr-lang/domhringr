//! The record plane's sedimentree: one tree per id, stored durably on disk
//! and synced with a peer over iroh.
//!
//! A peer is a state directory ([`StateDir`]) holding two ed25519 identities
//! ([`Identity`]) and a redb tree store ([`Peer`]). Content enters a tree as
//! a commit whose id is the BLAKE3 digest of its bytes and whose parents are
//! the tree's heads ([`Peer::commit`]). Binding the peer to an iroh endpoint
//! ([`Peer::bind`]) yields a [`Node`] reached by endpoint id alone, which
//! accepts connections ([`Node::accept`]) and dials other peers to sync a
//! tree ([`Node::sync`]).
//!
//! The substrate is subduction over iroh as published; this crate supplies
//! the Tokio spawner and timer subduction is generic over, the identity
//! files, and the shape of a sync: dial, one batch round, disconnect.

#![expect(
    clippy::multiple_crate_versions,
    reason = "iroh and subduction straddle the RustCrypto and ed25519-dalek major \
              transitions; the duplicates are theirs and no version this workspace \
              chooses unifies them"
)]
// The opt-in quenchant lints: absence named by `Maybe` in signatures and in
// fields outside wire form, arithmetic on nominal types. Selected here because
// Dylint's `-D` cannot reach rustc through `cargo dylint`; see
// `.config/mise/tasks/mise-tasks-check.toml`.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]

extern crate alloc;

mod id;
mod identity;
mod node;
mod runtime;
mod store;

pub use id::EndpointKey;
pub use id::ParseIdError;
pub use id::PeerKey;
pub use id::RemotePeer;
pub use id::TreeId;
pub use identity::Identity;
pub use identity::IdentityError;
pub use identity::StateDir;
pub use node::AcceptError;
pub use node::BindError;
pub use node::Node;
pub use node::SyncError;
pub use store::CommitError;
pub use store::Content;
pub use store::Heads;
pub use store::HeadsError;
pub use store::OpenError;
pub use store::Peer;
