//! The record plane's sedimentree: one tree per id, stored durably on disk,
//! folded into a view, and synced with a peer over iroh.
//!
//! A peer is a state directory ([`StateDir`]) holding two ed25519 identities
//! ([`Identity`]) and a redb tree store ([`Peer`]). A commit carries a
//! [`Receipt`] — the tree it belongs to, an operation fence, and the
//! transition it records ([`Kind`]) — encoded as its blob; its id is the
//! BLAKE3 digest of that blob, its parents are the tree's heads, and its
//! author is its verified signer ([`Peer::commit`]). Every peer holding the
//! same commits folds them into the same [`View`] ([`Peer::view`]): the
//! tree's owner, the peers granted write authority, the admitted notes, and
//! the commits refused with their [`Refusal`]. A receipt is admitted only
//! from an author with authority in its causal past.
//!
//! Binding the peer to an iroh endpoint ([`Peer::bind`]) yields a [`Node`]
//! reached by endpoint id alone, which accepts connections ([`Node::accept`])
//! and dials other peers to sync a tree ([`Node::sync`]), each reporting the
//! network path iroh selected ([`SelectedPath`]).
//!
//! The substrate is subduction over iroh as published; this crate supplies
//! the Tokio spawner and timer subduction is generic over, the identity
//! files, the receipt codec, the fold, and the shape of a sync: dial, one
//! batch round, disconnect.

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

mod fold;
mod id;
mod identity;
mod node;
mod receipt;
mod runtime;
mod store;
#[cfg(test)]
mod testing;

pub use fold::Refusal;
pub use fold::Unopened;
pub use fold::View;
pub use id::EndpointKey;
pub use id::ParseIdError;
pub use id::PeerKey;
pub use id::RemotePeer;
pub use id::TreeId;
pub use identity::Identity;
pub use identity::IdentityError;
pub use identity::StateDir;
pub use node::AcceptError;
pub use node::Accepted;
pub use node::BindError;
pub use node::BindPort;
pub use node::Node;
pub use node::ParsePortError;
pub use node::SelectedPath;
pub use node::SyncError;
pub use node::Synced;
pub use node::UdpPort;
pub use receipt::BodyError;
pub use receipt::DecodeError;
pub use receipt::EncodeError;
pub use receipt::Kind;
pub use receipt::Operation;
pub use receipt::RandomError;
pub use receipt::Receipt;
pub use store::CommitError;
pub use store::Heads;
pub use store::HeadsError;
pub use store::OpenError;
pub use store::Peer;
pub use store::ViewError;
