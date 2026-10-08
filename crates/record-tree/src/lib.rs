//! The record plane's sedimentree: one tree per id, stored durably on disk,
//! folded into a view, and synced with a peer over iroh.
//!
//! A peer is a state directory ([`StateDir`]) holding two ed25519 identities
//! ([`Identity`]), the keys of the trees it opened ([`TreeKey`]), and a redb
//! tree store ([`Peer`]). A tree's id is its own key's verifying key
//! ([`TreeId`]), so the id certifies itself: the tree's Open carries the
//! tree key's proof naming its owner, and the fold refuses an Open whose
//! proof fails. A commit carries a [`Receipt`] — the tree it belongs to, an
//! operation fence, and the transition it records ([`Kind`]) — whose blob is
//! the receipt's flat form in the value plane ([`gandr_storage_values`]); its
//! id is the BLAKE3 digest of that blob, its parents are the tree's heads,
//! and its author is its verified signer ([`Peer::commit`]). Every peer
//! holding the same commits folds them into the same [`View`]
//! ([`Peer::view`]): the tree's owner, the peers granted write authority, the
//! admitted notes, the paths bound, and the commits refused with their
//! [`Refusal`]. A receipt is admitted only from an author with authority in
//! its causal past.
//!
//! A tree and the paths in it are named by [`Anchor`]s,
//! `domhringr://<tree>/<path>`; [`Peer::whence`] resolves one by fold to the
//! [`Target`] its path is bound to, or to unbound ([`Resolution`]).
//!
//! Binding the peer to an iroh endpoint ([`Peer::bind`]) yields a [`Node`]
//! reached by endpoint id, which accepts connections ([`Node::accept`]) and
//! dials other peers to sync a tree ([`Node::sync`]) — by endpoint id alone or
//! at a direct address ([`Address`]) — each reporting the network path iroh
//! selected ([`SelectedPath`]).
//!
//! The substrate is subduction over iroh as published, and the value plane
//! for the receipt's canonical form; this crate supplies the Tokio spawner and
//! timer subduction is generic over, the key files, the receipt grammar, the
//! fold, the anchor form, and the shape of a sync: dial, one batch round,
//! disconnect.

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

mod anchor;
mod fold;
mod id;
mod identity;
mod line;
mod node;
mod receipt;
mod runtime;
mod store;
#[cfg(test)]
mod testing;

pub use anchor::Anchor;
pub use anchor::ParseAnchorError;
pub use anchor::Path;
pub use anchor::Resolution;
pub use anchor::Target;
pub use fold::Refusal;
pub use fold::Unopened;
pub use fold::View;
pub use id::Address;
pub use id::CommitHex;
pub use id::EndpointKey;
pub use id::ParseIdError;
pub use id::PeerKey;
pub use id::RemotePeer;
pub use id::TreeId;
pub use identity::Identity;
pub use identity::IdentityError;
pub use identity::StateDir;
pub use identity::TreeKey;
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
pub use receipt::Kind;
pub use receipt::OpenProof;
pub use receipt::Operation;
pub use receipt::RandomError;
pub use receipt::Receipt;
pub use store::CommitError;
pub use store::Heads;
pub use store::HeadsError;
pub use store::OpenError;
pub use store::Peer;
pub use store::ViewError;
