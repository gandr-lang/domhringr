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
//! admitted notes, the paths bound, the DNS names claimed, the trees
//! introduced, the book of who is reachable at which endpoint, the tree read
//! as a [`Task`], the commits admitted, and the commits refused with their
//! [`Refusal`]. A receipt is admitted only from an author with authority in
//! its causal past, a claim only from the owner, and a presence only of the
//! author's own endpoint.
//!
//! A tree is also a task: an operator — the owner or a member — dispatches a
//! seat to a [`Brief`], and the seat holding the dispatch's slot reports on
//! it — the content's BLAKE3 hash ([`ContentHash`]) and a one-line
//! [`Summary`] — hands the slot to another seat, or retires from it. Each is
//! a receipt ([`Kind::Dispatch`], [`Kind::Report`], [`Kind::Handoff`],
//! [`Kind::Retire`]) admitted only from the holder of the latest dispatch's
//! slot in its causal past, and the fold reads the admitted ones in canonical
//! order into the task's [`Step`]s and its [`Current`] attempt: who holds the
//! slot ([`Slot`]) and whether it is reported on ([`Answer`]).
//!
//! The work is checked on the task's record. A judge rules on a dispatch
//! ([`Kind::Verdict`]): each question's [`Ruling`], a [`Readout`] of the
//! probability on each option or the reason none was read ([`Unread`]). A
//! runner records a playbook step's verifier run on a dispatch
//! ([`Kind::Verified`]): the step's identifier ([`StepId`]), the hash of the
//! process's output and how it ended ([`Status`]). The judge of a verdict
//! grades it ([`Kind::Graded`]): a [`Grade`] per answer and the grades
//! composed. Each moves no slot and answers no attempt, and the fold admits
//! each only from the key it names — the judge, the runner, the verdict's
//! judge — while its dispatch is current.
//!
//! The operator closes the loop on the record too. A decision on the current
//! dispatch ([`Kind::Decide`]) names its operator and lands the change,
//! reworks it for a reason, or abandons the task ([`Decision`]); a landing
//! ([`Kind::Landed`]) carries out a decision to land and names the
//! repository's [`Revision`] the change landed at. The fold admits a decision
//! only from the operator it names, holding the operator role — the owner or
//! a member — and a landing only from its decision's operator. The attempt's
//! [`Progress`] is the furthest of its checks, decision and landing the fold
//! has admitted: verified, graded, decided, landed.
//!
//! A tree, the paths in it and its commits are named by [`Anchor`]s,
//! `domhringr://<authority>/<path>` and `domhringr://<authority>/.commit/<id>`,
//! whose [`Authority`] is the tree's key, a DNS name ([`Domain`]) or a label
//! ([`Label`]). A segment beginning with `.` is reserved for the forms the
//! scheme names, so no path holds one. An anchor names a commit by its whole
//! id; a [`Reference`], what a reader types, may abbreviate it to a unique
//! prefix of at least eight hex digits ([`CommitPrefix`]). [`Peer::whence`]
//! resolves a reference by fold ([`Resolution`]): a path to the [`Target`] it
//! is bound to, or to unbound; a commit to the fold's [`Verdict`] on it, or to
//! unknown. A DNS name resolves through a [`Witness`] — the DNS records
//! ([`Dns`]) or a map supplied by hand ([`Static`]) — together with the
//! owner's claim in the witnessed tree, and a label through the introductions
//! of the tree it is read in ([`Scope`]).
//!
//! Binding the peer to an iroh endpoint ([`Peer::bind`]) yields a [`Node`]
//! reached by endpoint id, which accepts connections ([`Node::accept`]),
//! presents its endpoint in a tree ([`Node::present`]: a [`Presence`] in the
//! tree's book, proved by the endpoint key for the peer's key
//! ([`EndpointProof`])), and dials other peers to sync a tree
//! ([`Node::sync`]) at an [`Endpoint`] — its id and any addresses
//! ([`Address`]) — each reporting the network path iroh selected
//! ([`SelectedPath`]). [`Peer::route`] names the remote a dial for a tree
//! reaches ([`Route`]): the peer aimed at ([`Aim`]), at an endpoint named by
//! hand or at its presence in the book ([`At`]); [`Peer::reads`] names the
//! trees a resolution reads, so a caller syncs them before resolving.
//!
//! The substrate is subduction over iroh as published, and the value plane
//! for the receipt's canonical form; this crate supplies the Tokio spawner and
//! timer subduction is generic over, the key files, the receipt grammar, the
//! fold, the anchor form, the witnesses, and the shape of a sync: dial, one
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

mod anchor;
mod check;
mod decision;
mod fold;
mod id;
mod identity;
mod line;
mod name;
mod node;
mod presence;
mod receipt;
mod ruling;
mod runtime;
mod store;
mod task;
#[cfg(test)]
mod testing;
mod witness;

pub use anchor::Anchor;
pub use anchor::Authority;
pub use anchor::ParseAnchorError;
pub use anchor::Path;
pub use anchor::Reference;
pub use anchor::Resolution;
pub use anchor::Scope;
pub use anchor::Target;
pub use check::Code;
pub use check::Grade;
pub use check::ParseStepIdError;
pub use check::Signal;
pub use check::Status;
pub use check::StepId;
pub use decision::Decision;
pub use decision::ParseRevisionError;
pub use decision::Revision;
pub use fold::Refusal;
pub use fold::Unopened;
pub use fold::Verdict;
pub use fold::View;
pub use id::Address;
pub use id::CommitPrefix;
pub use id::Content;
pub use id::ContentHash;
pub use id::Endpoint;
pub use id::EndpointKey;
pub use id::ParseIdError;
pub use id::PeerKey;
pub use id::RemotePeer;
pub use id::TreeId;
pub use identity::Identity;
pub use identity::IdentityError;
pub use identity::StateDir;
pub use identity::TreeKey;
pub use name::Domain;
pub use name::Label;
pub use name::ParseDomainError;
pub use name::ParseLabelError;
pub use node::AcceptError;
pub use node::Accepted;
pub use node::BindError;
pub use node::BindPort;
pub use node::DialError;
pub use node::Incoming;
pub use node::Node;
pub use node::ParsePortError;
pub use node::PresentError;
pub use node::Protocol;
pub use node::SelectedPath;
pub use node::SyncError;
pub use node::Synced;
pub use node::UdpPort;
pub use presence::Aim;
pub use presence::At;
pub use presence::Presence;
pub use presence::Route;
pub use receipt::EndpointProof;
pub use receipt::Kind;
pub use receipt::OpenProof;
pub use receipt::Operation;
pub use receipt::RandomError;
pub use receipt::Receipt;
pub use ruling::Letter;
pub use ruling::NotProbability;
pub use ruling::ParseLetterError;
pub use ruling::ParseProbabilityError;
pub use ruling::ParseRulingError;
pub use ruling::Probability;
pub use ruling::Readout;
pub use ruling::ReadoutError;
pub use ruling::Ruling;
pub use ruling::Unread;
pub use sedimentree_core::loose_commit::id::CommitId;
pub use store::CommitError;
pub use store::Heads;
pub use store::HeadsError;
pub use store::OpenError;
pub use store::Peer;
pub use store::RouteError;
pub use store::TreesError;
pub use store::ViewError;
pub use store::WhenceError;
pub use task::Answer;
pub use task::Attempt;
pub use task::Brief;
pub use task::Current;
pub use task::ParseSummaryError;
pub use task::Progress;
pub use task::Slot;
pub use task::Step;
pub use task::Summary;
pub use task::Task;
pub use witness::Dns;
pub use witness::Static;
pub use witness::Witness;
pub use witness::WitnessError;
