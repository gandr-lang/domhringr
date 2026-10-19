//! The seat: the Player participant of a task tree. An operator dispatches a
//! seat to a brief by a receipt in the task's tree; the seat holding the
//! dispatch's slot answers the operator's wake, acts on the brief through a
//! command surface, keeps the content as evidence and reports it by its value
//! manifest with a one-line summary, by a receipt in the same tree.
//!
//! The receipts and the rules that admit them are the record's
//! ([`domhringr_record_tree::Kind`], [`domhringr_record_tree::Task`]), and
//! the evidence plane is `domhringr_record_evidence`'s; this crate is the
//! exchange around them. [`wake`](fn@wake) is the operator's side: link to
//! the seat, name the dispatch on one stream under [`PROTOCOL`], read the
//! reply ([`Reply`]), and pull the task back. [`serve`] is the seat's side:
//! accept links and wakes, pull and fold the task, reply, present itself in
//! the task's book when it lacks a presence there, act through its
//! [`Surface`] and report, answer fetches of the evidence it keeps, and
//! resume on start what it holds unreported; it tells what it did as
//! [`Event`]s.
//!
//! # Dependencies
//!
//! **Tokio's `sync` feature carries the event channel and the set of dispatches
//! being acted on.** The feature is already in the graph through iroh and
//! subduction, so it adds nothing to the build. The set sits behind
//! `tokio::sync::Mutex`, whose lock does not poison.
//!
//! - `std::sync::Mutex`: poisoning makes every lock a `Result` the seat has no
//!   use for, and the lock is held across no await either way.
//!
//! Reversal: a single-threaded seat, which needs no lock.
//!
//! **`iroh` is a direct dependency for the connection the wake runs on.**
//! `Node::accept` hands over an `iroh::endpoint::Connection`, and the seat
//! opens and reads its streams. iroh is the transport the record plane already
//! binds.
//!
//! # References
//!
//! | Artifact | Use |
//! | -------- | --- |
//! | S. Friedl, A. Popov, A. Langley, E. Stephan, _Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension_, IETF RFC 7301, July 2014, [doi:10.17487/RFC7301](https://doi.org/10.17487/RFC7301) | The protocol name a connection carries, by which the node routes the wake apart from subduction's sync. |
//! | `iroh`, [crate documentation](https://docs.rs/iroh) | QUIC connections and their bidirectional streams. |
//! | `tokio`, [crate documentation](https://docs.rs/tokio) | Tasks, the event channel, blocking threads for the program, and the reply deadline. |
//! | `domhringr-record-evidence` | The evidence store a report's output is kept in, and the fetch a seat answers. |
//! | `domhringr-record-index` | Derived-index nodes and authenticated key and range answers. |

// Module documentation that predates the shape lint: 4 headings outside the
// vocabulary, 9 decision records and 2 budgets exceeded. Each allow leaves with
// the rewrite that clears its count.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    allow(
        module_doc_heading,
        doc_decision_record,
        module_doc_budget,
        reason = "module documentation that predates the shape lint"
    )
)]
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

mod seat;
mod wake;

pub use seat::ActError;
pub use seat::AnswerError;
pub use seat::Declined;
pub use seat::Event;
pub use seat::ResumeError;
pub use seat::Surface;
pub use seat::serve;
pub use wake::Decline;
pub use wake::PROTOCOL;
pub use wake::ParseReplyError;
pub use wake::ParseWakeError;
pub use wake::Reply;
pub use wake::Wake;
pub use wake::WakeError;
pub use wake::wake;
