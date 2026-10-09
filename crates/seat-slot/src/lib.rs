//! The seat: the Player participant of a task tree. An operator dispatches a
//! seat to a brief by a receipt in the task's tree; the seat holding the
//! dispatch's slot answers the operator's wake, acts on the brief through a
//! command surface, and reports the content by its hash with a one-line
//! summary, by a receipt in the same tree.
//!
//! The receipts and the rules that admit them are the record's
//! ([`domhringr_record_tree::Kind`], [`domhringr_record_tree::Task`]); this
//! crate is the exchange around them. [`wake`](fn@wake) is the operator's
//! side: link to the seat, name the dispatch on one stream under
//! [`PROTOCOL`], read the reply ([`Reply`]), and pull the task back.
//! [`serve`] is the seat's side: accept links and wakes, pull and fold the
//! task, reply, present itself in the task's book when it lacks a presence
//! there, act through its [`Surface`] and report, and resume on start what it
//! holds unreported; it tells what it did as [`Event`]s.

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
