//! The judge: asks a model one question about a transcript, the question's
//! options lettered `A`, `B`, …, and reads the answer out of the model's
//! next-token distribution — the letter holding the most probability and a
//! probability per option — or records why it read none.
//!
//! A [`Question`] is its text and its options, named by the hash of its
//! canonical form; a [`Transcript`] is the content asked about, held or named
//! by its hash. A [`Backend`] answers a question about a transcript with a
//! [`Readout`](domhringr_record_tree::Readout) or a [`Refusal`], whose
//! [`Refusal::reason`] is what a verdict records
//! ([`Unread`](domhringr_record_tree::Unread)): never a default letter.
//! [`ChatCompletions`] asks an OpenAI-compatible endpoint for one token with
//! its top log-probabilities, configured from the environment ([`Config`]);
//! [`Static`] answers from a table, for tests and for replaying a recorded
//! ruling.
//!
//! The verdict that carries a judge's rulings is the record's
//! ([`domhringr_record_tree::Kind::Verdict`]): this crate reads the rulings,
//! and a caller commits them.

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

mod backend;
mod chat;
mod question;
mod readout;

pub use backend::Backend;
pub use backend::EndpointError;
pub use backend::MalformedError;
pub use backend::ParseTableError;
pub use backend::Refusal;
pub use backend::Static;
pub use chat::ChatCompletions;
pub use chat::Config;
pub use chat::ConfigError;
pub use chat::Variable;
pub use question::Question;
pub use question::QuestionError;
pub use question::TextError;
pub use question::Transcript;
pub use readout::Ceiling;
