//! The judge: asks a model one question about a transcript, the question's
//! options lettered `A`, `B`, …, and reads the answer out of the model's
//! next-token distribution — the letter holding the most probability and a
//! probability per option — or records why it read none.
//!
//! A [`Question`] is its text and its options, named by the hash of its
//! canonical form; a [`Transcript`] is the content asked about, staged as
//! evidence and named by its value manifest. A [`Backend`] answers a question
//! about a transcript with a
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
//!
//! # The laws
//!
//! A judge classifies evidence and never adds to it. Refusal is outside the
//! laws: an endpoint that fails, a question the endpoint refuses, or an answer
//! that names no option is an operational outcome, recorded as an unread ruling
//! with its reason, never as a letter. Three laws bind what the judge records,
//! each witnessed by a test:
//!
//! - **Unit.** A verdict changes no attempt: the task stands where its seat
//!   receipts put it, with or without rulings. Witnesses:
//!   `fold::tests::a_judge_rules_on_the_current_dispatch` in
//!   `domhringr-record-tree`, and
//!   `judge::tests::a_judge_rules_on_a_transcript_and_replay_shows_the_verdict`
//!   in `domhringr-surface-peer`, where the task replays `dispatched` after the
//!   verdict.
//! - **Composition.** A verdict over several questions holds, in the order
//!   asked, the ruling each question gets when asked alone: a ruling depends on
//!   its question and its transcript alone. Witnesses:
//!   `backend::tests::a_table_answers_what_it_records`, and the peer's process
//!   test, where the verdict's first ruling is the one `judge ask` printed.
//! - **Property grade.** A verdict is a function of what it records. Replay
//!   reads the same rulings from the record on any day and against no endpoint,
//!   and `Static` answers a recorded ruling again. The verdict names the rubric
//!   by hash and the transcript by its manifest, and holds only the rulings, so
//!   it adds no evidence: the transcript it names is the one the judge read,
//!   kept in the evidence plane. Witnesses:
//!   `receipt::tests::every_kind_round_trips` and
//!   `ruling::tests::a_ruling_reads_back_from_its_text` in
//!   `domhringr-record-tree`, and
//!   `backend::tests::each_refusal_records_its_reason` for refusals.
//!
//! # References
//!
//! | Artifact | Use |
//! | -------- | --- |
//! | D. Ahman, A. Bauer, _Sheaves as oracle computations_, arXiv, February 2026, [arXiv:2602.22135](https://arxiv.org/abs/2602.22135) | The oracle reading: a judge answers a query and classifies evidence, and never contributes a witness. |
//! | OpenAI, _Chat Completions API reference_, [`POST /v1/chat/completions`](https://platform.openai.com/docs/api-reference/chat/create) | The request and its `logprobs` and `top_logprobs` fields: the next-token distribution at the answer's position. |
//! | vLLM, _OpenAI-Compatible Server_, [documentation](https://docs.vllm.ai/en/latest/serving/openai_compatible_server.html) | A local server of that API, reporting log-probabilities for chat requests. |
//! | `reqwest`, [crate documentation](https://docs.rs/reqwest) | The HTTP client. |
//! | `serde_json`, [crate documentation](https://docs.rs/serde_json) | The request and response bodies. |

// Module documentation that predates the shape lint: 5 headings outside the
// vocabulary, 6 decision records and 1 budget exceeded. Each allow leaves with
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
