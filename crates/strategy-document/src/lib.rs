//! Playbooks and rubrics: the strategies a task is checked by, read from
//! TOML and run.
//!
//! A [`Playbook`] is a Player strategy written down: named [`Step`]s, each
//! saying why it is there and bound ([`Bound`]) to a [`Verifier`] — a
//! program run on the task's state, whose [`Run`] is its output and how it
//! ended — or to a question of a [`Rubric`]. A rubric is an Opponent
//! strategy: the state files it reads into a transcript ([`StateFile`]), the
//! [`Band`] its grades stand against, and named questions, each asked of a
//! judge as a choice between its criterion holding and failing. A ruling is
//! graded against the band ([`Band::grade`]) and a rubric's grades compose
//! as the conjunction of its criteria ([`domhringr_record_tree::compose`]):
//! unmet when any is unmet, otherwise refused when any is refused, otherwise
//! undecided when any is undecided, otherwise met.
//!
//! Both documents are read by hand from TOML's document tree, so a text that
//! is not the document is refused at the field it is about ([`Refusal`]:
//! its [`Field`] and its [`Reason`]). A document read from its file is named
//! by the hash of its bytes ([`Loaded`]); a playbook is read with each rubric
//! its steps name ([`Plan`]), whose questions it asks rubric by rubric
//! ([`Grading`]).
//!
//! The receipts a run commits are the record's
//! ([`domhringr_record_tree::Kind::Verified`] and
//! [`domhringr_record_tree::Kind::Graded`]), and the judge that answers a
//! question is the judge oracle's ([`domhringr_judge_oracle::Backend`]): this
//! crate reads, runs and grades, and a caller commits.
//!
//! # The rubric set
//!
//! The example rubric grades two questions about a checkout of this repository.
//! The rubric set under `rubrics/` grades a change to a repository of this
//! workspace's shape with seven rubrics: `stable-refs`,
//! `public-private-stance`, `issues`, `pull-requests`, `ci-shape`, `docs` and
//! `code`. Each reads the artifacts a task's record supplies, such as a diff,
//! its commit messages, an issue, a review, a workflow or a README, and each
//! has a fixture pair: one state that meets it and one that fails exactly one
//! of its questions. The peer binary's process tests grade every pair from a
//! table, and one pair by a real judge when the environment configures one.
//!
//! # Dependencies
//!
//! **`toml` 1.1 with the `parse` feature alone.** It reads a document into its
//! tree, and a text that is not TOML into an error with the span a refusal's
//! line and column come from; `serde`, `display` and the standard library
//! features stay off. It adds two crates to the lock, `toml` and
//! `serde_spanned`; its parser, `toml_parser` with `winnow`, and
//! `toml_datetime` are already in the graph. The five crates build in about
//! half a second from clean.
//!
//! - `toml_edit`: a format-preserving document model for files this crate never
//!   writes.
//! - `toml-span`: a second, smaller parser beside the `toml_parser` the graph
//!   already carries.
//!
//! Reversal: a document read on a hot path, where a parser without the span
//! bookkeeping wins.
//!
//! # References
//!
//! | Artifact | Use |
//! | -------- | --- |
//! | T. Preston-Werner, P. Gedam et al., _TOML v1.0.0_, [toml.io/en/v1.0.0](https://toml.io/en/v1.0.0) | The document language. |
//! | S. C. Kleene, _Introduction to Metamathematics_, North-Holland, 1952, ISBN 978-0-7204-2103-3, § 64 | The strong three-valued conjunction the grades compose by, with refusal placed between failure and indecision. |
//! | `toml`, [crate documentation](https://docs.rs/toml) | `de::DeTable::parse`: the document tree with each key's and value's span. |
//! | `domhringr-judge-oracle` | The question a rubric asks and the judge that answers it. |
//! | `domhringr-record-tree` | The `Verified` and `Graded` receipts, `StepId`, `Status`, `Grade` and the `Ruling` a grade reads. |
//! | `domhringr-record-evidence` | The evidence plane a transcript is staged in and a verifier's output is committed to. |

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

mod document;
mod load;
mod playbook;
mod rubric;
mod verify;

pub use document::Expected;
pub use document::Field;
pub use document::Name;
pub use document::Reason;
pub use document::Refusal;
pub use document::Syntax;
pub use load::Grading;
pub use load::LoadError;
pub use load::Loaded;
pub use load::Plan;
pub use playbook::Bound;
pub use playbook::ParseRubricFileError;
pub use playbook::Playbook;
pub use playbook::RubricFile;
pub use playbook::Step;
pub use rubric::Band;
pub use rubric::ParseStateFileError;
pub use rubric::Rubric;
pub use rubric::StateFile;
pub use rubric::TranscriptError;
pub use verify::Run;
pub use verify::Verifier;
pub use verify::VerifyError;
