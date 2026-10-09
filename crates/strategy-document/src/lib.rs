//! Playbooks and rubrics: the strategies a task is checked by, read from
//! TOML and run.
//!
//! A [`Playbook`] is a Player strategy written down: named [`Step`]s, each
//! saying why it is there and bound ([`Bound`]) to a [`Verifier`] — a
//! program run on the task's state, whose [`Run`] is its output's hash and
//! how it ended — or to a question of a [`Rubric`]. A rubric is an Opponent
//! strategy: the state files it reads into a transcript ([`StateFile`]), the
//! [`Band`] its grades stand against, and named questions, each asked of a
//! judge as a choice between its criterion holding and failing. A ruling is
//! graded against the band ([`Band::grade`]) and a rubric's grades compose
//! as the conjunction of its criteria ([`compose`]): unmet when any is
//! unmet, otherwise refused when any is refused, otherwise undecided when any
//! is undecided, otherwise met — a refused question is never read as met.
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
pub use rubric::StateError;
pub use rubric::StateFile;
pub use rubric::compose;
pub use verify::Run;
pub use verify::Verifier;
pub use verify::VerifyError;
