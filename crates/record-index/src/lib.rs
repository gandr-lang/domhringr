//! A project's derived index as one store of a keyed schema, and the
//! root-checkable proofs of what it holds.
//!
//! The receipt fold owns admission. A project's tasks, their attempts and
//! admitted moves, their refusals, and the evidence and revisions those
//! moves name are parts of one store of
//! `gandr_storage_schema::keyed::schema()` ([`keyed`]). An `Indexed`
//! receipt attests the store's root. Every question a reader asks is a
//! question of that schema, proved against that root ([`prove`],
//! [`stream`]).
//!
//! # Decisions
//!
//! | Choice | Alternative | Reversal condition |
//! | ------ | ----------- | ------------------ |
//! | Derive above the fold | Maintain indexes during receipt admission | Admission itself needs authenticated index queries |
//! | One store of the keyed schema, attested by its root | A record family per index kind, each with its own manifest and the project nesting the others | A question the schema's proofs can't answer, needing a family the schema doesn't state |
//! | The standing's kind as a tag; the rest recomputed from the last attempt | Store the whole standing beside the moves it is a projection of | The fold's standing gains a field no move kind carries |
//! | No tree attribute: a task is found by name, its moves by attempt | Store each task's tree | A reader needs a task's tree before any of its moves exists |
//! | A refresh edits the previous store; agreement is by contents | Rebuild every derive from empty so roots compare | Readers need a root that is a function of the project alone |
//! | Original receipt bytes in move values | Re-encode displayed moves | The receipt language supplies a canonical, lossless transformation with preserved identity |
//! | Replay through the arena monitor and share the fold's standing projection | Maintain another receipt automaton or trust the claimed standing | The monitor gains a resumable cursor, allowing replay without rebuilding channel prefixes |
//! | Content-addressed node files | A separate database table | Measured file overhead exceeds the cost of a transactional store |
//! | `quenchant-arith` at the storage sibling's pin, with defaults off | Primitive arithmetic loses the nominal boundary; local wrappers duplicate its checked and saturating families | The shared arithmetic contract changes or the dependency goes unmaintained |
//! | Dedicated proof protocol | Mix derived bytes into receipt sync or evidence transfer | Batching or subscription requires another protocol version |

// Module documentation that predates the shape lint: 1 heading outside the
// vocabulary and 1 decision record. Each allow leaves with the rewrite that
// clears its count.
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    allow(
        module_doc_heading,
        doc_decision_record,
        reason = "module documentation that predates the shape lint"
    )
)]
#![expect(
    clippy::multiple_crate_versions,
    reason = "iroh and subduction depend on different cryptographic crate majors"
)]
#![cfg_attr(
    dylint_lib = "quenchant_dylints",
    deny(option_signature, option_field, primitive_arithmetic)
)]
extern crate alloc;

#[cfg(test)]
mod testing;

pub mod check;
pub mod derive;
pub mod dialogue;
pub mod key;
pub mod keyed;
pub mod measure;
pub mod project;
pub mod prove;
pub mod provenance;
pub mod replay;
pub mod store;
pub mod stream;
mod wire;

pub use key::AttemptNumber;
pub use key::MoveKey;
pub use key::SequenceNumber;
pub use wire::WireError;
pub use wire::WireImage;
