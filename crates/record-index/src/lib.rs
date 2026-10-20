//! Derived, attested ordered indexes and their root-checkable proofs.
//!
//! The receipt fold owns admission. Index manifests bind a kind, layout,
//! boundary rule, record count and node identity independently of storage.
//!
//! The record-tree API and proof language come from `gandr-storage-records`.
//! Verification uses its membership, non-membership and range proofs against
//! the resealed root alone.
//!
//! # Decisions
//!
//! | Choice | Alternative | Reversal condition |
//! | ------ | ----------- | ------------------ |
//! | Derive above the fold | Maintain indexes during receipt admission | Admission itself needs authenticated index queries |
//! | Kind-bound manifest images | Use a record root or a value manifest as the index name | Record-root metadata changes, requiring a new manifest layout |
//! | Original receipt bytes in move values | Re-encode displayed moves | The receipt language supplies a canonical, lossless transformation with preserved identity |
//! | Replay through the arena monitor and share the fold's standing projection | Maintain another receipt automaton or trust the claimed standing | The monitor gains a resumable cursor, allowing replay without rebuilding channel prefixes |
//! | Content-addressed node files | A separate database table | Measured file overhead exceeds the cost of a transactional store |
//! | `quenchant-arith` at the storage sibling's pin, with defaults off | Primitive arithmetic loses the nominal boundary; local wrappers duplicate its checked and saturating families | The shared arithmetic contract changes or the dependency is no longer maintained |
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
pub mod manifest;
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
pub use manifest::IndexKind;
pub use manifest::Manifest;
pub use manifest::ManifestError;
pub use wire::WireError;
pub use wire::WireImage;

/// A manifest paired with the exact record tree it names.
#[derive(Debug)]
pub struct Index
{
    /// The kind-bound identity envelope.
    pub manifest: Manifest,
    /// The canonical tree retained for proof construction.
    pub tree: gandr_storage_records::RecordTree,
}

impl Index
{
    /// Bind the tree under its index language.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn new(
        kind: IndexKind,
        tree: gandr_storage_records::RecordTree,
    ) -> Self
    {
        Self {
            manifest: Manifest::new(kind, &tree),
            tree,
        }
    }
}
