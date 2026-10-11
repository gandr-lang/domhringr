//! Derived, attested ordered indexes and their root-checkable proofs.
//!
//! The receipt fold owns admission. Index manifests bind a kind, layout,
//! boundary rule, record count and node identity independently of storage.

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
