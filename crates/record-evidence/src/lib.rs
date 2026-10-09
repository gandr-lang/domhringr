//! Evidence in the value plane: the bytes a report, a verifier's run and a
//! judge's transcript hold, committed as chunk DAGs under one pinned profile
//! and named by their manifest's identity.
//!
//! A receipt names its evidence by a [`gandr_storage_values::ManifestDigest`];
//! this crate holds the bytes the name stands for. [`Staged`] commits a content
//! in memory under [`profile()`] through the lines codec; [`Evidence`] keeps it
//! beside the peer's tree store and reads it back only through the manifest's
//! profile check and its complete closure, refusing by name. [`fetch()`] asks a
//! peer holding a value for it on one stream under [`PROTOCOL`], and [`answer`]
//! is the holder's side; the reader verifies every chunk and walks the whole
//! closure before it keeps the value or returns a byte.

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

mod fetch;
mod lines;
mod profile;
mod store;

pub use fetch::FetchError;
pub use fetch::PROTOCOL;
pub use fetch::ParseDigestError;
pub use fetch::ParsedDigest;
pub use fetch::ServeError;
pub use fetch::Served;
pub use fetch::answer;
pub use fetch::fetch;
pub use profile::profile;
pub use store::Evidence;
pub use store::EvidenceError;
pub use store::Staged;
pub use store::StoreAction;
