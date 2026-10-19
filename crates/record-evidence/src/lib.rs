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
//!
//! # The plane and its identity
//!
//! **Evidence lives in gandr's value plane and is named by its manifest's
//! digest.** A report's content, a verifier's output and a judge's transcript
//! are values: committed as chunk DAGs, held beside the tree store, and named
//! in the receipt by `ManifestDigest`, the BLAKE3 digest of a manifest that
//! binds the root, the length and the profile the value was cut under. One name
//! carries everything a reader needs to check the bytes, and two values sharing
//! content share the chunks it was cut into. The value plane is the identity
//! and the chunk form; how a value moves between peers is the `fetch` module's,
//! and nothing in the name depends on it.
//!
//! - the BLAKE3 hash of the flat bytes: names the bytes but nothing a reader
//!   can fetch or check in parts, and two values sharing a prefix share
//!   nothing.
//! - the hash a blob transport names a value by: a second identity beside the
//!   plane's for every value, chosen by the transport.
//! - the bytes in the tree store: receipts and values in one store, and a sync
//!   carrying what only a reader of the value needs.
//!
//! Reversal: a change to the value plane's manifest identity, which needs a new
//! receipt version naming the new one.
//!
//! **This crate is a layer of its own above the record tree.**
//! `domhringr-record-tree` names a digest and never dereferences it; the codec,
//! the profile, the store and the fetch live here. The fold stays free of value
//! I/O, and a consumer of receipts alone does not build the chunker.
//!
//! - a module of `domhringr-record-tree`: every reader of receipts would build
//!   the chunker, the store and the fetch.
//!
//! Reversal: a fold that checks evidence — refusing a report whose content it
//! cannot read — which needs the store in the fold.
//!
//! # Dependencies
//!
//! **`gandr-storage-chunker` is a direct dependency for the profile's
//! parameters.** `TypedChunkerParams`, `Kappa` and `TokenCap` name the pinned
//! pair; the crate is already built through `gandr-storage-values`, so it adds
//! nothing to the build.
//!
//! **`tempfile` writes each file beside its name and renames it into place.** A
//! file is synced before the rename, so a name in the store always holds a
//! whole image; the crate is already in the workspace for the binaries' scratch
//! directories.
//!
//! **`data-encoding` reads and writes a digest's hex.** A request line and a
//! command line carry a digest as 64 lowercase hex digits, decoded into a fixed
//! buffer; the crate already reads the record tree's ids.
//!
//! # References
//!
//! | Artifact | Use |
//! | -------- | --- |
//! | J. O'Connor, J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn, _BLAKE3: one function, fast everywhere_, specification, January 2020, [BLAKE3-specs](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) | The hash a chunk image and a manifest are named by. |
//! | S. Friedl, A. Popov, A. Langley, E. Stephan, _Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension_, IETF RFC 7301, July 2014, [doi:10.17487/RFC7301](https://doi.org/10.17487/RFC7301) | The protocol name a fetch's connection carries, by which a node routes it apart from sync and wakes. |
//! | `gandr-storage-values`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-values) | `cam_commit`, the value manifest and its digest, the value profile and its check, the closure walk and the refusals a read names. |
//! | `gandr-storage-chunker`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-chunker) | The typed chunker's parameters: κ and the token cap. |
//! | `iroh`, [crate documentation](https://docs.rs/iroh) | The QUIC connection and the bidirectional stream a fetch runs on. |
//! | `iroh-blobs`, [crate documentation](https://docs.rs/iroh-blobs) | The transport alternative (the `fetch` module). |

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
#![cfg_attr(
    all(test, dylint_lib = "quenchant_dylints"),
    expect(
        count_against_constant,
        reason = "1 cost-shape site in test modules; #35 lists it"
    )
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
