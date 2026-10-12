//! The profile every evidence value is committed and read under: the typed
//! chunker's constants, measured over the corpus the crate's tests carry, and
//! the lines codec's identity.
//!
//! # The profile
//!
//! **The profile is the typed chunker at κ 64 with a token cap of 512, over
//! lines of at most 512 bytes, measured over the corpus the crate carries.**
//! The corpus under `tests/corpus` is 21 values, 203,337 bytes: the reports,
//! verifier outputs and judge transcripts the workspace's tests and the
//! operator loop produce, the smallest empty and the largest 81 KB. Each
//! candidate commits every value of the corpus into one store; the table counts
//! each value's chunks summed over the corpus, the distinct chunks stored,
//! their bytes, the distribution of a stored chunk's size in bytes, the chunks
//! the two change transcripts' closures hold and share, and the new chunks a
//! line appended to the test run's output produces:
//!
//! | κ | cap | chunks | distinct | stored bytes | p50 | p90 | max | mean | change transcripts | appended line |
//! | - | --- | ------ | -------- | ------------ | --- | --- | --- | ---- | ------------------ | ------------- |
//! | 16 | 128 | 285 | 165 | 162,851 | 703 | 2,048 | 6,572 | 986 | 111 and 115, 110 shared | 1 of 11 |
//! | 32 | 256 | 159 | 95 | 156,874 | 1,171 | 3,865 | 10,465 | 1,651 | 59 and 62, 58 shared | 1 of 6 |
//! | **64** | **512** | **79** | **51** | **155,318** | **1,597** | **8,137** | **17,974** | **3,045** | **27 and 27, 26 shared** | **1 of 3** |
//! | 128 | 1024 | 62 | 42 | 154,562 | 1,592 | 8,137 | 19,061 | 3,680 | 19 and 19, 18 shared | 1 of 3 |
//! | 256 | 2048 | 29 | 29 | 257,307 | 2,087 | 27,688 | 57,535 | 8,872 | 5 and 5, none shared | 1 of 1 |
//!
//! At the pinned pair the smallest chunk is 50 bytes and the tenth percentile
//! 279. A cap of 256 at κ 64 cuts 91 chunks, 58 distinct, and a cap of 1024
//! cuts as 512 does; lines of at most 256 bytes cut 88 chunks, 57 distinct, and
//! of 1024 or 4096 bytes 87, 55 distinct. κ 128 with a cap of 2048 shares
//! nothing between the change transcripts.
//!
//! κ 64 sits in the middle of the range: the store is within half a percent of
//! its smallest, the two change transcripts share 26 of their 27 chunks, an
//! appended line produces one new chunk, and a cap of 1024 cuts the corpus no
//! differently while 512 bounds the worst chunk at 256 lines of 512 bytes, 128
//! KiB of payload. The lines codec is identifier 1, version 1, with absolute
//! child indices. Two tests pin the measurement:
//! `corpus::tests::the_commitment_is_pinned` pins the chunker commitment byte
//! by byte, and `corpus::tests::the_cuts_of_the_corpus_are_pinned` pins each
//! value's chunk count and the size of every distinct chunk.
//!
//! - κ 32: nearly twice the files for the same bytes stored.
//! - κ 128: fewer chunks, but sharing that depends on the cap: at 2048 the
//!   change transcripts share nothing.
//!
//! Reversal: evidence whose cuts fall outside this distribution — values far
//! longer than the corpus's largest, or not shaped as lines — measured again. A
//! new pin is a migration: the manifest names its profile, and a read refuses a
//! value cut under another (`IncompatibleProfile`).

use core::num::NonZeroU64;

use gandr_storage_chunker::Kappa;
use gandr_storage_chunker::TokenCap;
use gandr_storage_chunker::TypedChunkerParams;
use gandr_storage_values::ChildIndexBase;
use gandr_storage_values::CodecId;
use gandr_storage_values::CodecIdentity;
use gandr_storage_values::CodecVersion;
use gandr_storage_values::ValueProfile;

/// The expected number of boundary events per content-defined cut: a line is
/// one event, so a chunk holds 64 lines on average.
const KAPPA: NonZeroU64 = NonZeroU64::MIN.saturating_add(63_u64);

/// The most tokens a chunk holds before the cap cuts it: eight times
/// [`KAPPA`], two tokens a line, so 256 lines.
const TOKEN_CAP: NonZeroU64 = NonZeroU64::MIN.saturating_add(511_u64);

/// The lines codec's identifier among this workspace's value-plane codecs.
const CODEC: u16 = 0x0001_u16;

/// The lines codec's layout version.
const CODEC_VERSION: u16 = 0x0001_u16;

/// The profile every evidence value is committed and read under.
///
/// # Specification
/// - ensures: kappa 64 and a token cap of 512 under the typed chunker, the
///   lines codec at identifier 1 and version 1, absolute child indices; the
///   same profile on every call and every peer, so a value one peer commits
///   reads under another's, and a value cut under other constants is refused.
/// - panics: none.
/// - executable: none — the function is its own specification; independent
///   commitment and corpus goldens fix the profile without repeating its
///   fields.
///
/// # Adequacy
/// - hypothesis: L2 agreement — the chunker commitment is pinned byte by byte,
///   and the cuts of the checked-in corpus under the profile are pinned as each
///   value's chunk count and the size of every distinct chunk.
/// - witness: `corpus::tests::the_commitment_is_pinned`
/// - witness: `corpus::tests::the_cuts_of_the_corpus_are_pinned`
#[inline]
#[must_use]
pub fn profile() -> ValueProfile
{
    ValueProfile::new(
        TypedChunkerParams::new(Kappa::from(KAPPA), TokenCap::from(TOKEN_CAP)),
        CodecIdentity::new(CodecId::from(CODEC), CodecVersion::from(CODEC_VERSION)),
        ChildIndexBase::Absolute,
    )
}
