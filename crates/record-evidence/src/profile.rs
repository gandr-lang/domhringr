//! The profile every evidence value is committed and read under: the typed
//! chunker's constants, measured over the corpus the crate's tests carry, and
//! the lines codec's identity.

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
