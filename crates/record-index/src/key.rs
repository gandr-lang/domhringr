//! Fixed-width, big-endian dialogue coordinates.

use anodized::spec;
use gandr_storage_records::OwnedKeyBound;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::OwnedRecordKey;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

/// A one-based attempt number at one manifest; zero is an absent probe.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct AttemptNumber(pub u32);

/// A zero-based position within one attempt.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct SequenceNumber(pub u32);

impl core::fmt::Display for AttemptNumber
{
    /// Write the attempt coordinate.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
    ) -> core::fmt::Result
    {
        self.0.fmt(f)
    }
}

impl core::fmt::Display for SequenceNumber
{
    /// Write the sequence coordinate.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
    ) -> core::fmt::Result
    {
        self.0.fmt(f)
    }
}

/// An eight-byte ordered coordinate, scoped to a dialogue manifest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct MoveKey([u8; 8]);

/// A coordinate cannot be represented or parsed.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError
{
    /// The coordinate is not exactly eight bytes.
    #[error("a move key is eight bytes")]
    Width,
    /// The next attempt or sequence would exceed 32 bits.
    #[error("dialogue coordinate exceeds u32")]
    Overflow,
}

impl MoveKey
{
    /// Encode attempt then sequence in numeric byte order.
    ///
    /// # Specification
    /// - ensures: decoding the key returns exactly the two coordinates.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — crossings at 255 and 65535 distinguish endianness and
    ///   the precedence of the attempt field.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[spec(ensures: |ret| ret.coordinates() == (attempt, seq))]
    #[inline]
    #[must_use]
    #[expect(
        clippy::big_endian_bytes,
        reason = "ordered record keys require big-endian coordinates so byte order equals numeric order"
    )]
    pub fn new(
        attempt: AttemptNumber,
        seq: SequenceNumber,
    ) -> Self
    {
        let [attempt0, attempt1, attempt2, attempt3] = attempt.0.to_be_bytes();
        let [seq0, seq1, seq2, seq3] = seq.0.to_be_bytes();
        Self([
            attempt0, attempt1, attempt2, attempt3, seq0, seq1, seq2, seq3,
        ])
    }

    /// Decode the fixed-width fields.
    ///
    /// # Specification
    /// - ensures: both fields are read in big-endian order.
    /// - panics: none.
    /// - executable: none — the const decoder is its own specification;
    ///   asymmetric coordinates and numeric ordering are the oracle.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — asymmetric coordinates distinguish field swapping.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[inline]
    #[must_use]
    #[expect(
        clippy::big_endian_bytes,
        reason = "decode the specified big-endian ordered key, not the value language"
    )]
    pub const fn coordinates(self) -> (AttemptNumber, SequenceNumber)
    {
        let [
            attempt0,
            attempt1,
            attempt2,
            attempt3,
            seq0,
            seq1,
            seq2,
            seq3,
        ] = self.0;
        (
            AttemptNumber(u32::from_be_bytes([attempt0, attempt1, attempt2, attempt3])),
            SequenceNumber(u32::from_be_bytes([seq0, seq1, seq2, seq3])),
        )
    }

    /// Own the record key at a storage boundary.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn owned(self) -> OwnedRecordKey
    {
        OwnedRecordKey::from(Box::<[u8]>::from(self.0))
    }
}

impl AsRef<[u8]> for MoveKey
{
    /// Borrow the encoded coordinate.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &[u8]
    {
        &self.0
    }
}

impl TryFrom<&[u8]> for MoveKey
{
    type Error = KeyError;

    /// Read exactly one coordinate.
    ///
    /// # Specification
    /// - ensures: preserves all eight input bytes.
    /// - fails: a different width is refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`KeyError::Width`]: input is not eight bytes.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — round trips and short/long probes distinguish width.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[spec(ensures: |ret| ret.is_ok() == (bytes.len() == 8))]
    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error>
    {
        let bytes = <[u8; 8]>::try_from(bytes).map_err(|_width| KeyError::Width)?;
        Ok(Self(bytes))
    }
}

impl AttemptNumber
{
    /// Name the next attempt without wrapping.
    ///
    /// # Specification
    /// - ensures: returns the successor iff it fits in 32 bits.
    /// - fails: overflow is explicit.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`KeyError::Overflow`]: this is the largest attempt number.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — maximum and ordinary successors separate overflow.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[spec(ensures: |ret| ret.as_ref().map_or(self.0 == u32::MAX, |next| arith::checked_sub(Int::from(next.0), Int::from(self.0)).map(u32::from) == Ok(1)))]
    #[inline]
    pub fn next(self) -> Result<Self, KeyError>
    {
        let next = arith::checked_add(Int::from(self.0), Int::from(1))
            .map_err(|_overflow| KeyError::Overflow)?;
        Ok(Self(u32::from(next)))
    }

    /// Select this attempt's whole play, including the largest attempt.
    ///
    /// # Specification
    /// - ensures: includes this attempt from sequence zero and excludes the
    ///   next dispatch; the largest attempt has an unbounded upper edge.
    /// - fails: the record plane refuses an unordered range.
    /// - panics: none.
    /// - executable: none — the range constructor is its own specification; the
    ///   maximum-attempt witness checks inclusion and the unbounded edge.
    ///
    /// # Errors
    /// - [`gandr_storage_records::RecordTreeError`]: invalid range endpoints.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the maximum attempt catches wrapping upper bounds.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[inline]
    pub fn range(self) -> Result<OwnedKeyRange, gandr_storage_records::RecordTreeError>
    {
        let lower = OwnedKeyBound::Included(MoveKey::new(self, SequenceNumber(0)).owned());
        let upper = match self.next() {
            | Ok(next) => OwnedKeyBound::Excluded(MoveKey::new(next, SequenceNumber(0)).owned()),
            | Err(KeyError::Overflow | KeyError::Width) => OwnedKeyBound::Unbounded,
        };
        let range = gandr_storage_records::KeyRange::new(lower.as_bound(), upper.as_bound())?;
        Ok(OwnedKeyRange::from_range(range))
    }
}

#[cfg(test)]
mod tests
{
    use super::*;

    #[test]
    fn move_keys_sort_as_attempt_then_seq()
    {
        let values = [0, 1, 255, 256, 0xffff, 0x0001_0000, u32::MAX];
        let mut keys = Vec::new();
        for attempt in values {
            for seq in values {
                let key = MoveKey::new(AttemptNumber(attempt), SequenceNumber(seq));
                assert_eq!(
                    key.coordinates(),
                    (AttemptNumber(attempt), SequenceNumber(seq))
                );
                assert_eq!(MoveKey::try_from(key.as_ref()).unwrap(), key);
                keys.push(key);
            }
        }
        assert!(keys.array_windows::<2>().all(|pair| {
            let [left, right] = pair.each_ref();
            left < right
        }));
        assert_eq!(
            MoveKey::new(AttemptNumber(256), SequenceNumber(0x0001_0000)).as_ref(),
            [0, 0, 1, 0, 0, 1, 0, 0]
        );
        assert_eq!(MoveKey::try_from([0; 7].as_slice()), Err(KeyError::Width));
        assert_eq!(MoveKey::try_from([0; 9].as_slice()), Err(KeyError::Width));
        assert_eq!(AttemptNumber(u32::MAX).next(), Err(KeyError::Overflow));
        assert_eq!(AttemptNumber(255).next(), Ok(AttemptNumber(256)));
        assert_eq!(
            AttemptNumber(u32::MAX)
                .range()
                .unwrap()
                .as_range()
                .unwrap()
                .end(),
            gandr_storage_records::KeyBound::Unbounded
        );
    }
}
