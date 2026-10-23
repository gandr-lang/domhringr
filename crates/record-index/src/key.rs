//! Dialogue coordinates: an attempt and a move's place in it.

use anodized::spec;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::keyed::Number;

/// A one-based attempt number; zero is an absent probe.
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

/// A move's place: its attempt, then its sequence number in that attempt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct MoveKey
{
    /// The attempt.
    attempt: AttemptNumber,
    /// The place in the attempt.
    seq: SequenceNumber,
}

/// A coordinate cannot be represented.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum KeyError
{
    /// The next attempt or sequence, or a stored number, exceeds 32 bits.
    #[error("dialogue coordinate exceeds u32")]
    Overflow,
}

impl MoveKey
{
    /// Place a move.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        attempt: AttemptNumber,
        seq: SequenceNumber,
    ) -> Self
    {
        Self { attempt, seq }
    }

    /// The attempt and the place in it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn coordinates(self) -> (AttemptNumber, SequenceNumber)
    {
        (self.attempt, self.seq)
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
}

impl From<AttemptNumber> for Number
{
    /// The attempt as its stored number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(attempt: AttemptNumber) -> Self
    {
        Self(u64::from(attempt.0))
    }
}

impl From<SequenceNumber> for Number
{
    /// The place as its stored number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(seq: SequenceNumber) -> Self
    {
        Self(u64::from(seq.0))
    }
}

impl TryFrom<Number> for AttemptNumber
{
    type Error = KeyError;

    /// Read a stored number as an attempt.
    ///
    /// # Specification
    /// - ensures: `AttemptNumber::try_from(Number::from(a)) == Ok(a)`.
    /// - fails: a number past 32 bits.
    /// - panics: none.
    /// - executable: none — the conversion is its own specification; the
    ///   witness reads the extremes back.
    ///
    /// # Errors
    /// - [`KeyError::Overflow`]: past 32 bits.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the largest attempt reads back and the next number is
    ///   refused.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[inline]
    fn try_from(number: Number) -> Result<Self, Self::Error>
    {
        u32::try_from(number.0)
            .map(Self)
            .map_err(|_width| KeyError::Overflow)
    }
}

impl TryFrom<Number> for SequenceNumber
{
    type Error = KeyError;

    /// Read a stored number as a place.
    ///
    /// # Specification
    /// - ensures: `SequenceNumber::try_from(Number::from(s)) == Ok(s)`.
    /// - fails: a number past 32 bits.
    /// - panics: none.
    /// - executable: none — the conversion is its own specification; the
    ///   witness reads the extremes back.
    ///
    /// # Errors
    /// - [`KeyError::Overflow`]: past 32 bits.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the largest place reads back and the next number is
    ///   refused.
    /// - witness: `key::tests::move_keys_sort_as_attempt_then_seq`
    #[inline]
    fn try_from(number: Number) -> Result<Self, Self::Error>
    {
        u32::try_from(number.0)
            .map(Self)
            .map_err(|_width| KeyError::Overflow)
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
                assert_eq!(
                    AttemptNumber::try_from(Number::from(AttemptNumber(attempt))),
                    Ok(AttemptNumber(attempt))
                );
                assert_eq!(
                    SequenceNumber::try_from(Number::from(SequenceNumber(seq))),
                    Ok(SequenceNumber(seq))
                );
                keys.push(key);
            }
        }
        assert!(keys.array_windows::<2>().all(|pair| {
            let [left, right] = pair.each_ref();
            left < right
        }));
        let past = Number(0x0001_0000_0000);
        assert_eq!(AttemptNumber::try_from(past), Err(KeyError::Overflow));
        assert_eq!(SequenceNumber::try_from(past), Err(KeyError::Overflow));
        assert_eq!(AttemptNumber(u32::MAX).next(), Err(KeyError::Overflow));
        assert_eq!(AttemptNumber(255).next(), Ok(AttemptNumber(256)));
    }
}
