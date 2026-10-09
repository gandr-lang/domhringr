//! Decisions: what the operator decides of an attempt ([`Decision`]) and the
//! revision of the repository a landing carried its change into
//! ([`Revision`]).
//!
//! The operator decides an attempt by its dispatch: land its change, rework
//! it for a reason, or abandon the task. A landing names the decision to land
//! it carries out and the revision the repository's default branch stood at
//! once the change was in: the merge commit, or the change's own commit when
//! the branch fast-forwarded to it. The record names the revision and holds no
//! repository: where the repository lives is the operator's.

use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use crate::line::Field;
use crate::line::OneLine;
use crate::task::Summary;

/// The bytes of a SHA-1 object id: git's default object format.
const SHA1_BYTES: usize = 20;

/// The hex digits that spell a SHA-1 object id.
const SHA1_DIGITS: usize = 40;

/// The bytes of a SHA-256 object id: git's other object format.
const SHA256_BYTES: usize = 32;

/// The hex digits that spell a SHA-256 object id.
const SHA256_DIGITS: usize = 64;

/// What the operator decides of an attempt.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Decision
{
    /// Land the attempt's change.
    Land,
    /// Dispatch the task again: the attempt falls short, for this reason.
    Rework
    {
        /// What falls short, on one line.
        reason: Summary,
    },
    /// Give the task up.
    Abandon,
}

impl fmt::Display for Decision
{
    /// Write the decision as `land`, `rework <reason>` or `abandon`.
    ///
    /// # Specification
    /// - ensures: the reason is written as a line's last field, its backslashes
    ///   escaped as a summary's are, so the decision stays one line.
    /// - fails: the formatter's own error.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`fmt::Error`]: the formatter refused a write.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a task holding a decision of each kind, the reason
    ///   carrying a backslash, is printed and compared line for line.
    /// - witness: `fold::tests::a_task_prints_one_line_per_step_and_its_standing`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Land => f.write_str("land"),
            | Self::Rework { ref reason } => {
                f.write_str("rework ")?;
                OneLine::new(f, Field::Last).write_str(reason.as_ref())
            },
            | Self::Abandon => f.write_str("abandon"),
        }
    }
}

/// A revision of a repository, by the object id git gives its commit: 20
/// bytes in a SHA-1 repository, 32 in a SHA-256 one, written as 40 or 64
/// lowercase hex digits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Revision
{
    /// A SHA-1 object id.
    Sha1([u8; SHA1_BYTES]),
    /// A SHA-256 object id.
    Sha256([u8; SHA256_BYTES]),
}

impl AsRef<[u8]> for Revision
{
    /// The object id's bytes: 20 or 32 of them.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &[u8]
    {
        match *self {
            | Self::Sha1(ref bytes) => bytes,
            | Self::Sha256(ref bytes) => bytes,
        }
    }
}

impl TryFrom<&[u8]> for Revision
{
    type Error = ParseRevisionError;

    /// Read an object id from its bytes.
    ///
    /// # Specification
    /// - ensures: 20 bytes read as a SHA-1 id and 32 as a SHA-256 id, the bytes
    ///   kept as given.
    /// - fails: [`ParseRevisionError::Length`] for any other length.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRevisionError::Length`]: the bytes are neither 20 nor 32.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a landing of each width round-trips through the
    ///   receipt codec, and a landing whose revision is 21 bytes is refused at
    ///   its record.
    /// - witness: `receipt::tests::every_kind_round_trips`
    /// - witness: `receipt::tests::a_malformed_blob_is_refused_by_name`
    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error>
    {
        if let Ok(id) = <[u8; SHA1_BYTES]>::try_from(bytes) {
            return Ok(Self::Sha1(id));
        }
        if let Ok(id) = <[u8; SHA256_BYTES]>::try_from(bytes) {
            return Ok(Self::Sha256(id));
        }
        Err(ParseRevisionError::Length)
    }
}

impl FromStr for Revision
{
    type Err = ParseRevisionError;

    /// Read an object id from its lowercase hex digits, as git prints it.
    ///
    /// # Specification
    /// - ensures: 40 lowercase hex digits read as a SHA-1 id and 64 as a
    ///   SHA-256 id; [`Display`] writes the same digits back.
    /// - fails: [`ParseRevisionError::Length`] for text of any other byte
    ///   length, then [`ParseRevisionError::Digit`] for a byte that is not a
    ///   lowercase hex digit, an uppercase one among them.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRevisionError::Length`]: neither 40 nor 64 digits.
    /// - [`ParseRevisionError::Digit`]: a byte is not a lowercase hex digit.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — both widths round-trip through their text; 39, 41, 63
    ///   and 65 digits, an uppercase digit and a non-hex byte are each refused
    ///   by name.
    /// - witness: `decision::tests::a_revision_is_forty_or_sixty_four_lowercase_hex_digits`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let decode = |output: &mut [u8]| {
            data_encoding::HEXLOWER
                .decode_mut(text.as_bytes(), output)
                .map_err(|partial| ParseRevisionError::Digit(partial.error))
        };
        if text.len() == SHA1_DIGITS {
            let mut id = [0_u8; SHA1_BYTES];
            decode(&mut id)?;
            return Ok(Self::Sha1(id));
        }
        if text.len() == SHA256_DIGITS {
            let mut id = [0_u8; SHA256_BYTES];
            decode(&mut id)?;
            return Ok(Self::Sha256(id));
        }
        Err(ParseRevisionError::Length)
    }
}

impl fmt::Display for Revision
{
    /// Write the object id as lowercase hex digits, 40 or 64 of them.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        self.as_ref()
            .iter()
            .try_for_each(|byte| write!(f, "{byte:02x}"))
    }
}

/// Why a text or a byte string is not a revision.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseRevisionError
{
    /// Neither the length of a SHA-1 id nor of a SHA-256 one.
    #[error("a revision is a git object id: 40 or 64 hex digits, 20 or 32 bytes")]
    Length,
    /// A byte is not a lowercase hex digit.
    #[error("a revision is written in lowercase hex digits")]
    Digit(#[source] data_encoding::DecodeError),
}

#[cfg(test)]
mod tests
{
    use super::ParseRevisionError;
    use super::Revision;

    #[test]
    fn a_revision_is_forty_or_sixty_four_lowercase_hex_digits()
    {
        let sha1 = "0123456789abcdef0123456789abcdef01234567";
        let sha256 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        for (text, width) in [(sha1, 20), (sha256, 32)] {
            let revision = text.parse::<Revision>().unwrap();
            assert_eq!(revision.to_string(), text, "{text} reads back as written");
            assert_eq!(
                revision.as_ref().len(),
                width,
                "{text} spells {width} bytes"
            );
            assert_eq!(
                Revision::try_from(revision.as_ref()),
                Ok(revision),
                "{text}'s bytes read back as the same revision"
            );
        }
        for digits in [39, 41, 63, 65] {
            assert_eq!(
                "a".repeat(digits).parse::<Revision>(),
                Err(ParseRevisionError::Length),
                "{digits} digits"
            );
        }
        for text in [
            "0123456789ABCDEF0123456789abcdef01234567",
            "0123456789abcdeg0123456789abcdef01234567",
        ] {
            assert!(
                matches!(text.parse::<Revision>(), Err(ParseRevisionError::Digit(_))),
                "{text} holds a byte that is not a lowercase hex digit"
            );
        }
        assert_eq!(
            Revision::try_from([0_u8; 21].as_slice()),
            Err(ParseRevisionError::Length),
            "21 bytes"
        );
    }
}
