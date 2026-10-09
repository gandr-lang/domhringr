//! Checks: what running a playbook's step and grading a rubric record on a
//! task — the step's identifier ([`StepId`]), how its verifier's process
//! ended ([`Status`]), and a question's or a rubric's [`Grade`].
//!
//! A verification names its step by the identifier the playbook gives it,
//! and records how the verifier's process ended — exited with a code, or
//! ended by a signal — never only whether it passed. A grade is where a
//! ruling stands against a rubric's band — met, unmet, or undecided between
//! — or refused, for a ruling the judge did not read: a refusal is never
//! graded as an answer.

use alloc::string::String;
use core::fmt;
use core::str::FromStr;

/// The longest step identifier, in bytes.
const STEP_ID_BYTES: usize = 64;

/// A playbook step's identifier: 1 to 64 lowercase ASCII letters, digits and
/// hyphens, beginning with a letter.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StepId(String);

impl FromStr for StepId
{
    type Err = ParseStepIdError;

    /// Read a step identifier from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts of 1 to 64 lowercase ASCII letters,
    ///   digits and hyphens whose first character is a letter, and keeps the
    ///   text as written, so [`Display`] writes it back.
    /// - fails: the first refusal that holds, in this order:
    ///   [`ParseStepIdError::Empty`] for the empty text,
    ///   [`ParseStepIdError::Long`] for more than 64 bytes,
    ///   [`ParseStepIdError::Start`] for a first character that is no lowercase
    ///   letter, and [`ParseStepIdError::Character`] for any other character
    ///   outside the admitted set.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseStepIdError::Empty`]: the text is empty.
    /// - [`ParseStepIdError::Long`]: the text is longer than 64 bytes.
    /// - [`ParseStepIdError::Start`]: the text does not begin with a lowercase
    ///   letter.
    /// - [`ParseStepIdError::Character`]: a character is not a lowercase ASCII
    ///   letter, a digit or a hyphen.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — one letter, 64 bytes and a text holding every
    ///   admitted class read back as written; the empty text, 65 bytes, a
    ///   leading digit and hyphen, and an uppercase letter, an underscore, a
    ///   space and a non-ASCII letter after a letter each meet their own
    ///   refusal.
    /// - witness: `check::tests::a_step_id_is_a_short_lowercase_identifier`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let Some((first, rest)) = text.as_bytes().split_first()
        else {
            return Err(ParseStepIdError::Empty);
        };
        if text.len() > STEP_ID_BYTES {
            return Err(ParseStepIdError::Long);
        }
        if !first.is_ascii_lowercase() {
            return Err(ParseStepIdError::Start);
        }
        if !rest
            .iter()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || *byte == b'-')
        {
            return Err(ParseStepIdError::Character);
        }
        Ok(Self(text.into()))
    }
}

impl fmt::Display for StepId
{
    /// Write the identifier as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(&self.0)
    }
}

impl AsRef<str> for StepId
{
    /// The identifier's text, as written.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// Why a text is not a step identifier.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseStepIdError
{
    /// The text is empty.
    #[error("an identifier is not empty")]
    Empty,
    /// The text is longer than the longest identifier.
    #[error("an identifier is {STEP_ID_BYTES} bytes at most")]
    Long,
    /// The text does not begin with a lowercase letter.
    #[error("an identifier begins with a lowercase ASCII letter")]
    Start,
    /// A character is not one an identifier holds.
    #[error("an identifier holds lowercase ASCII letters, digits and hyphens alone")]
    Character,
}

/// How a verifier's process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Status
{
    /// The process exited with this code.
    Exited(Code),
    /// A signal ended the process before it exited.
    Signalled(Signal),
}

impl fmt::Display for Status
{
    /// Write the status as `exit <code>` or `signal <number>`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Exited(code) => write!(f, "exit {code}"),
            | Self::Signalled(signal) => write!(f, "signal {signal}"),
        }
    }
}

/// A process's exit code, as the operating system reports it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Code(i32);

impl From<i32> for Code
{
    /// Take `code` as an exit code.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(code: i32) -> Self
    {
        Self(code)
    }
}

impl From<Code> for i32
{
    /// The exit code as a number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(code: Code) -> Self
    {
        code.0
    }
}

impl fmt::Display for Code
{
    /// Write the code in decimal.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.0, f)
    }
}

/// The number of the signal that ended a process.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Signal(i32);

impl From<i32> for Signal
{
    /// Take `number` as a signal's number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(number: i32) -> Self
    {
        Self(number)
    }
}

impl From<Signal> for i32
{
    /// The signal's number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(signal: Signal) -> Self
    {
        signal.0
    }
}

impl fmt::Display for Signal
{
    /// Write the signal's number in decimal.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Where a ruling stands against a rubric's band, or where a rubric's grades
/// composed stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Grade
{
    /// The criterion holds: the probability the judge read for it reaches
    /// the band's high bound.
    Met,
    /// The criterion fails: that probability is at or below the band's low
    /// bound.
    Unmet,
    /// That probability lies strictly between the band's bounds.
    Undecided,
    /// The judge read no answer: the question is graded by no probability.
    Refused,
}

impl fmt::Display for Grade
{
    /// Write the grade: `met`, `unmet`, `undecided` or `refused`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Met => "met",
            | Self::Unmet => "unmet",
            | Self::Undecided => "undecided",
            | Self::Refused => "refused",
        })
    }
}

#[cfg(test)]
mod tests
{
    use super::ParseStepIdError;
    use super::StepId;

    #[test]
    fn a_step_id_is_a_short_lowercase_identifier()
    {
        let longest = format!("a{}", "9".repeat(63));
        for text in ["b", "build-and-test2", longest.as_str()] {
            assert_eq!(
                text.parse::<StepId>().unwrap().to_string(),
                text,
                "the identifier {text:?} reads back as written"
            );
        }
        let long = format!("a{}", "9".repeat(64));
        for (text, refusal) in [
            ("", ParseStepIdError::Empty),
            (long.as_str(), ParseStepIdError::Long),
            ("9a", ParseStepIdError::Start),
            ("-a", ParseStepIdError::Start),
            ("aB", ParseStepIdError::Character),
            ("a_b", ParseStepIdError::Character),
            ("a b", ParseStepIdError::Character),
            ("aö", ParseStepIdError::Character),
        ] {
            assert_eq!(
                text.parse::<StepId>(),
                Err(refusal),
                "the text {text:?} is refused by name"
            );
        }
    }
}
