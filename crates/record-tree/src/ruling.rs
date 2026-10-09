//! Rulings: a judge's answer to one question asked about a task — the readout
//! of a model's next-token distribution over the question's option letters,
//! or why there is none.
//!
//! A question lists its options in order, lettered `A`, `B`, … ([`Letter`]),
//! two to twenty-six of them. A [`Readout`] holds one [`Probability`] per
//! option, renormalised over the option letters so the vector sums to one
//! within [`TOLERANCE`]; the mass the model put on every other token, the
//! outside mass; and the answer letter, the option holding the most
//! probability, unique by construction: two letters sharing the most are no
//! readout. A judge that reads no answer records why ([`Unread`]), never a
//! default letter ([`Ruling`]).

use alloc::vec::Vec;
use core::cmp::Ordering;
use core::fmt;
use core::str::FromStr;

/// How far a readout's probabilities may sum from one: far above the rounding
/// of renormalising twenty-six doubles, far below any difference a reader of
/// a probability acts on.
const TOLERANCE: f64 = 1.0e-9_f64;

/// The fewest options a question lists: one option is no choice.
const FEWEST: usize = 2;

/// The most options a question lists: one per letter of the alphabet.
const MOST: usize = 26;

/// An option's letter: `A` for the first option, `B` for the second, through
/// `Z`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Letter(char);

impl Letter
{
    /// The letters in option order, `A` through `Z`.
    ///
    /// # Specification
    /// - ensures: yields the 26 uppercase ASCII letters in alphabetical order,
    ///   each once, so the `n`-th option's letter is the `n`-th item.
    /// - panics: none.
    #[inline]
    pub fn sequence() -> impl Iterator<Item = Self>
    {
        ('A' ..= 'Z').map(Self)
    }
}

impl TryFrom<char> for Letter
{
    type Error = ParseLetterError;

    /// Take `character` as a letter.
    ///
    /// # Specification
    /// - ensures: accepts exactly the uppercase ASCII letters `A` through `Z`.
    /// - fails: [`ParseLetterError`] for any other character.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseLetterError`]: the character is no uppercase ASCII letter.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — `A` and `Z` are accepted, and `a`, `[` and `@`, the
    ///   characters beside the range, refused.
    /// - witness: `ruling::tests::a_letter_is_one_uppercase_ascii_letter`
    #[inline]
    fn try_from(character: char) -> Result<Self, Self::Error>
    {
        character
            .is_ascii_uppercase()
            .then_some(Self(character))
            .ok_or(ParseLetterError)
    }
}

impl FromStr for Letter
{
    type Err = ParseLetterError;

    /// Read a letter from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly one uppercase ASCII letter, which [`Display`]
    ///   writes back.
    /// - fails: [`ParseLetterError`] for the empty text, more than one
    ///   character, or another character.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseLetterError`]: the text is not one uppercase ASCII letter.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — `A` reads back, and the empty text, `AB` and `a` are
    ///   refused.
    /// - witness: `ruling::tests::a_letter_is_one_uppercase_ascii_letter`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut characters = text.chars();
        match (characters.next(), characters.next()) {
            | (Some(character), None) => Self::try_from(character),
            | (None, _) | (Some(_), Some(_)) => Err(ParseLetterError),
        }
    }
}

impl fmt::Display for Letter
{
    /// Write the letter.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Write::write_char(f, self.0)
    }
}

impl From<Letter> for char
{
    /// The letter as a character.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(letter: Letter) -> Self
    {
        letter.0
    }
}

/// Why a text or a character is not a letter.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a letter is one of A through Z")]
pub struct ParseLetterError;

/// A probability: a finite number from zero to one, never negative zero, so
/// each probability has one binary64 encoding.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Probability(f64);

impl TryFrom<f64> for Probability
{
    type Error = NotProbability;

    /// Take `value` as a probability.
    ///
    /// # Specification
    /// - ensures: accepts exactly the numbers from zero to one, both included,
    ///   and holds negative zero as zero.
    /// - fails: [`NotProbability`] for a NaN, an infinity, a negative number or
    ///   one above one.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`NotProbability`]: the value is not a number from zero to one.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — zero, one and a value between are accepted as
    ///   themselves and negative zero as zero; the smallest negative number,
    ///   the next number above one, both infinities and a NaN are refused.
    /// - witness: `ruling::tests::a_probability_is_a_number_from_zero_to_one`
    #[inline]
    fn try_from(value: f64) -> Result<Self, Self::Error>
    {
        (0.0_f64 ..= 1.0_f64)
            .contains(&value)
            .then(|| Self(value.abs()))
            .ok_or(NotProbability)
    }
}

impl From<Probability> for f64
{
    /// The probability as a number.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(probability: Probability) -> Self
    {
        probability.0
    }
}

impl PartialEq for Probability
{
    /// Whether two probabilities are the same number.
    ///
    /// # Specification
    /// - ensures: equal exactly when the numbers are equal: a probability is
    ///   never NaN or negative zero, so equal numbers have equal encodings and
    ///   the encodings are compared.
    /// - panics: none.
    #[inline]
    fn eq(
        &self,
        other: &Self,
    ) -> bool
    {
        self.0.to_bits() == other.0.to_bits()
    }
}

impl Eq for Probability
{
}

impl PartialOrd for Probability
{
    /// The order of two probabilities as numbers.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn partial_cmp(
        &self,
        other: &Self,
    ) -> Option<Ordering>
    {
        Some(self.cmp(other))
    }
}

impl Ord for Probability
{
    /// The order of two probabilities as numbers.
    ///
    /// # Specification
    /// - ensures: the numeric order, total over probabilities: with NaN and
    ///   negative zero excluded, IEEE 754's total order is the numeric one, and
    ///   it agrees with [`PartialEq`].
    /// - panics: none.
    #[inline]
    fn cmp(
        &self,
        other: &Self,
    ) -> Ordering
    {
        self.0.total_cmp(&other.0)
    }
}

impl FromStr for Probability
{
    type Err = ParseProbabilityError;

    /// Read a probability from its decimal text.
    ///
    /// # Specification
    /// - ensures: accepts a decimal number Rust reads as a double that is a
    ///   probability ([`Probability::try_from`]); what [`Display`] writes reads
    ///   back to the same probability.
    /// - fails: [`ParseProbabilityError::Number`] for text that is no number,
    ///   [`ParseProbabilityError::Range`] for a number that is no probability.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseProbabilityError::Number`]: the text is not a number.
    /// - [`ParseProbabilityError::Range`]: the number is not from zero to one.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — written probabilities read back to themselves, and a
    ///   word, `1.5` and `NaN` each meet their own refusal.
    /// - witness: `ruling::tests::a_probability_is_a_number_from_zero_to_one`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let value = text.parse::<f64>().map_err(ParseProbabilityError::Number)?;
        Self::try_from(value).map_err(ParseProbabilityError::Range)
    }
}

impl fmt::Display for Probability
{
    /// Write the probability as the shortest decimal that reads back to it.
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

/// Why a number is not a probability.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a probability is a number from 0 to 1")]
pub struct NotProbability;

/// Why a text is not a probability.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseProbabilityError
{
    /// The text is not a number.
    #[error("the text is not a number")]
    Number(#[source] core::num::ParseFloatError),
    /// The number is not from zero to one.
    #[error(transparent)]
    Range(NotProbability),
}

/// What a judge read out of a model for one question: a probability per
/// option, renormalised over the option letters, the mass outside them, and
/// the answer letter.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Readout
{
    /// The option holding the most probability, alone.
    letter: Letter,
    /// One probability per option, in letter order.
    probabilities: Vec<Probability>,
    /// The mass the model put on tokens other than the option letters.
    outside: Probability,
}

impl Readout
{
    /// The readout of `probabilities`, one per option in letter order, with
    /// `outside` the mass outside the option letters.
    ///
    /// # Specification
    /// - ensures: the readout holds `probabilities` and `outside` as given, and
    ///   its letter is the option whose probability is greater than every
    ///   other's.
    /// - fails: [`ReadoutError::Few`] for fewer than two probabilities,
    ///   [`ReadoutError::Many`] for more than twenty-six, then
    ///   [`ReadoutError::Sum`] when they do not sum to one within `1e-9`, then
    ///   [`ReadoutError::Tied`] when two options share the greatest.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ReadoutError::Few`]: fewer than two options.
    /// - [`ReadoutError::Many`]: more than twenty-six options.
    /// - [`ReadoutError::Sum`]: the probabilities do not sum to one.
    /// - [`ReadoutError::Tied`]: no option holds the most alone.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two and twenty-six options are read and one and
    ///   twenty-seven refused; a vector off one by more than the tolerance is
    ///   refused while one off by less is read; the greatest first, last and in
    ///   the middle is the letter; two options sharing the greatest are tied
    ///   wherever they stand, and two sharing a lesser value are not.
    /// - witness: `ruling::tests::a_readout_names_the_option_holding_the_most`
    #[inline]
    pub fn new(
        probabilities: Vec<Probability>,
        outside: Probability,
    ) -> Result<Self, ReadoutError>
    {
        if probabilities.len() < FEWEST {
            return Err(ReadoutError::Few);
        }
        if probabilities.len() > MOST {
            return Err(ReadoutError::Many);
        }
        let total: f64 = probabilities.iter().map(|&probability| probability.0).sum();
        if (total - 1.0_f64).abs() > TOLERANCE {
            return Err(ReadoutError::Sum);
        }
        let mut best = None;
        let mut tied = false;
        for (letter, probability) in Letter::sequence().zip(probabilities.iter().copied()) {
            match best {
                | Some((_, most)) if probability < most => {},
                | Some((_, most)) if probability == most => tied = true,
                | Some(_) | None => {
                    best = Some((letter, probability));
                    tied = false;
                },
            }
        }
        match (best, tied) {
            | (Some((letter, _)), false) => Ok(Self {
                letter,
                probabilities,
                outside,
            }),
            | (Some(_) | None, _) => Err(ReadoutError::Tied),
        }
    }

    /// The answer letter: the option holding the most probability.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn letter(&self) -> Letter
    {
        self.letter
    }

    /// Each option's letter and probability, in letter order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    pub fn probabilities(&self) -> impl Iterator<Item = (Letter, Probability)> + '_
    {
        Letter::sequence().zip(self.probabilities.iter().copied())
    }

    /// The mass the model put on tokens other than the option letters.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn outside(&self) -> Probability
    {
        self.outside
    }
}

impl FromStr for Readout
{
    type Err = ParseRulingError;

    /// Read a readout from the text [`Display`] writes: `<letter> A=<p> B=<p>
    /// … outside=<p>`.
    ///
    /// # Specification
    /// - ensures: accepts the answer letter, then one `<letter>=<probability>`
    ///   field per option with the letters in order from `A`, then
    ///   `outside=<probability>`, separated by single spaces; yields the
    ///   readout [`Readout::new`] makes of them, whose letter is the one given.
    /// - fails: [`ParseRulingError::Form`] for a missing or surplus field or a
    ///   field without `=`, [`ParseRulingError::Letter`] for an answer letter
    ///   or an option name that is no letter, [`ParseRulingError::Order`] for
    ///   options out of letter order, [`ParseRulingError::Probability`] for a
    ///   value that is no probability, [`ParseRulingError::Readout`] as
    ///   [`Readout::new`] refuses, and [`ParseRulingError::Mismatch`] when the
    ///   answer letter is not the option holding the most.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRulingError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a readout reads back from its text, and each refusal
    ///   is met by a text one field away from a well-formed one.
    /// - witness: `ruling::tests::a_ruling_reads_back_from_its_text`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut fields = text.split(' ');
        let letter = fields.next().ok_or(ParseRulingError::Form)?;
        let letter = letter.parse::<Letter>().map_err(ParseRulingError::Letter)?;
        let mut letters = Letter::sequence();
        let mut probabilities = Vec::new();
        let outside = loop {
            let field = fields.next().ok_or(ParseRulingError::Form)?;
            let (name, value) = field.split_once('=').ok_or(ParseRulingError::Form)?;
            let value = value
                .parse::<Probability>()
                .map_err(ParseRulingError::Probability)?;
            if name == "outside" {
                break value;
            }
            let name = name.parse::<Letter>().map_err(ParseRulingError::Letter)?;
            if letters.next() != Some(name) {
                return Err(ParseRulingError::Order);
            }
            probabilities.push(value);
        };
        if fields.next().is_some() {
            return Err(ParseRulingError::Form);
        }
        let readout = Self::new(probabilities, outside).map_err(ParseRulingError::Readout)?;
        if readout.letter != letter {
            return Err(ParseRulingError::Mismatch);
        }
        Ok(readout)
    }
}

impl fmt::Display for Readout
{
    /// Write the readout as `<letter> A=<p> B=<p> … outside=<p>`.
    ///
    /// # Specification
    /// - ensures: one line with no newline, which [`Readout::from_str`] reads
    ///   back to the same readout.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(f, "{}", self.letter)?;
        for (letter, probability) in self.probabilities() {
            write!(f, " {letter}={probability}")?;
        }
        write!(f, " outside={}", self.outside)
    }
}

/// Why a readout cannot be made of a vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ReadoutError
{
    /// Fewer than two options.
    #[error("a readout has at least {FEWEST} options")]
    Few,
    /// More than twenty-six options.
    #[error("a readout has at most {MOST} options")]
    Many,
    /// The probabilities do not sum to one within the tolerance.
    #[error("a readout's probabilities sum to one")]
    Sum,
    /// Two options share the greatest probability.
    #[error("two options share the greatest probability")]
    Tied,
}

/// Why a judge read no answer for a question.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unread
{
    /// The tokens the model reported at the answer's position hold no option
    /// letter.
    NoLetter,
    /// The model put more mass outside the option letters than the judge's
    /// ceiling admits.
    Outside,
    /// Two options share the greatest probability.
    Tied,
    /// The endpoint could not be reached, failed, or answered without a
    /// distribution over tokens.
    Endpoint,
    /// The question could not be put as asked: its transcript's content is not
    /// held or not text, or the endpoint refused the request as malformed.
    Malformed,
}

impl FromStr for Unread
{
    type Err = ParseRulingError;

    /// Read a reason from the text [`Display`] writes.
    ///
    /// # Specification
    /// - ensures: accepts `no letter`, `outside`, `tied`, `endpoint` and
    ///   `malformed`, each naming its reason.
    /// - fails: [`ParseRulingError::Reason`] for any other text.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRulingError::Reason`]: the text names no reason.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every reason reads back from its text, and an unknown
    ///   one is refused.
    /// - witness: `ruling::tests::a_ruling_reads_back_from_its_text`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        match text {
            | "no letter" => Ok(Self::NoLetter),
            | "outside" => Ok(Self::Outside),
            | "tied" => Ok(Self::Tied),
            | "endpoint" => Ok(Self::Endpoint),
            | "malformed" => Ok(Self::Malformed),
            | _ => Err(ParseRulingError::Reason),
        }
    }
}

impl fmt::Display for Unread
{
    /// Write the reason: `no letter`, `outside`, `tied`, `endpoint` or
    /// `malformed`.
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
            | Self::NoLetter => "no letter",
            | Self::Outside => "outside",
            | Self::Tied => "tied",
            | Self::Endpoint => "endpoint",
            | Self::Malformed => "malformed",
        })
    }
}

/// A judge's answer to one question: the readout, or why there is none.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Ruling
{
    /// The judge read this out of the model.
    Read(Readout),
    /// The judge read no answer, for this reason.
    Unread(Unread),
}

impl FromStr for Ruling
{
    type Err = ParseRulingError;

    /// Read a ruling from the text [`Display`] writes: `read <readout>` or
    /// `unread <reason>`.
    ///
    /// # Specification
    /// - ensures: accepts `read ` followed by a readout as
    ///   [`Readout::from_str`] reads it, or `unread ` followed by a reason as
    ///   [`Unread::from_str`] reads it.
    /// - fails: [`ParseRulingError::Form`] for text that begins with neither,
    ///   and as those readers refuse otherwise.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRulingError`]: as [`Readout::from_str`] and
    ///   [`Unread::from_str`], or the text begins with neither form.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a readout and every reason read back from their text,
    ///   and a text of neither form is refused.
    /// - witness: `ruling::tests::a_ruling_reads_back_from_its_text`
    ///
    /// [`Display`]: fmt::Display
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if let Some(reason) = text.strip_prefix("unread ") {
            return reason.parse().map(Self::Unread);
        }
        let readout = text.strip_prefix("read ").ok_or(ParseRulingError::Form)?;
        readout.parse().map(Self::Read)
    }
}

impl fmt::Display for Ruling
{
    /// Write the ruling as `read <readout>` or `unread <reason>`.
    ///
    /// # Specification
    /// - ensures: one line with no newline, which [`Ruling::from_str`] reads
    ///   back to the same ruling.
    /// - panics: none.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Read(ref readout) => write!(f, "read {readout}"),
            | Self::Unread(reason) => write!(f, "unread {reason}"),
        }
    }
}

/// Why a text is not a ruling.
#[derive(Clone, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseRulingError
{
    /// The text is not `read <letter> A=<p> … outside=<p>` or `unread
    /// <reason>`.
    #[error("a ruling is `read <letter> A=<p> B=<p> … outside=<p>` or `unread <reason>`")]
    Form,
    /// The reason is not one a ruling names.
    #[error("a reason is no letter, outside, tied, endpoint or malformed")]
    Reason,
    /// The answer letter or an option's name is not a letter.
    #[error("cannot read the letter")]
    Letter(#[source] ParseLetterError),
    /// The options are not lettered in order from `A`.
    #[error("the options are lettered in order from A")]
    Order,
    /// A value is not a probability.
    #[error("cannot read the probability")]
    Probability(#[source] ParseProbabilityError),
    /// The probabilities make no readout.
    #[error("the probabilities make no readout")]
    Readout(#[source] ReadoutError),
    /// The answer letter is not the option holding the most probability.
    #[error("the answer letter is not the option holding the most probability")]
    Mismatch,
}

#[cfg(test)]
mod tests
{
    use alloc::vec::Vec;

    use super::Letter;
    use super::NotProbability;
    use super::ParseLetterError;
    use super::ParseProbabilityError;
    use super::ParseRulingError;
    use super::Probability;
    use super::Readout;
    use super::ReadoutError;
    use super::Ruling;
    use super::Unread;

    #[test]
    fn a_letter_is_one_uppercase_ascii_letter()
    {
        let letters = Letter::sequence()
            .map(|letter| letter.to_string())
            .collect::<Vec<_>>();
        assert_eq!(letters.len(), 26, "one letter per option, A through Z");
        assert_eq!(
            letters.first().map(String::as_str),
            Some("A"),
            "A comes first"
        );
        assert_eq!(
            letters.last().map(String::as_str),
            Some("Z"),
            "Z comes last"
        );
        for text in ["A", "Z"] {
            assert_eq!(
                text.parse::<Letter>().unwrap().to_string(),
                text,
                "{text} reads back"
            );
        }
        for character in ['a', '[', '@'] {
            assert_eq!(
                Letter::try_from(character),
                Err(ParseLetterError),
                "{character:?} stands beside the range"
            );
        }
        for text in ["", "AB", "a"] {
            assert_eq!(
                text.parse::<Letter>(),
                Err(ParseLetterError),
                "{text:?} is not one letter"
            );
        }
    }

    #[test]
    fn a_probability_is_a_number_from_zero_to_one()
    {
        let probability = |value: f64| Probability::try_from(value).unwrap();
        for value in [0.0_f64, 1.0_f64, 0.25_f64] {
            assert_eq!(
                f64::from(probability(value)).to_bits(),
                value.to_bits(),
                "{value} is itself"
            );
        }
        assert_eq!(
            f64::from(probability(-0.0_f64)).to_bits(),
            0.0_f64.to_bits(),
            "negative zero is zero"
        );
        for value in [
            -f64::from_bits(1),
            1.0_f64.next_up(),
            f64::INFINITY,
            f64::NEG_INFINITY,
            f64::NAN,
        ] {
            assert_eq!(
                Probability::try_from(value),
                Err(NotProbability),
                "{value} is no probability"
            );
        }
        for text in ["0", "1", "0.25", "0.7310585786300049", "0.00000000045"] {
            assert_eq!(
                text.parse::<Probability>().unwrap().to_string(),
                text,
                "{text} reads back"
            );
        }
        assert!(
            matches!(
                "half".parse::<Probability>(),
                Err(ParseProbabilityError::Number(_))
            ),
            "a word is no number"
        );
        for text in ["1.5", "NaN"] {
            assert_eq!(
                text.parse::<Probability>(),
                Err(ParseProbabilityError::Range(NotProbability)),
                "{text} is a number but no probability"
            );
        }
    }

    #[test]
    fn a_readout_names_the_option_holding_the_most()
    {
        let probability = |value: f64| Probability::try_from(value).unwrap();
        let probabilities = |values: &[f64]| {
            values
                .iter()
                .map(|&value| probability(value))
                .collect::<Vec<_>>()
        };
        let none = probability(0.0_f64);
        let read = |values: &[f64]| Readout::new(probabilities(values), none);
        let letter = |text: &str| text.parse::<Letter>().unwrap();
        for (values, most) in [
            (&[0.75_f64, 0.25_f64][..], "A"),
            (&[0.25_f64, 0.75_f64][..], "B"),
            (&[0.25_f64, 0.5_f64, 0.25_f64][..], "B"),
            (&[0.5_f64, 0.25_f64, 0.25_f64][..], "A"),
        ] {
            assert_eq!(
                read(values).unwrap().letter(),
                letter(most),
                "{most} holds the most of {values:?}"
            );
        }
        let mut many = [0.0_f64; 26];
        many[25] = 1.0_f64;
        assert_eq!(
            read(&many).unwrap().letter(),
            letter("Z"),
            "twenty-six options, the last holding all"
        );
        assert_eq!(read(&[1.0_f64]), Err(ReadoutError::Few), "one option");
        let mut too_many = [0.0_f64; 27];
        too_many[0] = 1.0_f64;
        assert_eq!(read(&too_many), Err(ReadoutError::Many), "27 options");
        assert_eq!(
            read(&[0.75_f64, 0.25_f64 + 2.0e-9_f64]),
            Err(ReadoutError::Sum),
            "off one by more than the tolerance"
        );
        assert_eq!(
            read(&[0.75_f64, 0.25_f64 + 5.0e-10_f64]).unwrap().letter(),
            letter("A"),
            "off one by less than the tolerance"
        );
        for values in [
            &[0.5_f64, 0.5_f64][..],
            &[0.4_f64, 0.2_f64, 0.4_f64][..],
            &[0.2_f64, 0.4_f64, 0.4_f64][..],
        ] {
            assert_eq!(
                read(values),
                Err(ReadoutError::Tied),
                "{values:?} shares the greatest"
            );
        }
        assert_eq!(
            read(&[0.2_f64, 0.2_f64, 0.6_f64]).unwrap().letter(),
            letter("C"),
            "two sharing a lesser value are not tied"
        );
        let readout =
            Readout::new(probabilities(&[0.25_f64, 0.75_f64]), probability(0.5_f64)).unwrap();
        assert_eq!(
            readout
                .probabilities()
                .map(|(letter, probability)| format!("{letter}={probability}"))
                .collect::<Vec<_>>(),
            ["A=0.25", "B=0.75"],
            "each option's letter and probability, in letter order"
        );
        assert_eq!(readout.outside(), probability(0.5_f64), "the mass outside");
    }

    #[test]
    fn a_ruling_reads_back_from_its_text()
    {
        let text = "read B A=0.25 B=0.75 outside=0.0125";
        let ruling = text.parse::<Ruling>().unwrap();
        let Ruling::Read(ref readout) = ruling
        else {
            panic!("a read ruling reads as a readout: {ruling:?}");
        };
        assert_eq!(readout.letter().to_string(), "B", "the answer letter");
        assert_eq!(ruling.to_string(), text, "the readout writes back as read");
        for (reason, text) in [
            (Unread::NoLetter, "unread no letter"),
            (Unread::Outside, "unread outside"),
            (Unread::Tied, "unread tied"),
            (Unread::Endpoint, "unread endpoint"),
            (Unread::Malformed, "unread malformed"),
        ] {
            assert_eq!(
                text.parse::<Ruling>(),
                Ok(Ruling::Unread(reason)),
                "{text} reads to its reason"
            );
            assert_eq!(
                Ruling::Unread(reason).to_string(),
                text,
                "{text} writes back"
            );
        }
        for (text, refusal) in [
            ("answered B", ParseRulingError::Form),
            ("unread asleep", ParseRulingError::Reason),
            ("read B A=0.25 B=0.75", ParseRulingError::Form),
            ("read B A=0.25 B=0.75 outside=0 C=0", ParseRulingError::Form),
            ("read B A=0.25 B 0.75 outside=0", ParseRulingError::Form),
            (
                "read b A=0.25 B=0.75 outside=0",
                ParseRulingError::Letter(ParseLetterError),
            ),
            ("read B A=0.25 C=0.75 outside=0", ParseRulingError::Order),
            ("read B B=0.25 A=0.75 outside=0", ParseRulingError::Order),
            (
                "read B A=0.25 B=0.75 outside=2",
                ParseRulingError::Probability(ParseProbabilityError::Range(NotProbability)),
            ),
            (
                "read B A=0.5 B=0.75 outside=0",
                ParseRulingError::Readout(ReadoutError::Sum),
            ),
            ("read A A=0.25 B=0.75 outside=0", ParseRulingError::Mismatch),
        ] {
            assert_eq!(text.parse::<Ruling>(), Err(refusal), "{text:?}");
        }
    }
}
