//! The letter readout: the answer a judge reads out of a model's next-token
//! distribution for a lettered question.
//!
//! An endpoint reports, at the answer's position, its most probable tokens
//! with their natural log-probabilities. Each option holds the mass of the
//! reported tokens that are its letter: a token that, trimmed of whitespace,
//! is exactly the uppercase letter, so `B` and ` B` are one letter and their
//! masses add; an option whose letter is not reported holds none. The masses
//! are renormalised over the option letters, so the vector sums to one and
//! the letter holding the most is the answer. What the model put on every
//! other token, reported or not — prose, a lowercase letter, a letter past
//! the last option — is the outside mass, kept in the readout as the measure
//! of how far the model was answering the question at all; a judge whose
//! [`Ceiling`] admits less refuses. A distribution holding no option letter,
//! or two options sharing the most, is no answer, and is refused by name.

use alloc::string::String;
use alloc::vec::Vec;

use domhringr_record_tree::Letter;
use domhringr_record_tree::Probability;
use domhringr_record_tree::Readout;
use domhringr_record_tree::ReadoutError;
use serde::Deserialize;

use crate::backend::EndpointError;
use crate::backend::Refusal;
use crate::question::Question;

/// One reported token at the answer's position, with its natural
/// log-probability.
#[derive(Clone, Debug, PartialEq, Deserialize)]
pub struct Candidate
{
    /// The token's text.
    token: String,
    /// The natural logarithm of the token's probability.
    logprob: f64,
}

/// The most mass a judge admits outside the option letters.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ceiling
{
    /// Any: the outside mass is recorded and never refused.
    Unbounded,
    /// This much: a readout with more outside mass is refused.
    At(Probability),
}

/// The readout of `reported`, the tokens reported at the answer's position,
/// for `question`, refused when its outside mass passes `ceiling`.
///
/// # Specification
/// - ensures: each option's probability is the summed mass of the reported
///   tokens that are its letter once trimmed of whitespace, divided by the
///   summed mass of every option's letter; the outside mass is one less that
///   sum, and never below zero; the letter is the option holding the most.
/// - fails: [`EndpointError::Logprob`] for a reported log-probability that is
///   NaN or above zero, then [`Refusal::NoLetter`] when no option letter holds
///   any mass, then [`Refusal::Outside`] when the outside mass passes the
///   ceiling, then [`Refusal::Tied`] when two options share the most.
/// - panics: none.
///
/// # Errors
/// - [`Refusal`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a distribution with a letter reported twice, a letter
///   unreported, a lowercase letter, a letter past the last option and a word
///   is read and compared with the masses renormalised by hand; and an empty
///   report, a report of words alone, a NaN and a positive log-probability,
///   outside mass past a ceiling and within one, and two options sharing the
///   most each meet their own outcome.
/// - witness: `readout::tests::the_options_share_the_mass_on_their_letters`
/// - witness: `readout::tests::a_distribution_that_answers_nothing_is_refused`
pub fn read(
    question: &Question,
    reported: &[Candidate],
    ceiling: Ceiling,
) -> Result<Readout, Refusal>
{
    let mut masses: Vec<f64> = question.options().iter().map(|_option| 0.0_f64).collect();
    let mut inside = 0.0_f64;
    for candidate in reported {
        if candidate.logprob.is_nan() || candidate.logprob > 0.0_f64 {
            return Err(Refusal::Endpoint(EndpointError::Logprob));
        }
        let Ok(letter) = candidate.token.trim().parse::<Letter>()
        else {
            continue;
        };
        let mass = candidate.logprob.exp();
        for (option, held) in Letter::sequence().zip(masses.iter_mut()) {
            if option == letter {
                *held += mass;
                inside += mass;
            }
        }
    }
    if inside <= 0.0_f64 {
        return Err(Refusal::NoLetter);
    }
    let unreadable = |_not_a_probability| Refusal::Endpoint(EndpointError::Distribution);
    let outside = Probability::try_from((1.0_f64 - inside).max(0.0_f64)).map_err(unreadable)?;
    if let Ceiling::At(ceiling) = ceiling
        && outside > ceiling
    {
        return Err(Refusal::Outside { outside, ceiling });
    }
    let probabilities = masses
        .into_iter()
        .map(|held| Probability::try_from(held / inside))
        .collect::<Result<Vec<_>, _>>()
        .map_err(unreadable)?;
    Readout::new(probabilities, outside).map_err(|unread| match unread {
        | ReadoutError::Tied => Refusal::Tied,
        | ReadoutError::Few | ReadoutError::Many | ReadoutError::Sum => {
            Refusal::Endpoint(EndpointError::Distribution)
        },
    })
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::vec::Vec;

    use domhringr_record_tree::Probability;

    use super::Candidate;
    use super::Ceiling;
    use super::read;
    use crate::backend::EndpointError;
    use crate::backend::Refusal;
    use crate::question::Question;

    #[test]
    fn the_options_share_the_mass_on_their_letters()
    {
        let question = Question::new(String::from("Which colour is the sky?"), vec![
            String::from("green"),
            String::from("blue"),
            String::from("red"),
        ])
        .unwrap();
        let reported = [
            ("B", 0.5_f64),
            (" B", 0.1_f64),
            ("A", 0.2_f64),
            ("b", 0.05_f64),
            ("D", 0.05_f64),
            ("Blue", 0.04_f64),
        ]
        .map(|(token, probability)| Candidate {
            token: String::from(token),
            logprob: probability.ln(),
        });
        let readout = read(&question, &reported, Ceiling::Unbounded).unwrap();
        assert_eq!(
            readout.letter().to_string(),
            "B",
            "B holds the most once its two tokens add"
        );
        let expected = [0.2_f64 / 0.8_f64, 0.6_f64 / 0.8_f64, 0.0_f64];
        for ((letter, probability), expected) in readout.probabilities().zip(expected) {
            assert!(
                (f64::from(probability) - expected).abs() < 1.0e-12_f64,
                "{letter} holds {probability}, renormalised over the letters: {expected}"
            );
        }
        assert!(
            (f64::from(readout.outside()) - 0.2_f64).abs() < 1.0e-12_f64,
            "the lowercase letter, the letter past the options, the word and the unreported \
             mass are outside: {}",
            readout.outside()
        );
        let total: f64 = readout
            .probabilities()
            .map(|(_letter, probability)| f64::from(probability))
            .sum();
        assert!(
            (total - 1.0_f64).abs() < 1.0e-12_f64,
            "the vector sums to one: {total}"
        );
    }

    #[test]
    fn a_distribution_that_answers_nothing_is_refused()
    {
        let question = Question::new(String::from("Yes or no?"), vec![
            String::from("yes"),
            String::from("no"),
        ])
        .unwrap();
        let candidates = |reported: &[(&str, f64)]| {
            reported
                .iter()
                .map(|&(token, logprob)| Candidate {
                    token: String::from(token),
                    logprob,
                })
                .collect::<Vec<_>>()
        };
        let ceiling = |value: f64| Ceiling::At(Probability::try_from(value).unwrap());
        let refused = |reported: &[(&str, f64)], at: Ceiling| {
            read(&question, &candidates(reported), at).unwrap_err()
        };
        assert!(
            matches!(refused(&[], Ceiling::Unbounded), Refusal::NoLetter),
            "an empty report holds no letter"
        );
        assert!(
            matches!(
                refused(&[("Yes", -0.1_f64), ("C", -2.0_f64)], Ceiling::Unbounded),
                Refusal::NoLetter
            ),
            "a report of a word and a letter past the options holds no option letter"
        );
        for logprob in [f64::NAN, 0.5_f64, f64::INFINITY] {
            assert!(
                matches!(
                    refused(&[("A", -0.1_f64), ("B", logprob)], Ceiling::Unbounded),
                    Refusal::Endpoint(EndpointError::Logprob)
                ),
                "{logprob} is no log-probability"
            );
        }
        let half = 0.5_f64.ln();
        let wide = [("A", 0.25_f64.ln()), ("B", 0.125_f64.ln()), ("Hmm", half)];
        assert!(
            matches!(
                refused(&wide, ceiling(0.5_f64)),
                Refusal::Outside { outside, ceiling } if f64::from(outside) > 0.6_f64
                    && f64::from(ceiling) < 0.6_f64
            ),
            "outside mass of 0.625 passes a ceiling of 0.5"
        );
        assert_eq!(
            read(&question, &candidates(&wide), ceiling(0.75_f64))
                .unwrap()
                .letter()
                .to_string(),
            "A",
            "and is read under a ceiling of 0.75"
        );
        assert!(
            matches!(
                refused(&[("A", half), (" B", half)], Ceiling::Unbounded),
                Refusal::Tied
            ),
            "two options sharing the most are tied"
        );
    }
}
