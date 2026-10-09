//! Backends: what answers a judge's question about a transcript, and why an
//! answer is refused.
//!
//! A backend answers with a readout or a [`Refusal`] naming why it read none;
//! the refusal's [`Refusal::reason`] is what a verdict records, so an
//! unanswered question is recorded as unread for that reason and never as a
//! default letter. [`Static`] answers from a table keyed by the question's
//! hash and the transcript's manifest: a fixed backend for tests, and the
//! replay of rulings already recorded.

use core::str::FromStr;
use std::collections::HashMap;

use domhringr_record_evidence::ParseDigestError;
use domhringr_record_evidence::ParsedDigest;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::ParseRulingError;
use domhringr_record_tree::Probability;
use domhringr_record_tree::Readout;
use domhringr_record_tree::Ruling;
use domhringr_record_tree::Unread;
use gandr_storage_values::ManifestDigest;

use crate::question::Question;
use crate::question::TextError;
use crate::question::Transcript;

/// What answers a judge's question about a transcript.
pub trait Backend
{
    /// Ask `question` about `transcript`.
    ///
    /// # Specification
    /// - ensures: the readout of the answer: a probability per option and the
    ///   letter of the option holding the most, never a default letter.
    /// - fails: [`Refusal`] when no answer is read, naming why.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: no answer was read.
    fn ask(
        &self,
        question: &Question,
        transcript: &Transcript,
    ) -> impl Future<Output = Result<Readout, Refusal>> + Send;
}

/// Why a judge read no answer to a question.
#[derive(Debug, thiserror::Error)]
pub enum Refusal
{
    /// The reported tokens hold no option letter.
    #[error("the reported tokens hold no option letter")]
    NoLetter,
    /// The model put more mass outside the option letters than the ceiling
    /// admits.
    #[error("the model put {outside} outside the option letters, above the ceiling {ceiling}")]
    Outside
    {
        /// The mass outside the option letters.
        outside: Probability,
        /// The most the judge admits.
        ceiling: Probability,
    },
    /// Two options share the greatest probability.
    #[error("two options share the greatest probability")]
    Tied,
    /// The endpoint could not be asked, failed, or answered without a
    /// distribution over tokens.
    #[error("the endpoint did not answer")]
    Endpoint(#[source] EndpointError),
    /// The question could not be put as asked.
    #[error("the question cannot be put")]
    Malformed(#[source] MalformedError),
    /// The table records the question unread, for this reason.
    #[error("the table records the question unread: {0}")]
    Recorded(Unread),
}

impl Refusal
{
    /// The reason a verdict records for this refusal.
    ///
    /// # Specification
    /// - ensures: each refusal maps to the [`Unread`] of its name — the
    ///   endpoint's failures to [`Unread::Endpoint`], a question that cannot be
    ///   put to [`Unread::Malformed`] — and a recorded one to the reason it
    ///   records.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a refusal of each variant is mapped and compared with
    ///   its reason.
    /// - witness: `backend::tests::each_refusal_records_its_reason`
    #[inline]
    #[must_use]
    pub const fn reason(&self) -> Unread
    {
        match *self {
            | Self::NoLetter => Unread::NoLetter,
            | Self::Outside { .. } => Unread::Outside,
            | Self::Tied => Unread::Tied,
            | Self::Endpoint(_) => Unread::Endpoint,
            | Self::Malformed(_) => Unread::Malformed,
            | Self::Recorded(reason) => reason,
        }
    }
}

/// Why an endpoint gave no answer.
#[derive(Debug, thiserror::Error)]
pub enum EndpointError
{
    /// The TLS configuration cannot be built.
    #[error("cannot configure TLS")]
    Tls(#[source] std::io::Error),
    /// The HTTP client cannot be built.
    #[error("cannot build the HTTP client")]
    Client(#[source] reqwest::Error),
    /// The request cannot be encoded.
    #[error("cannot encode the request")]
    Encode(#[source] serde_json::Error),
    /// The request was not answered: no connection, or the deadline passed.
    #[error("the request was not answered")]
    Request(#[source] reqwest::Error),
    /// The endpoint answered with a failure status.
    #[error("the endpoint answered {0}")]
    Status(reqwest::StatusCode),
    /// The response's body cannot be read.
    #[error("cannot read the response")]
    Body(#[source] reqwest::Error),
    /// The response is not a chat completion.
    #[error("the response is not a chat completion")]
    Response(#[source] serde_json::Error),
    /// The response carries no distribution over tokens at the answer's
    /// position.
    #[error("the response reports no log-probabilities at the answer's position")]
    NoDistribution,
    /// A reported log-probability is NaN or above zero.
    #[error("a reported log-probability is not one")]
    Logprob,
    /// The reported distribution makes no readout.
    #[error("the reported distribution makes no readout")]
    Distribution,
}

/// Why a question could not be put as asked.
#[derive(Debug, thiserror::Error)]
pub enum MalformedError
{
    /// The transcript cannot be put to a model.
    #[error("the transcript cannot be put to a model")]
    Text(#[source] TextError),
    /// The endpoint refused the request as malformed or too large.
    #[error("the endpoint refused the request: {0}")]
    Refused(reqwest::StatusCode),
    /// The table holds no ruling for the question about the transcript.
    #[error("the table holds no ruling for the question about the transcript")]
    Unlisted,
}

/// A backend answering from a table: the ruling for each question, by its
/// hash, about each transcript, by its manifest.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Static(HashMap<(ContentHash, ManifestDigest), Ruling>);

impl FromIterator<(ContentHash, ManifestDigest, Ruling)> for Static
{
    /// A table holding each triple's ruling for its question, the hash,
    /// about its transcript, the manifest digest.
    ///
    /// # Specification
    /// - ensures: a pair of names holds the ruling of the last triple naming
    ///   it, and a pair no triple names holds none.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — through the table's text, a pair named twice holds
    ///   the later ruling.
    /// - witness: `backend::tests::a_table_answers_what_it_records`
    #[inline]
    fn from_iter<Triples>(iter: Triples) -> Self
    where
        Triples: IntoIterator<Item = (ContentHash, ManifestDigest, Ruling)>,
    {
        Self(
            iter.into_iter()
                .map(|(question, transcript, ruling)| ((question, transcript), ruling))
                .collect(),
        )
    }
}

impl FromStr for Static
{
    type Err = ParseTableError;

    /// Read a table from its text: one ruling a line, `<question>
    /// <transcript> <ruling>`, the question's hash and the transcript's
    /// manifest digest as 64 hex digits each and the ruling as [`Ruling`]
    /// writes it.
    ///
    /// # Specification
    /// - ensures: every line that is not empty contributes its triple, a later
    ///   line naming the same pair replacing an earlier one.
    /// - fails: [`ParseTableError::Form`] for a line of fewer than three
    ///   fields, [`ParseTableError::Hash`] for a question that is no hash,
    ///   [`ParseTableError::Transcript`] for a transcript that is no manifest
    ///   digest, and [`ParseTableError::Ruling`] for a ruling that does not
    ///   read, each naming its line from one.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseTableError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a table of a read ruling, an unread one, a blank line
    ///   and a replaced pair answers each recorded pair and refuses an
    ///   unrecorded one; a short line, a bad hash, a bad digest and a bad
    ///   ruling each meet their own refusal at their line.
    /// - witness: `backend::tests::a_table_answers_what_it_records`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut table = HashMap::new();
        for (line, entry) in (1_usize ..).zip(text.lines()) {
            if entry.is_empty() {
                continue;
            }
            let mut fields = entry.splitn(3, ' ');
            let (Some(question), Some(transcript), Some(ruling)) =
                (fields.next(), fields.next(), fields.next())
            else {
                return Err(ParseTableError::Form { line });
            };
            let question = question
                .parse::<ContentHash>()
                .map_err(|source| ParseTableError::Hash { line, source })?;
            let transcript = transcript
                .parse::<ParsedDigest>()
                .map_err(|source| ParseTableError::Transcript { line, source })?;
            let transcript = ManifestDigest::from(transcript);
            let ruling = ruling
                .parse::<Ruling>()
                .map_err(|source| ParseTableError::Ruling { line, source })?;
            let _replaced = table.insert((question, transcript), ruling);
        }
        Ok(Self(table))
    }
}

impl Backend for Static
{
    /// The table's ruling for `question` about `transcript`.
    ///
    /// # Specification
    /// - ensures: the readout the table records for the pair of names.
    /// - fails: [`Refusal::Recorded`] with the reason the table records for an
    ///   unread pair, and [`MalformedError::Unlisted`] for a pair the table
    ///   does not hold; the transcript's text is never read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a read pair, an unread pair and an unlisted pair are
    ///   asked about a transcript, each meeting its own outcome.
    /// - witness: `backend::tests::a_table_answers_what_it_records`
    #[inline]
    fn ask(
        &self,
        question: &Question,
        transcript: &Transcript,
    ) -> impl Future<Output = Result<Readout, Refusal>> + Send
    {
        let answered = match self.0.get(&(question.hash(), transcript.digest())) {
            | Some(&Ruling::Read(ref readout)) => Ok(readout.clone()),
            | Some(&Ruling::Unread(reason)) => Err(Refusal::Recorded(reason)),
            | None => Err(Refusal::Malformed(MalformedError::Unlisted)),
        };
        core::future::ready(answered)
    }
}

/// Why a text is not a table of rulings.
#[derive(Debug, thiserror::Error)]
pub enum ParseTableError
{
    /// A line holds fewer than three fields.
    #[error("line {line}: a ruling is `<question> <transcript> <ruling>`")]
    Form
    {
        /// The line, counted from one.
        line: usize,
    },
    /// A question is not a hash.
    #[error("line {line}: cannot read the question's hash")]
    Hash
    {
        /// The line, counted from one.
        line: usize,
        /// Why the field is no hash.
        #[source]
        source: ParseIdError,
    },
    /// A transcript is not a manifest digest.
    #[error("line {line}: cannot read the transcript's manifest digest")]
    Transcript
    {
        /// The line, counted from one.
        line: usize,
        /// Why the field is no digest.
        #[source]
        source: ParseDigestError,
    },
    /// The ruling does not read.
    #[error("line {line}: cannot read the ruling")]
    Ruling
    {
        /// The line, counted from one.
        line: usize,
        /// Why the ruling does not read.
        #[source]
        source: ParseRulingError,
    },
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;

    use domhringr_record_tree::Content;
    use domhringr_record_tree::ParseRulingError;
    use domhringr_record_tree::Probability;
    use domhringr_record_tree::Unread;

    use super::Backend as _;
    use super::EndpointError;
    use super::MalformedError;
    use super::ParseTableError;
    use super::Refusal;
    use super::Static;
    use crate::question::Question;
    use crate::question::Transcript;

    #[test]
    fn a_table_answers_what_it_records()
    {
        let ask = |last: &str| {
            Question::new(String::from("Which?"), vec![
                String::from("this"),
                String::from(last),
            ])
            .unwrap()
        };
        let (read, unread, unlisted) = (ask("that"), ask("neither"), ask("both"));
        let transcript = Transcript::held(Content::from(b"text".to_vec())).unwrap();
        let table = format!(
            "{q} {t} read A A=0.75 B=0.25 outside=0\n\n{q} {t} read B A=0.25 B=0.75 \
             outside=0.5\n{u} {t} unread tied\n",
            q = read.hash(),
            u = unread.hash(),
            t = transcript.digest(),
        );
        let table = table.parse::<Static>().unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .build()
            .unwrap();
        let readout = runtime.block_on(table.ask(&read, &transcript)).unwrap();
        assert_eq!(
            readout.to_string(),
            "B A=0.25 B=0.75 outside=0.5",
            "the later line for a pair replaces the earlier"
        );
        assert!(
            matches!(
                runtime.block_on(table.ask(&unread, &transcript)),
                Err(Refusal::Recorded(Unread::Tied))
            ),
            "an unread pair is refused for the reason it records"
        );
        assert!(
            matches!(
                runtime.block_on(table.ask(&unlisted, &transcript)),
                Err(Refusal::Malformed(MalformedError::Unlisted))
            ),
            "a pair the table does not hold is unlisted"
        );
        let hash = read.hash();
        assert!(
            matches!(
                format!("\n{hash} {hash}").parse::<Static>(),
                Err(ParseTableError::Form { line: 2 })
            ),
            "a line of two fields, counted from one"
        );
        assert!(
            matches!(
                format!("0e {hash} unread tied").parse::<Static>(),
                Err(ParseTableError::Hash { line: 1, .. })
            ),
            "a question that is no hash"
        );
        assert!(
            matches!(
                format!("{hash} 0e unread tied").parse::<Static>(),
                Err(ParseTableError::Transcript { line: 1, .. })
            ),
            "a transcript that is no manifest digest"
        );
        assert!(
            matches!(
                format!("{hash} {hash} unread asleep").parse::<Static>(),
                Err(ParseTableError::Ruling {
                    line: 1,
                    source: ParseRulingError::Reason,
                })
            ),
            "a ruling that does not read"
        );
    }

    #[test]
    fn each_refusal_records_its_reason()
    {
        let probability = Probability::try_from(0.5_f64).unwrap();
        let binary = Transcript::held(Content::from(vec![0xff]))
            .unwrap()
            .text()
            .unwrap_err();
        for (refusal, reason) in [
            (Refusal::NoLetter, Unread::NoLetter),
            (
                Refusal::Outside {
                    outside: probability,
                    ceiling: probability,
                },
                Unread::Outside,
            ),
            (Refusal::Tied, Unread::Tied),
            (Refusal::Endpoint(EndpointError::Logprob), Unread::Endpoint),
            (
                Refusal::Malformed(MalformedError::Text(binary)),
                Unread::Malformed,
            ),
            (Refusal::Recorded(Unread::Outside), Unread::Outside),
        ] {
            assert_eq!(refusal.reason(), reason, "{refusal}");
        }
    }
}
