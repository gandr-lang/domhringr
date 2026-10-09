//! Rubrics: an Opponent strategy written down — the task's state it reads,
//! the band its grades stand against, and named questions, each asked of a
//! judge as a choice between its criterion holding and failing.
//!
//! ```toml
//! name = "change-review"
//! state = ["change.diff", "README.md"]
//!
//! [band]
//! low = 0.2
//! high = 0.8
//!
//! [questions.readme-current]
//! instructions = "Read the change and the README it leaves."
//! criteria.true = "The README states what the change does."
//! criteria.false = "The README misses or misstates what the change does."
//! ```
//!
//! A rubric holds `name`, `state`, `band` and `questions`. Each state file is
//! a relative path inside the task's state directory, read into the
//! transcript in the rubric's order; the band's `low` and `high` are floats
//! from zero to one with `low` below `high`; each question is named by its
//! key and holds `instructions` and `criteria` — `true`, the criterion
//! holding, offered as `A`, and `false`, it failing, offered as `B`.
//!
//! A ruling is graded against the band by the probability the judge put on
//! `A`: met at `high` or above, unmet at `low` or below, undecided between,
//! and refused when the judge read no answer. A rubric's grades compose as
//! the conjunction of its criteria: unmet when any is unmet, whatever the
//! others; otherwise refused when any is refused; otherwise undecided when
//! any is undecided; otherwise met. A refused question is never read as met
//! or unmet.

use alloc::collections::BTreeMap;
use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use std::path::Path;

use domhringr_judge_oracle::Question;
use domhringr_judge_oracle::Transcript;
use domhringr_record_tree::Content;
use domhringr_record_tree::Grade;
use domhringr_record_tree::Probability;
use domhringr_record_tree::Ruling;

use crate::document::Key;
use crate::document::Keys;
use crate::document::Name;
use crate::document::Reason;
use crate::document::Refusal;
use crate::document::Value;

/// A rubric: its name, the state it reads, its band and its questions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Rubric
{
    /// What the rubric is called.
    name: Name,
    /// The state files the transcript holds, in order, at least one.
    state: Vec<StateFile>,
    /// The band grades stand against.
    band: Band,
    /// The questions by name, at least one.
    questions: BTreeMap<Name, Question>,
}

impl Rubric
{
    /// What the rubric is called.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &Name
    {
        &self.name
    }

    /// The state files the transcript holds, in order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn state(&self) -> &[StateFile]
    {
        &self.state
    }

    /// The band grades stand against.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn band(&self) -> Band
    {
        self.band
    }

    /// The questions by name, in the names' order: the order a whole rubric
    /// is asked in.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn questions(&self) -> &BTreeMap<Name, Question>
    {
        &self.questions
    }

    /// The transcript the questions are asked about: each state file of the
    /// task's state `directory`, in the rubric's order.
    ///
    /// # Specification
    /// - ensures: the transcript holds, per state file in order, the line
    ///   `<state name="<file>">`, the file's bytes, a newline when they do not
    ///   end in one, and the line `</state>`.
    /// - fails: [`StateError`] naming the first state file that cannot be read.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StateError`]: a state file cannot be read.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a transcript of two state files, one without a final
    ///   newline, is compared byte for byte with the text written by hand, and
    ///   a missing state file is refused by name.
    /// - witness: `rubric::tests::a_transcript_holds_each_state_file_in_order`
    #[inline]
    pub fn transcript(
        &self,
        directory: &Path,
    ) -> Result<Transcript, StateError>
    {
        let mut held = Vec::new();
        for file in &self.state {
            let bytes = std::fs::read(directory.join(&file.0)).map_err(|source| StateError {
                file: file.clone(),
                source,
            })?;
            held.extend_from_slice(br#"<state name=""#);
            held.extend_from_slice(file.0.as_bytes());
            held.extend_from_slice(b"\">\n");
            held.extend_from_slice(&bytes);
            if !bytes.is_empty() && !bytes.ends_with(b"\n") {
                held.push(b'\n');
            }
            held.extend_from_slice(b"</state>\n");
        }
        Ok(Transcript::held(Content::from(held)))
    }
}

impl FromStr for Rubric
{
    type Err = Refusal;

    /// Read a rubric from its TOML text.
    ///
    /// # Specification
    /// - ensures: the rubric the text writes, its state files in order and each
    ///   question asking its instructions with the options `true` then `false`.
    /// - fails: the first refusal that holds, reading the document from the top
    ///   and a table's fields in the order the module states: a text that is
    ///   not TOML ([`Reason::Syntax`]); in each table, an unknown field
    ///   ([`Reason::Unknown`]) before any other; a missing field
    ///   ([`Reason::Missing`]), a value of another type ([`Reason::Type`]), a
    ///   name [`Name`] refuses ([`Reason::Identifier`]), a state file
    ///   [`StateFile`] refuses ([`Reason::StateFile`]), a bound that is no
    ///   probability ([`Reason::Probability`]), an empty text
    ///   ([`Reason::Empty`]), a question the judge cannot ask
    ///   ([`Reason::Question`]) at its `criteria`; a band whose low bound is
    ///   not below its high one ([`Reason::Inverted`]) at `band`; and no state
    ///   files or no questions ([`Reason::Empty`]) at `state` or `questions`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: as listed above, naming the field it is about.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a rubric of two state files and two questions reads
    ///   back field for field, its questions in their names' order; and each
    ///   refusal is met by a text that differs from a valid one in the one
    ///   place it names, among them an unknown field, missing criteria, an
    ///   inverted and an equal band, and a criterion of two lines.
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut document =
            Value::try_from(text)?.table(Keys(&["name", "state", "band", "questions"]))?;
        let name = document
            .require(Key("name"))?
            .parsed::<Name>(Reason::Identifier)?;
        let listed = document.require(Key("state"))?;
        let field = listed.field().clone();
        let mut state = Vec::new();
        for file in listed.array()? {
            state.push(file.parsed::<StateFile>(Reason::StateFile)?);
        }
        if state.is_empty() {
            return Err(field.refused(Reason::Empty));
        }
        let band = Band::read(document.require(Key("band"))?)?;
        let listed = document.require(Key("questions"))?;
        let field = listed.field().clone();
        let mut questions = BTreeMap::new();
        for (name, value) in listed.named::<Name>(Reason::Identifier)? {
            let mut table = value.table(Keys(&["instructions", "criteria"]))?;
            let instructions = table.require(Key("instructions"))?.filled()?;
            let criteria = table.require(Key("criteria"))?;
            let at = criteria.field().clone();
            let mut criteria = criteria.table(Keys(&["true", "false"]))?;
            let holds = criteria.require(Key("true"))?.filled()?;
            let fails = criteria.require(Key("false"))?.filled()?;
            let question = Question::new(instructions, vec![holds, fails])
                .map_err(|error| at.refused(Reason::Question(error)))?;
            let _unique = questions.insert(name, question);
        }
        if questions.is_empty() {
            return Err(field.refused(Reason::Empty));
        }
        Ok(Self {
            name,
            state,
            band,
            questions,
        })
    }
}

/// Where a rubric's grades stand: the probability on a criterion holding at
/// or below which it is unmet, and at or above which it is met.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Band
{
    /// At or below: unmet.
    low: Probability,
    /// At or above: met.
    high: Probability,
}

impl Band
{
    /// Read a band from its table.
    ///
    /// # Specification
    /// - ensures: the band of the table's `low` and `high`.
    /// - fails: an unknown field, then a missing `low` or `high`, one that is
    ///   no float or no probability, then [`Reason::Inverted`] at the band when
    ///   `low` is not below `high`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: the table is no band.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the rubric's parser.
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    fn read(value: Value<'_>) -> Result<Self, Refusal>
    {
        let mut table = value.table(Keys(&["low", "high"]))?;
        let low = table.require(Key("low"))?.probability()?;
        let high = table.require(Key("high"))?.probability()?;
        if low >= high {
            return Err(table.field().clone().refused(Reason::Inverted));
        }
        Ok(Self { low, high })
    }

    /// At or below this, a criterion is unmet.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn low(&self) -> Probability
    {
        self.low
    }

    /// At or above this, a criterion is met.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn high(&self) -> Probability
    {
        self.high
    }

    /// Grade `ruling` against the band.
    ///
    /// # Specification
    /// - ensures: a read ruling is [`Grade::Met`] when the probability on `A`,
    ///   the criterion holding, is at or above the high bound, [`Grade::Unmet`]
    ///   when it is at or below the low bound, and [`Grade::Undecided`]
    ///   strictly between; an unread ruling is [`Grade::Refused`].
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a band of `0.25` and `0.75` grades readouts on `A` of
    ///   1, 0.75, 0.7, 0.5, 0.3, 0.25 and 0, and an unread ruling, at each
    ///   position.
    /// - witness: `rubric::tests::a_ruling_is_graded_at_each_band_position`
    #[inline]
    #[must_use]
    pub fn grade(
        self,
        ruling: &Ruling,
    ) -> Grade
    {
        let Ruling::Read(ref readout) = *ruling
        else {
            return Grade::Refused;
        };
        // A readout holds two options at least, so `A` is always there; one
        // without it would be no reading of the criterion, as unread is.
        let Some((_letter, holds)) = readout.probabilities().next()
        else {
            return Grade::Refused;
        };
        if holds >= self.high {
            Grade::Met
        }
        else if holds <= self.low {
            Grade::Unmet
        }
        else {
            Grade::Undecided
        }
    }
}

/// Compose a rubric's grades: the conjunction of its criteria.
///
/// # Specification
/// - ensures: [`Grade::Unmet`] when any grade is unmet; otherwise
///   [`Grade::Refused`] when any is refused; otherwise [`Grade::Undecided`]
///   when any is undecided; otherwise [`Grade::Met`], the empty composition
///   among them.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — all met, met with undecided, met with refused, and unmet
///   beside each of met, undecided and refused compose to their outcome,
///   whatever the order, and no grades compose to met.
/// - witness: `rubric::tests::grades_compose_as_the_conjunction_of_their_criteria`
#[inline]
#[must_use]
pub fn compose(grades: &[Grade]) -> Grade
{
    if grades.contains(&Grade::Unmet) {
        Grade::Unmet
    }
    else if grades.contains(&Grade::Refused) {
        Grade::Refused
    }
    else if grades.contains(&Grade::Undecided) {
        Grade::Undecided
    }
    else {
        Grade::Met
    }
}

/// A file a rubric reads from the task's state directory: a relative path of
/// segments joined by `/`, each of ASCII letters, digits, `.`, `_` and `-`,
/// none empty, `.` or `..`.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct StateFile(String);

impl FromStr for StateFile
{
    type Err = ParseStateFileError;

    /// Read a state file from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the paths this type admits, kept as written.
    /// - fails: [`ParseStateFileError::Segment`] for an empty segment — the
    ///   empty text, a leading, trailing or doubled `/` among them — or a
    ///   segment `.` or `..`, then [`ParseStateFileError::Character`] for any
    ///   other character.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseStateFileError::Segment`]: a segment is empty, `.` or `..`.
    /// - [`ParseStateFileError::Character`]: a character is not admitted.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a file and a nested file read back as written, and an
    ///   absolute path, a parent segment and a space are each refused at their
    ///   field.
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        for segment in text.split('/') {
            if matches!(segment, "" | "." | "..") {
                return Err(ParseStateFileError::Segment);
            }
            if !segment
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
            {
                return Err(ParseStateFileError::Character);
            }
        }
        Ok(Self(text.into()))
    }
}

impl fmt::Display for StateFile
{
    /// Write the path as written.
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

/// Why a text is not a state file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseStateFileError
{
    /// A segment is empty, `.` or `..`.
    #[error("a state file is a relative path inside the state directory")]
    Segment,
    /// A character is not one a state file holds.
    #[error("a state file's segments hold ASCII letters, digits, '.', '_' and '-' alone")]
    Character,
}

/// A state file that cannot be read into a transcript.
#[derive(Debug, thiserror::Error)]
#[error("cannot read the state file {file}")]
pub struct StateError
{
    /// The state file.
    file: StateFile,
    /// Why it cannot be read.
    #[source]
    source: std::io::Error,
}

#[cfg(test)]
mod tests
{
    use domhringr_judge_oracle::Question;
    use domhringr_judge_oracle::Transcript;
    use domhringr_record_tree::Content;
    use domhringr_record_tree::Grade;
    use domhringr_record_tree::Probability;
    use domhringr_record_tree::Readout;
    use domhringr_record_tree::Ruling;
    use domhringr_record_tree::Unread;

    use super::Rubric;
    use super::compose;

    /// A valid rubric of two state files and two questions.
    const RUBRIC: &str = r#"
name = "change-review"
state = ["change.diff", "docs/README.md"]

[band]
low = 0.25
high = 0.75

[questions.scoped]
instructions = "Read the change."
criteria.true = "The change does one thing."
criteria.false = "The change does several things."

[questions.dense]
instructions = "Read the README."
criteria = { true = "The README is dense.", false = "The README is padded." }
"#;

    #[test]
    fn a_rubric_reads_its_state_band_and_questions()
    {
        let rubric = RUBRIC.parse::<Rubric>().unwrap();
        assert_eq!(rubric.name().to_string(), "change-review");
        assert_eq!(
            rubric
                .state()
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>(),
            ["change.diff", "docs/README.md"],
            "the state files in order"
        );
        let probability = |value: f64| Probability::try_from(value).unwrap();
        assert_eq!(
            (rubric.band().low(), rubric.band().high()),
            (probability(0.25_f64), probability(0.75_f64)),
            "the band's bounds"
        );
        let asked = |text: &str, holds: &str, fails: &str| {
            Question::new(text.into(), vec![holds.into(), fails.into()]).unwrap()
        };
        assert_eq!(
            rubric
                .questions()
                .iter()
                .map(|(name, question)| (name.to_string(), question.clone()))
                .collect::<Vec<_>>(),
            [
                (
                    "dense".to_owned(),
                    asked(
                        "Read the README.",
                        "The README is dense.",
                        "The README is padded."
                    )
                ),
                (
                    "scoped".to_owned(),
                    asked(
                        "Read the change.",
                        "The change does one thing.",
                        "The change does several things."
                    )
                ),
            ],
            "each question asks its instructions, true as A and false as B, in the names' order"
        );
    }

    #[test]
    fn a_malformed_rubric_is_refused_at_its_field()
    {
        let rubric = |state: &str, band: &str, question: &str| {
            format!("name = \"r\"\nstate = {state}\n[band]\n{band}\n[questions.q]\n{question}\n")
        };
        let state = "[\"a\"]";
        let band = "low = 0.25\nhigh = 0.75";
        let question = "instructions = \"i\"\ncriteria = { true = \"t\", false = \"f\" }";
        assert!(
            rubric(state, band, question).parse::<Rubric>().is_ok(),
            "the rubric the cases vary is valid"
        );
        let cases = [
            (
                rubric(state, band, &format!("{question}\nweight = 2")),
                "questions.q.weight: unknown field",
            ),
            (
                rubric(state, band, "instructions = \"i\""),
                "questions.q.criteria: missing field",
            ),
            (
                rubric(state, band, "instructions = \"i\"\ncriterion = 1"),
                "questions.q.criterion: unknown field",
            ),
            (
                rubric(
                    state,
                    band,
                    "instructions = \"i\"\ncriteria = { true = \"t\" }",
                ),
                "questions.q.criteria.false: missing field",
            ),
            (
                rubric(
                    state,
                    band,
                    "instructions = \"i\"\ncriteria = { true = \"\", false = \"f\" }",
                ),
                "questions.q.criteria.true: empty",
            ),
            (
                rubric(
                    state,
                    band,
                    "instructions = \"i\"\ncriteria = { true = \"t\\nu\", false = \"f\" }",
                ),
                "questions.q.criteria: an option is one line",
            ),
            (
                rubric(state, "low = 0.75\nhigh = 0.25", question),
                "band: the band's low bound is not below its high bound",
            ),
            (
                rubric(state, "low = 0.5\nhigh = 0.5", question),
                "band: the band's low bound is not below its high bound",
            ),
            (
                rubric(state, "low = 0\nhigh = 0.75", question),
                "band.low: expected a float",
            ),
            (
                rubric(state, "low = 0.25\nhigh = 1.5", question),
                "band.high: a probability is a number from 0 to 1",
            ),
            (
                rubric(state, "low = nan\nhigh = 0.75", question),
                "band.low: a probability is a number from 0 to 1",
            ),
            (
                rubric(state, "low = 0.25", question),
                "band.high: missing field",
            ),
            (
                rubric(state, "low = 0.25\nhigh = 0.75\nmid = 0.5", question),
                "band.mid: unknown field",
            ),
            (rubric("[]", band, question), "state: empty"),
            (
                rubric("[\"/etc/passwd\"]", band, question),
                "state[0]: a state file is a relative path inside the state directory",
            ),
            (
                rubric("[\"a\", \"../b\"]", band, question),
                "state[1]: a state file is a relative path inside the state directory",
            ),
            (
                rubric("[\"a b\"]", band, question),
                "state[0]: a state file's segments hold",
            ),
            (
                "name = \"r\"\nstate = [\"a\"]\nquestions = {}\n[band]\nlow = 0.25\nhigh = 0.75\n"
                    .to_owned(),
                "questions: empty",
            ),
            (
                format!(
                    "name = \"r\"\nstate = [\"a\"]\n[band]\n{band}\n[questions.Q]\n{question}\n"
                ),
                "questions.Q: an identifier begins with a lowercase ASCII letter",
            ),
            (
                format!("name = \"r\"\nstate = [\"a\"]\n[band]\n{band}\n[questions]\nq = 1\n"),
                "questions.q: expected a table",
            ),
        ];
        for (text, refusal) in cases {
            let refused = text.parse::<Rubric>().unwrap_err().to_string();
            assert!(
                refused.starts_with(refusal),
                "{text:?} is refused as {refusal:?}, not {refused:?}"
            );
        }
    }

    #[test]
    fn a_ruling_is_graded_at_each_band_position()
    {
        let band = RUBRIC.parse::<Rubric>().unwrap().band();
        let probability = |value: f64| Probability::try_from(value).unwrap();
        let read = |holds: f64, fails: f64| {
            let readout = Readout::new(
                vec![probability(holds), probability(fails)],
                probability(0.0_f64),
            )
            .unwrap();
            Ruling::Read(readout)
        };
        for (holds, fails, grade, position) in [
            (1.0_f64, 0.0_f64, Grade::Met, "certain"),
            (0.75_f64, 0.25_f64, Grade::Met, "at the high bound"),
            (
                0.7_f64,
                0.3_f64,
                Grade::Undecided,
                "just below the high bound",
            ),
            (
                0.3_f64,
                0.7_f64,
                Grade::Undecided,
                "just above the low bound",
            ),
            (0.25_f64, 0.75_f64, Grade::Unmet, "at the low bound"),
            (0.0_f64, 1.0_f64, Grade::Unmet, "certainly not"),
        ] {
            assert_eq!(band.grade(&read(holds, fails)), grade, "{position}");
        }
        assert_eq!(
            band.grade(&Ruling::Unread(Unread::Tied)),
            Grade::Refused,
            "an unread ruling is refused, never graded"
        );
    }

    #[test]
    fn grades_compose_as_the_conjunction_of_their_criteria()
    {
        use Grade::Met;
        use Grade::Refused;
        use Grade::Undecided;
        use Grade::Unmet;
        for (grades, composed) in [
            (&[][..], Met),
            (&[Met, Met][..], Met),
            (&[Met, Undecided][..], Undecided),
            (&[Refused, Met][..], Refused),
            (&[Undecided, Refused][..], Refused),
            (&[Met, Unmet][..], Unmet),
            (&[Unmet, Undecided][..], Unmet),
            (&[Refused, Unmet][..], Unmet),
        ] {
            assert_eq!(compose(grades), composed, "{grades:?}");
        }
    }

    #[test]
    fn a_transcript_holds_each_state_file_in_order()
    {
        let state = tempfile::tempdir().unwrap();
        std::fs::write(state.path().join("change.diff"), "+ one\n- two\n").unwrap();
        std::fs::create_dir_all(state.path().join("docs")).unwrap();
        std::fs::write(state.path().join("docs/README.md"), "# Dense").unwrap();
        let rubric = RUBRIC.parse::<Rubric>().unwrap();
        let transcript = rubric.transcript(state.path()).unwrap();
        let written = "<state name=\"change.diff\">\n+ one\n- two\n</state>\n<state \
                       name=\"docs/README.md\">\n# Dense\n</state>\n";
        assert_eq!(
            transcript.hash(),
            Transcript::held(Content::from(written.as_bytes().to_vec())).hash(),
            "each state file in the rubric's order, a final newline added where missing"
        );
        std::fs::remove_file(state.path().join("change.diff")).unwrap();
        assert_eq!(
            rubric.transcript(state.path()).unwrap_err().to_string(),
            "cannot read the state file change.diff",
            "a missing state file is refused by name"
        );
    }
}
