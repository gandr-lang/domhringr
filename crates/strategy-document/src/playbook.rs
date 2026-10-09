//! Playbooks: a Player strategy written down — named steps, each saying why
//! it is there and bound to the check that answers it: a verifier, a program
//! run on the task's state, or a question of a rubric, asked of a judge.
//!
//! ```toml
//! name = "change-review"
//!
//! [[steps]]
//! id = "gates"
//! why = "Every gate passes on the change."
//! verifier = { command = "mise", args = ["run", "check"] }
//!
//! [[steps]]
//! id = "readme"
//! why = "The README states what the change does."
//! question = { rubric = "change-review.rubric.toml", question = "readme-current" }
//! ```
//!
//! A playbook holds `name` and `steps`, and a step `id`, `why` and exactly
//! one of `verifier` — `command` and optional `args` — and `question` —
//! `rubric`, the rubric file relative to the playbook's directory, and
//! `question`, a question that rubric names. Steps run in their order; no two
//! share an identifier.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::str::FromStr;
use std::path::Path;
use std::path::PathBuf;

use domhringr_record_tree::StepId;

use crate::document::Key;
use crate::document::Keys;
use crate::document::Name;
use crate::document::Reason;
use crate::document::Refusal;
use crate::document::Segment;
use crate::document::Slot;
use crate::document::Value;
use crate::verify::Verifier;

/// A playbook: its name and its steps, in the order they run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Playbook
{
    /// What the playbook is called.
    name: Name,
    /// Its steps, in order, at least one.
    steps: Vec<Step>,
}

impl Playbook
{
    /// What the playbook is called.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn name(&self) -> &Name
    {
        &self.name
    }

    /// The steps, in the order they run.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn steps(&self) -> &[Step]
    {
        &self.steps
    }
}

impl FromStr for Playbook
{
    type Err = Refusal;

    /// Read a playbook from its TOML text.
    ///
    /// # Specification
    /// - ensures: the playbook the text writes, its steps in order, each bound
    ///   as it says: a verifier with its arguments in order, none when `args`
    ///   is absent, or a rubric's question.
    /// - fails: the first refusal that holds, reading the document from the top
    ///   and a table's fields in the order the module states: a text that is
    ///   not TOML ([`Reason::Syntax`]); in each table, an unknown field
    ///   ([`Reason::Unknown`]) before any other; a missing field
    ///   ([`Reason::Missing`]), a value of another type ([`Reason::Type`]), a
    ///   name or an identifier [`StepId`] refuses ([`Reason::Identifier`]), an
    ///   empty `why` or `command` ([`Reason::Empty`]), a rubric file that is no
    ///   relative path ([`Reason::RubricFile`]); a step bound to neither
    ///   ([`Reason::Unbound`]) or to both ([`Reason::Ambiguous`]) at the step;
    ///   a step sharing an earlier step's identifier ([`Reason::Duplicate`]) at
    ///   its `id`; and no steps at all ([`Reason::Empty`]) at `steps`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: as listed above, naming the field it is about.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook of a verifier with and without arguments
    ///   and a question reads back field for field; and each refusal is met by
    ///   a text that differs from a valid one in the one place it names, among
    ///   them an unknown field beside a missing one, a step bound to both and
    ///   to neither, a duplicate identifier, a step that is no table, and a
    ///   text that is not TOML.
    /// - witness: `playbook::tests::a_playbook_reads_its_steps_in_order`
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut document = Value::try_from(text)?.table(Keys(&["name", "steps"]))?;
        let name = document
            .require(Key("name"))?
            .parsed::<Name>(Reason::Identifier)?;
        let listed = document.require(Key("steps"))?;
        let field = listed.field().clone();
        let mut steps: Vec<Step> = Vec::new();
        for value in listed.array()? {
            let id = value.field().then(Segment::from("id"));
            let step = Step::read(value)?;
            if steps.iter().any(|earlier| earlier.id == step.id) {
                return Err(id.refused(Reason::Duplicate));
            }
            steps.push(step);
        }
        if steps.is_empty() {
            return Err(field.refused(Reason::Empty));
        }
        Ok(Self { name, steps })
    }
}

/// One step of a playbook.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Step
{
    /// The step's identifier, unique in its playbook.
    id: StepId,
    /// Why the step is there: what passing it shows.
    why: String,
    /// The check that answers it.
    bound: Bound,
}

impl Step
{
    /// Read one step from its table.
    ///
    /// # Specification
    /// - ensures: the step the table writes.
    /// - fails: as [`Playbook`]'s parser states for a step.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Refusal`]: the table is no step.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — witnessed through the playbook's parser.
    /// - witness: `playbook::tests::a_playbook_reads_its_steps_in_order`
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    fn read(value: Value<'_>) -> Result<Self, Refusal>
    {
        let mut table = value.table(Keys(&["id", "why", "verifier", "question"]))?;
        let id = table
            .require(Key("id"))?
            .parsed::<StepId>(Reason::Identifier)?;
        let why = table.require(Key("why"))?.filled()?;
        let bound = match (table.take(Key("verifier")), table.take(Key("question"))) {
            | (Slot::Given(verifier), Slot::Absent) => Bound::Verifier(Verifier::read(verifier)?),
            | (Slot::Absent, Slot::Given(question)) => {
                let mut question = question.table(Keys(&["rubric", "question"]))?;
                let rubric = question
                    .require(Key("rubric"))?
                    .parsed::<RubricFile>(Reason::RubricFile)?;
                let question = question
                    .require(Key("question"))?
                    .parsed::<Name>(Reason::Identifier)?;
                Bound::Question { rubric, question }
            },
            | (Slot::Given(_), Slot::Given(_)) => {
                return Err(table.field().clone().refused(Reason::Ambiguous));
            },
            | (Slot::Absent, Slot::Absent) => {
                return Err(table.field().clone().refused(Reason::Unbound));
            },
        };
        Ok(Self { id, why, bound })
    }

    /// The step's identifier.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn id(&self) -> &StepId
    {
        &self.id
    }

    /// Why the step is there.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn why(&self) -> &String
    {
        &self.why
    }

    /// The check that answers the step.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn bound(&self) -> &Bound
    {
        &self.bound
    }
}

/// What answers a step.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Bound
{
    /// A program run on the task's state: its status and output answer.
    Verifier(Verifier),
    /// A rubric's question, asked of a judge: its grade answers.
    Question
    {
        /// The rubric's file, relative to the playbook's directory.
        rubric: RubricFile,
        /// The question, by its name in the rubric.
        question: Name,
    },
}

/// A rubric's file as a playbook names it: a relative path, resolved
/// against the playbook's own directory.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct RubricFile(PathBuf);

impl RubricFile
{
    /// The rubric's file for a playbook in `directory`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn beside(
        &self,
        directory: &Path,
    ) -> PathBuf
    {
        directory.join(&self.0)
    }
}

impl FromStr for RubricFile
{
    type Err = ParseRubricFileError;

    /// Read a rubric file from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the non-empty relative paths, kept as
    ///   written.
    /// - fails: [`ParseRubricFileError::Empty`] for the empty text, then
    ///   [`ParseRubricFileError::Absolute`] for a path that is not relative.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseRubricFileError::Empty`]: the text is empty.
    /// - [`ParseRubricFileError::Absolute`]: the path is not relative.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a rubric beside the playbook and one in a sibling
    ///   directory are resolved against the playbook's directory, and an
    ///   absolute rubric path is refused at its field.
    /// - witness: `load::tests::a_plan_reads_its_rubrics_beside_its_playbook`
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.is_empty() {
            return Err(ParseRubricFileError::Empty);
        }
        let path = PathBuf::from(text);
        if !path.is_relative() {
            return Err(ParseRubricFileError::Absolute);
        }
        Ok(Self(path))
    }
}

impl fmt::Display for RubricFile
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
        fmt::Display::fmt(&self.0.display(), f)
    }
}

/// Why a text is not a rubric file.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ParseRubricFileError
{
    /// The text is empty.
    #[error("a rubric file is a path, not empty")]
    Empty,
    /// The path is not relative.
    #[error("a rubric file is relative to the playbook's directory")]
    Absolute,
}

#[cfg(test)]
mod tests
{
    use super::Bound;
    use super::Playbook;
    use crate::document::Reason;

    /// A valid playbook: a verifier with arguments, one without, and a
    /// question.
    const PLAYBOOK: &str = r#"
name = "change-review"

[[steps]]
id = "tests"
why = "Every test passes."
verifier = { command = "cargo", args = ["test", "", "--workspace"] }

[[steps]]
id = "clean"
why = "The tree is clean."
verifier = { command = "true" }

[[steps]]
id = "readme"
why = "The README states the change."
question = { rubric = "../rubrics/change.toml", question = "readme-current" }
"#;

    #[test]
    fn a_playbook_reads_its_steps_in_order()
    {
        let playbook = PLAYBOOK.parse::<Playbook>().unwrap();
        assert_eq!(playbook.name().to_string(), "change-review");
        let read = playbook
            .steps()
            .iter()
            .map(|step| {
                let bound = match *step.bound() {
                    | Bound::Verifier(ref verifier) => {
                        format!("{} {:?}", verifier.command(), verifier.arguments())
                    },
                    | Bound::Question {
                        ref rubric,
                        ref question,
                    } => format!("{rubric} {question}"),
                };
                format!("{} {} {bound}", step.id(), step.why())
            })
            .collect::<Vec<_>>();
        assert_eq!(
            read,
            [
                r#"tests Every test passes. cargo ["test", "", "--workspace"]"#,
                "clean The tree is clean. true []",
                "readme The README states the change. ../rubrics/change.toml readme-current",
            ],
            "each step reads back in order, an empty argument kept and absent arguments none"
        );
    }

    #[test]
    fn a_malformed_playbook_is_refused_at_its_field()
    {
        let step = |body: &str| format!("name = \"p\"\n[[steps]]\n{body}\n");
        let verifier = r#"verifier = { command = "true" }"#;
        let cases = [
            (
                "name = \"p\"\n[[steps\n".to_owned(),
                "not TOML at line 2, column 8",
            ),
            (
                format!(
                    "title = 1\n{}",
                    step(&format!("id = \"a\"\nwhy = \"w\"\n{verifier}"))
                ),
                "title: unknown field",
            ),
            (
                step(&format!("id = \"a\"\nwhy = \"w\"\ncheck = 1\n{verifier}")),
                "steps[0].check: unknown field",
            ),
            (
                step("id = \"a\"\nwhy = \"w\"\ncheck = 1"),
                "steps[0].check: unknown field",
            ),
            ("[[steps]]\nid = \"a\"\n".to_owned(), "name: missing field"),
            ("name = \"p\"\n".to_owned(), "steps: missing field"),
            ("name = \"p\"\nsteps = []\n".to_owned(), "steps: empty"),
            (
                "name = \"p\"\nsteps = \"a\"\n".to_owned(),
                "steps: expected an array",
            ),
            (
                "name = \"p\"\nsteps = [1]\n".to_owned(),
                "steps[0]: expected a table",
            ),
            (
                step(&format!("id = \"a\"\n{verifier}")),
                "steps[0].why: missing field",
            ),
            (
                step(&format!("id = \"a\"\nwhy = 1\n{verifier}")),
                "steps[0].why: expected a string",
            ),
            (
                step(&format!("id = \"a\"\nwhy = \"\"\n{verifier}")),
                "steps[0].why: empty",
            ),
            (
                step(&format!("id = \"A\"\nwhy = \"w\"\n{verifier}")),
                "steps[0].id: an identifier begins with a lowercase ASCII letter",
            ),
            (
                "name = \"P\"\n".to_owned(),
                "name: an identifier begins with a lowercase ASCII letter",
            ),
            (
                step("id = \"a\"\nwhy = \"w\""),
                "steps[0]: a step is bound to a verifier or a question",
            ),
            (
                step(&format!(
                    "id = \"a\"\nwhy = \"w\"\n{verifier}\nquestion = {{ rubric = \"r.toml\", question = \"q\" }}"
                )),
                "steps[0]: a step is bound to a verifier or a question, not both",
            ),
            (
                step("id = \"a\"\nwhy = \"w\"\nverifier = { command = \"\" }"),
                "steps[0].verifier.command: empty",
            ),
            (
                step("id = \"a\"\nwhy = \"w\"\nverifier = { args = [] }"),
                "steps[0].verifier.command: missing field",
            ),
            (
                step("id = \"a\"\nwhy = \"w\"\nverifier = { command = \"c\", args = [1] }"),
                "steps[0].verifier.args[0]: expected a string",
            ),
            (
                step(
                    "id = \"a\"\nwhy = \"w\"\nquestion = { rubric = \"/r.toml\", question = \"q\" }",
                ),
                "steps[0].question.rubric: a rubric file is relative to the playbook's directory",
            ),
            (
                step("id = \"a\"\nwhy = \"w\"\nquestion = { rubric = \"r.toml\" }"),
                "steps[0].question.question: missing field",
            ),
            (
                format!(
                    "{}[[steps]]\nid = \"b\"\nwhy = \"w\"\n{verifier}\n[[steps]]\nid = \"a\"\nwhy = \"w\"\n{verifier}\n",
                    step(&format!("id = \"a\"\nwhy = \"w\"\n{verifier}"))
                ),
                "steps[2].id: another step has this identifier",
            ),
            (
                "name = \"p\"\n[[steps]]\n\"a b\" = 1\n".to_owned(),
                "steps[0].\"a b\": unknown field",
            ),
        ];
        for (text, refusal) in cases {
            let refused = text.parse::<Playbook>().unwrap_err().to_string();
            assert!(
                refused.starts_with(refusal),
                "{text:?} is refused as {refusal:?}, not {refused:?}"
            );
        }
        let refused = "name = \"p\"\n[[steps\n".parse::<Playbook>().unwrap_err();
        assert!(
            matches!(refused.reason(), Reason::Syntax(_)),
            "a text that is not TOML is refused at the root"
        );
        assert_eq!(
            refused.field().to_string(),
            "",
            "the root is written as nothing"
        );
    }
}
