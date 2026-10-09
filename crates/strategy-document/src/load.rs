//! Loading: a document read from its file and named by the hash of the
//! file's bytes ([`Loaded`]), and a playbook read with every rubric its
//! question steps name ([`Plan`]).
//!
//! A document's hash is the BLAKE3 hash of its file's bytes, as a record
//! names any content: a verification names its playbook by it, a verdict its
//! rubric. A playbook names a rubric by its path relative to the playbook's
//! own directory; the plan reads each rubric once, however many steps name
//! it, and refuses a step naming a question its rubric does not hold.

use alloc::collections::BTreeMap;
use alloc::collections::btree_map::Entry;
use alloc::vec::Vec;
use core::str::FromStr;
use core::str::Utf8Error;
use std::path::Path;
use std::path::PathBuf;

use domhringr_judge_oracle::Question;
use domhringr_record_tree::Content;
use domhringr_record_tree::ContentHash;

use crate::document::Field;
use crate::document::Name;
use crate::document::Reason;
use crate::document::Refusal;
use crate::document::Segment;
use crate::playbook::Bound;
use crate::playbook::Playbook;
use crate::playbook::RubricFile;
use crate::rubric::Rubric;

/// A document as read from its file: the hash of the file's bytes, and the
/// document they hold.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Loaded<Document>
{
    /// The BLAKE3 hash of the file's bytes.
    hash: ContentHash,
    /// The document.
    document: Document,
}

impl<Document> Loaded<Document>
where
    Document: FromStr<Err = Refusal>,
{
    /// Read the document `file` holds.
    ///
    /// # Specification
    /// - ensures: the document the file's text reads as, named by the hash of
    ///   the file's bytes.
    /// - fails: [`LoadError::Read`] when the file cannot be read,
    ///   [`LoadError::Encoding`] when it is not UTF-8, and
    ///   [`LoadError::Refused`] when its text is not the document, each naming
    ///   the file.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`LoadError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook and its rubrics are read and named by the
    ///   hashes of their bytes; a missing rubric file and a playbook that is
    ///   not UTF-8 are refused naming their files.
    /// - witness: `load::tests::a_plan_reads_its_rubrics_beside_its_playbook`
    #[inline]
    pub fn read(file: &Path) -> Result<Self, LoadError>
    {
        let bytes = std::fs::read(file).map_err(|source| LoadError::Read {
            file: file.to_path_buf(),
            source,
        })?;
        let text = core::str::from_utf8(&bytes).map_err(|source| LoadError::Encoding {
            file: file.to_path_buf(),
            source,
        })?;
        let document = text
            .parse::<Document>()
            .map_err(|refusal| LoadError::Refused {
                file: file.to_path_buf(),
                refusal,
            })?;
        Ok(Self {
            hash: ContentHash::of(&Content::from(bytes)),
            document,
        })
    }
}

impl<Document> Loaded<Document>
{
    /// The BLAKE3 hash of the file's bytes.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn hash(&self) -> ContentHash
    {
        self.hash
    }

    /// The document.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn document(&self) -> &Document
    {
        &self.document
    }
}

/// A playbook read from its file, with every rubric its question steps name.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Plan
{
    /// The playbook.
    playbook: Loaded<Playbook>,
    /// Each rubric a step names, by the file the step names it by.
    rubrics: BTreeMap<RubricFile, Loaded<Rubric>>,
}

impl Plan
{
    /// Read the playbook `file` holds and each rubric its steps name.
    ///
    /// # Specification
    /// - ensures: the playbook, and each rubric its question steps name, read
    ///   once from the step's rubric file beside the playbook's directory.
    /// - fails: as [`Loaded::read`] fails for the playbook, then step by step
    ///   for each rubric file first named, and [`LoadError::Refused`] naming
    ///   the playbook with [`Reason::NoQuestion`] at the step's
    ///   `question.question` for a question its rubric does not hold.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`LoadError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook naming a rubric beside it twice and one in
    ///   a sibling directory reads each once by the hash of its bytes; a step
    ///   naming a question its rubric lacks, a missing rubric file and a rubric
    ///   that is no rubric are each refused naming the file at fault; and the
    ///   examples shipped with the repository read.
    /// - witness: `load::tests::a_plan_reads_its_rubrics_beside_its_playbook`
    /// - witness: `load::tests::the_example_playbook_and_rubric_read`
    #[inline]
    pub fn read(file: &Path) -> Result<Self, LoadError>
    {
        let playbook = Loaded::<Playbook>::read(file)?;
        let directory = file.parent().unwrap_or_else(|| Path::new(""));
        let mut rubrics = BTreeMap::new();
        for (place, step) in playbook.document().steps().iter().enumerate() {
            let Bound::Question {
                ref rubric,
                ref question,
            } = *step.bound()
            else {
                continue;
            };
            let loaded = match rubrics.entry(rubric.clone()) {
                | Entry::Occupied(entry) => entry.into_mut(),
                | Entry::Vacant(entry) => {
                    entry.insert(Loaded::<Rubric>::read(&rubric.beside(directory))?)
                },
            };
            if !loaded.document().questions().contains_key(question) {
                let field = Field::default()
                    .then(Segment::from("steps"))
                    .then(Segment::from(place))
                    .then(Segment::from("question"))
                    .then(Segment::from("question"));
                return Err(LoadError::Refused {
                    file: file.to_path_buf(),
                    refusal: field.refused(Reason::NoQuestion),
                });
            }
        }
        Ok(Self { playbook, rubrics })
    }

    /// The playbook.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn playbook(&self) -> &Loaded<Playbook>
    {
        &self.playbook
    }

    /// Each rubric a step names, by the file the step names it by.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn rubrics(&self) -> &BTreeMap<RubricFile, Loaded<Rubric>>
    {
        &self.rubrics
    }

    /// What the plan asks of judges: each rubric its steps name, in the order
    /// first named, with the questions its steps name, each once, in step
    /// order.
    ///
    /// # Specification
    /// - ensures: one grading per rubric file the question steps name, in the
    ///   order of the step first naming it; its questions are those the steps
    ///   name in it, in step order, a question named twice asked once.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook naming two rubrics, interleaved and one
    ///   question twice, groups its questions per rubric in step order and asks
    ///   the repeated question once.
    /// - witness: `load::tests::a_plan_reads_its_rubrics_beside_its_playbook`
    #[inline]
    #[must_use]
    pub fn gradings(&self) -> Vec<Grading<'_>>
    {
        let mut gradings: Vec<Grading<'_>> = Vec::new();
        for step in self.playbook.document().steps() {
            let Bound::Question {
                ref rubric,
                ref question,
            } = *step.bound()
            else {
                continue;
            };
            // `read` holds every rubric a step names, and refused any
            // question its rubric lacks.
            let Some((name, asked)) = self
                .rubrics
                .get(rubric)
                .and_then(|loaded| loaded.document().questions().get_key_value(question))
            else {
                continue;
            };
            let grading = gradings.iter_mut().find(|grading| grading.file == rubric);
            match grading {
                | Some(grading) => {
                    if !grading.questions.iter().any(|&(named, _)| named == name) {
                        grading.questions.push((name, asked));
                    }
                },
                | None => {
                    if let Some(loaded) = self.rubrics.get(rubric) {
                        gradings.push(Grading {
                            file: rubric,
                            rubric: loaded,
                            questions: vec![(name, asked)],
                        });
                    }
                },
            }
        }
        gradings
    }
}

/// One rubric a plan grades, with the questions its steps ask.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Grading<'plan>
{
    /// The rubric's file, as the steps name it.
    file: &'plan RubricFile,
    /// The rubric.
    rubric: &'plan Loaded<Rubric>,
    /// The questions asked, by name, in step order.
    questions: Vec<(&'plan Name, &'plan Question)>,
}

impl<'plan> Grading<'plan>
{
    /// The rubric's file, as the steps name it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn file(&self) -> &'plan RubricFile
    {
        self.file
    }

    /// The rubric.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn rubric(&self) -> &'plan Loaded<Rubric>
    {
        self.rubric
    }

    /// The questions asked, by name, in step order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn questions(&self) -> &[(&'plan Name, &'plan Question)]
    {
        &self.questions
    }
}

/// Why a document cannot be loaded from its file.
#[derive(Debug, thiserror::Error)]
pub enum LoadError
{
    /// The file cannot be read.
    #[error("cannot read {}", file.display())]
    Read
    {
        /// The file.
        file: PathBuf,
        /// Why.
        #[source]
        source: std::io::Error,
    },
    /// The file is not UTF-8.
    #[error("{} is not UTF-8", file.display())]
    Encoding
    {
        /// The file.
        file: PathBuf,
        /// Where the encoding breaks.
        #[source]
        source: Utf8Error,
    },
    /// The file's text is not the document.
    #[error("{}: {refusal}", file.display())]
    Refused
    {
        /// The file.
        file: PathBuf,
        /// What in the text is refused, and why.
        refusal: Refusal,
    },
}

#[cfg(test)]
mod tests
{
    use std::path::Path;

    use domhringr_record_tree::Content;
    use domhringr_record_tree::ContentHash;

    use super::LoadError;
    use super::Plan;
    use crate::playbook::Bound;

    /// A rubric of two questions.
    const RUBRIC: &str = r#"
name = "r"
state = ["a"]
band = { low = 0.25, high = 0.75 }
questions.one = { instructions = "i", criteria = { true = "t", false = "f" } }
questions.two = { instructions = "j", criteria = { true = "t", false = "f" } }
"#;

    /// A rubric of one question.
    const OTHER: &str = r#"
name = "s"
state = ["b"]
band = { low = 0.25, high = 0.75 }
questions.three = { instructions = "k", criteria = { true = "t", false = "f" } }
"#;

    /// A playbook of a verifier, then questions of the rubric beside it and
    /// of the one in a sibling directory, interleaved, one asked twice.
    const PLAYBOOK: &str = r#"
name = "p"

[[steps]]
id = "a"
why = "w"
verifier = { command = "true" }

[[steps]]
id = "b"
why = "w"
question = { rubric = "r.toml", question = "two" }

[[steps]]
id = "c"
why = "w"
question = { rubric = "../rubrics/s.toml", question = "three" }

[[steps]]
id = "d"
why = "w"
question = { rubric = "r.toml", question = "one" }

[[steps]]
id = "e"
why = "w"
question = { rubric = "r.toml", question = "two" }
"#;

    #[test]
    fn a_plan_reads_its_rubrics_beside_its_playbook()
    {
        let root = tempfile::tempdir().unwrap();
        let (playbooks, rubrics) = (root.path().join("playbooks"), root.path().join("rubrics"));
        std::fs::create_dir_all(&playbooks).unwrap();
        std::fs::create_dir_all(&rubrics).unwrap();
        std::fs::write(playbooks.join("r.toml"), RUBRIC).unwrap();
        std::fs::write(rubrics.join("s.toml"), OTHER).unwrap();
        let file = playbooks.join("p.toml");
        std::fs::write(&file, PLAYBOOK).unwrap();
        let plan = Plan::read(&file).unwrap();
        let hash = |text: &str| ContentHash::of(&Content::from(text.as_bytes().to_vec()));
        assert_eq!(
            plan.playbook().hash(),
            hash(PLAYBOOK),
            "the playbook is named by its bytes"
        );
        assert_eq!(
            plan.rubrics()
                .iter()
                .map(|(rubric, loaded)| (rubric.to_string(), loaded.hash()))
                .collect::<Vec<_>>(),
            [
                ("../rubrics/s.toml".to_owned(), hash(OTHER)),
                ("r.toml".to_owned(), hash(RUBRIC)),
            ],
            "each rubric is read once, by the file the steps name it by"
        );
        assert_eq!(
            plan.gradings()
                .iter()
                .map(|grading| {
                    let asked = grading
                        .questions()
                        .iter()
                        .map(|&(name, _)| name.to_string())
                        .collect::<Vec<_>>();
                    (grading.file().to_string(), asked)
                })
                .collect::<Vec<_>>(),
            [
                ("r.toml".to_owned(), vec![
                    "two".to_owned(),
                    "one".to_owned()
                ]),
                ("../rubrics/s.toml".to_owned(), vec!["three".to_owned()]),
            ],
            "rubrics in the order first named, their questions in step order, each once"
        );

        std::fs::write(&file, PLAYBOOK.replace("\"one\"", "\"four\"")).unwrap();
        let refused = Plan::read(&file).unwrap_err();
        assert_eq!(
            refused.to_string(),
            format!(
                "{}: steps[3].question.question: the rubric holds no such question",
                file.display()
            ),
            "a question its rubric lacks is refused at the step naming it"
        );
        std::fs::write(&file, PLAYBOOK.replace("s.toml", "t.toml")).unwrap();
        assert!(
            matches!(
                Plan::read(&file),
                Err(LoadError::Read { file: missing, .. }) if missing == playbooks.join("../rubrics/t.toml")
            ),
            "a missing rubric is refused naming its file"
        );
        std::fs::write(&file, PLAYBOOK).unwrap();
        std::fs::write(rubrics.join("s.toml"), "name = \"s\"\n").unwrap();
        let refused = Plan::read(&file).unwrap_err().to_string();
        assert_eq!(
            refused,
            format!(
                "{}: state: missing field",
                playbooks.join("../rubrics/s.toml").display()
            ),
            "a rubric that is no rubric is refused naming its file and field"
        );
        std::fs::write(&file, [0x6e, 0xff]).unwrap();
        assert!(
            matches!(Plan::read(&file), Err(LoadError::Encoding { .. })),
            "a playbook that is not UTF-8 is refused"
        );
    }

    #[test]
    fn the_example_playbook_and_rubric_read()
    {
        let examples = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../examples");
        let plan = Plan::read(&examples.join("playbook.toml")).unwrap();
        let steps = plan
            .playbook()
            .document()
            .steps()
            .iter()
            .map(|step| match *step.bound() {
                | Bound::Verifier(ref verifier) => {
                    format!("{} verifier {}", step.id(), verifier.command())
                },
                | Bound::Question { ref question, .. } => {
                    format!("{} question {question}", step.id())
                },
            })
            .collect::<Vec<_>>();
        assert_eq!(
            steps,
            [
                "gates verifier mise",
                "synopsis question synopsis",
                "crate-rows question crate-rows"
            ],
            "the example playbook runs the gates and asks two of its rubric's questions"
        );
        let gradings = plan.gradings();
        let [ref grading] = gradings[..]
        else {
            panic!("the example playbook names one rubric: {gradings:?}");
        };
        assert_eq!(
            (
                grading.file().to_string(),
                grading.rubric().document().name().to_string(),
                grading.rubric().document().questions().len()
            ),
            ("rubric.toml".to_owned(), "change-review".to_owned(), 2),
            "the example rubric reads beside the playbook, every question of it asked"
        );
    }
}
