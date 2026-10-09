//! Documents: how a playbook's or a rubric's TOML text is read — the field
//! each value sits at ([`Field`]), a document's names ([`Name`]), and the
//! refusal of a text that is not the document ([`Refusal`]), naming the
//! field it is about and why ([`Reason`]).
//!
//! A document is read by hand from the TOML parser's document tree, never by
//! a derived deserializer, so every refusal names its field: an unknown
//! field, a missing one, a value of another type, and each document's own
//! refusals. A table's unknown fields are refused before any of its fields is
//! read, the smallest key first, so a misspelt field is refused as unknown
//! rather than as the missing field it was meant to be.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt;
use core::fmt::Write as _;
use core::str::FromStr;

use domhringr_judge_oracle::QuestionError;
use domhringr_record_tree::NotProbability;
use domhringr_record_tree::ParseStepIdError;
use domhringr_record_tree::Probability;
use domhringr_record_tree::StepId;
use toml::de::DeTable;
use toml::de::DeValue;

use crate::playbook::ParseRubricFileError;
use crate::rubric::ParseStateFileError;

/// Where a value sits in a document: the keys and array positions from its
/// root, written `steps[2].question.rubric`; a key that is not a bare TOML
/// key is written quoted.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Field(Vec<Segment>);

impl Field
{
    /// The field one `segment` below this one.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn then(
        &self,
        segment: Segment,
    ) -> Self
    {
        let mut segments = self.0.clone();
        segments.push(segment);
        Self(segments)
    }

    /// The refusal of the value at this field for `reason`.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn refused(
        self,
        reason: Reason,
    ) -> Refusal
    {
        Refusal {
            field: self,
            reason,
        }
    }
}

impl fmt::Display for Field
{
    /// Write the field: keys joined by `.`, each array position as `[n]`
    /// after the array's key, and a key holding anything but ASCII letters,
    /// digits, `_` and `-` quoted; the root is written as nothing.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        for (place, segment) in self.0.iter().enumerate() {
            match *segment {
                | Segment::Key(ref key) => {
                    if place != 0 {
                        f.write_str(".")?;
                    }
                    let bare = !key.is_empty()
                        && key.bytes().all(|byte| {
                            byte.is_ascii_alphanumeric() || byte == b'_' || byte == b'-'
                        });
                    if bare {
                        f.write_str(key)?;
                    }
                    else {
                        f.write_char('"')?;
                        for character in key.chars() {
                            match character {
                                | '"' | '\\' => write!(f, "\\{character}")?,
                                | _ if character.is_control() => {
                                    write!(f, "\\u{:04X}", u32::from(character))?;
                                },
                                | _ => f.write_char(character)?,
                            }
                        }
                        f.write_char('"')?;
                    }
                },
                | Segment::Index(Index(index)) => write!(f, "[{index}]")?,
            }
        }
        Ok(())
    }
}

/// One step from a table or an array to a value it holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Segment
{
    /// The value under a table's key.
    Key(String),
    /// The value at an array's position.
    Index(Index),
}

impl From<&str> for Segment
{
    /// The segment to the value under `key`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(key: &str) -> Self
    {
        Self::Key(key.into())
    }
}

/// A position in an array, counted from zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Index(usize);

impl From<usize> for Segment
{
    /// The segment to the value at an array's `place`, counted from zero.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(place: usize) -> Self
    {
        Self::Index(Index(place))
    }
}

/// Why a text is not the document it is read as, and where.
#[derive(Debug, PartialEq, Eq)]
pub struct Refusal
{
    /// Where in the document the refusal is.
    field: Field,
    /// Why.
    reason: Reason,
}

impl Refusal
{
    /// The field the refusal is about; the root for a text that is not
    /// TOML.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn field(&self) -> &Field
    {
        &self.field
    }

    /// Why the document is refused.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn reason(&self) -> &Reason
    {
        &self.reason
    }
}

impl fmt::Display for Refusal
{
    /// Write `<field>: <reason>`, or the reason alone at the root.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        if self.field.0.is_empty() {
            write!(f, "{}", self.reason)
        }
        else {
            write!(f, "{}: {}", self.field, self.reason)
        }
    }
}

impl core::error::Error for Refusal
{
}

/// Why a document refuses a value.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum Reason
{
    /// The text is not TOML.
    #[error("{0}")]
    Syntax(Syntax),
    /// The field is not one its table holds.
    #[error("unknown field")]
    Unknown,
    /// A field its table holds is absent.
    #[error("missing field")]
    Missing,
    /// The value is of another type.
    #[error("expected {0}")]
    Type(Expected),
    /// The text, array or table holds nothing where something is due.
    #[error("empty")]
    Empty,
    /// The value is not a name or a step identifier.
    #[error("{0}")]
    Identifier(ParseStepIdError),
    /// An earlier step has the same identifier.
    #[error("another step has this identifier")]
    Duplicate,
    /// A step is bound to neither a verifier nor a question.
    #[error("a step is bound to a verifier or a question")]
    Unbound,
    /// A step is bound to both a verifier and a question.
    #[error("a step is bound to a verifier or a question, not both")]
    Ambiguous,
    /// The rubric a step names is no relative path.
    #[error("{0}")]
    RubricFile(ParseRubricFileError),
    /// The rubric a step names holds no such question.
    #[error("the rubric holds no such question")]
    NoQuestion,
    /// A state file is no relative path inside the state directory.
    #[error("{0}")]
    StateFile(ParseStateFileError),
    /// The value is not a probability.
    #[error("{0}")]
    Probability(NotProbability),
    /// The band's low bound is not below its high bound.
    #[error("the band's low bound is not below its high bound")]
    Inverted,
    /// The question cannot be asked.
    #[error("{0}")]
    Question(QuestionError),
}

/// Where a text stops being TOML, and what the parser says of it.
#[derive(Debug, PartialEq, Eq)]
pub struct Syntax
{
    /// The line, counted from one.
    line: Ordinal,
    /// The character in the line, counted from one.
    column: Ordinal,
    /// The parser's account of the error, on one line.
    message: String,
}

impl fmt::Display for Syntax
{
    /// Write `not TOML at line <n>, column <n>: <message>`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(
            f,
            "not TOML at line {}, column {}: {}",
            self.line, self.column, self.message
        )
    }
}

/// A line's or a column's place, counted from one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
struct Ordinal(usize);

impl fmt::Display for Ordinal
{
    /// Write the number in decimal.
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

/// The type a field holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Expected
{
    /// A string.
    String,
    /// A float.
    Float,
    /// An array.
    Array,
    /// A table.
    Table,
}

impl fmt::Display for Expected
{
    /// Write `a string`, `a float`, `an array` or `a table`.
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
            | Self::String => "a string",
            | Self::Float => "a float",
            | Self::Array => "an array",
            | Self::Table => "a table",
        })
    }
}

/// A document's or a rubric question's name, spelled as a step's
/// identifier: 1 to 64 lowercase ASCII letters, digits and hyphens,
/// beginning with a letter.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[repr(transparent)]
pub struct Name(StepId);

impl FromStr for Name
{
    type Err = ParseStepIdError;

    /// Read a name from its text.
    ///
    /// # Specification
    /// - ensures: accepts exactly the texts [`StepId`] accepts, kept as
    ///   written.
    /// - fails: as [`StepId`]'s parser refuses.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseStepIdError`]: the text is not an identifier.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a rubric's question named by an uppercase key is
    ///   refused at its key, and named questions are read in their names'
    ///   order.
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        text.parse().map(Self)
    }
}

impl fmt::Display for Name
{
    /// Write the name as written.
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

/// The keys a table holds.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Keys(pub &'static [&'static str]);

/// One key of a table.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Key(pub &'static str);

/// A value of a document, at its field.
#[derive(Debug)]
pub struct Value<'input>
{
    /// Where the value sits.
    field: Field,
    /// The value, as the parser read it.
    value: DeValue<'input>,
}

impl<'input> TryFrom<&'input str> for Value<'input>
{
    type Error = Refusal;

    /// Read `text` as a TOML document: its root table, at the root field.
    ///
    /// # Specification
    /// - ensures: the root table of the document `text` holds, as the TOML
    ///   parser reads it.
    /// - fails: [`Reason::Syntax`] at the root for a text that is not TOML,
    ///   naming the line and column where the parser stopped.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Syntax`]: the text is not TOML.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook holding an unclosed table header is
    ///   refused at the root with the line and column of the header's end.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    #[inline]
    fn try_from(text: &'input str) -> Result<Self, Self::Error>
    {
        match DeTable::parse(text) {
            | Ok(root) => Ok(Self {
                field: Field::default(),
                value: DeValue::Table(root.into_inner()),
            }),
            | Err(error) => {
                let start = error.span().map_or(0, |span| span.start);
                let before = text.get(.. start).unwrap_or(text);
                // The lines before the error and its own, counted from one;
                // the characters before it on its line and its own.
                let line = before.split('\n').count();
                let column = before
                    .rsplit('\n')
                    .next()
                    .unwrap_or_default()
                    .chars()
                    .chain(core::iter::once('^'))
                    .count();
                let message = error.message().lines().collect::<Vec<_>>().join("; ");
                Err(Field::default().refused(Reason::Syntax(Syntax {
                    line: Ordinal(line),
                    column: Ordinal(column),
                    message,
                })))
            },
        }
    }
}

impl<'input> Value<'input>
{
    /// Where the value sits.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn field(&self) -> &Field
    {
        &self.field
    }

    /// The value as a table holding only `keys`.
    ///
    /// # Specification
    /// - ensures: the table, its fields read from it at this field.
    /// - fails: [`Reason::Type`] for a value that is no table, then
    ///   [`Reason::Unknown`] at the smallest key outside `keys`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no table.
    /// - [`Reason::Unknown`]: the table holds a key outside `keys`.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an unknown field in a playbook's step, in a rubric's
    ///   band and in a rubric's question is refused at the unknown key, before
    ///   a field missing beside it, and a step that is no table at its place.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn table(
        self,
        keys: Keys,
    ) -> Result<Table<'input>, Refusal>
    {
        let DeValue::Table(entries) = self.value
        else {
            return Err(self.field.refused(Reason::Type(Expected::Table)));
        };
        let unknown = entries
            .keys()
            .map(|key| key.get_ref().as_ref())
            .find(|key| !keys.0.contains(key));
        if let Some(key) = unknown {
            return Err(self.field.then(Segment::from(key)).refused(Reason::Unknown));
        }
        Ok(Table {
            field: self.field,
            entries,
        })
    }

    /// The value as a table whose keys are names: each name with the value
    /// under it, in the names' order.
    ///
    /// # Specification
    /// - ensures: one entry per key, each key read as `Named` reads it.
    /// - fails: [`Reason::Type`] for a value that is no table, then the refusal
    ///   `refused` makes of the first key in order that does not read, at that
    ///   key.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no table.
    /// - the reason `refused` gives: a key does not read.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a rubric's questions are read in their names' order,
    ///   and a question named by an uppercase key is refused at it.
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn named<Named>(
        self,
        refused: fn(Named::Err) -> Reason,
    ) -> Result<Vec<(Named, Self)>, Refusal>
    where
        Named: FromStr,
    {
        let DeValue::Table(entries) = self.value
        else {
            return Err(self.field.refused(Reason::Type(Expected::Table)));
        };
        let mut named = Vec::with_capacity(entries.len());
        for (key, value) in entries {
            let field = self.field.then(Segment::from(key.get_ref().as_ref()));
            let name = match key.get_ref().parse::<Named>() {
                | Ok(name) => name,
                | Err(error) => return Err(field.refused(refused(error))),
            };
            named.push((name, Self {
                field,
                value: value.into_inner(),
            }));
        }
        Ok(named)
    }

    /// The value as an array: each item at its position.
    ///
    /// # Specification
    /// - ensures: the array's items in order, each at this field followed by
    ///   its position.
    /// - fails: [`Reason::Type`] for a value that is no array.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no array.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook's steps are read in order and a refusal
    ///   inside the third names its position, and `steps` given as a string is
    ///   refused as no array.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    pub(crate) fn array(self) -> Result<Vec<Self>, Refusal>
    {
        let DeValue::Array(items) = self.value
        else {
            return Err(self.field.refused(Reason::Type(Expected::Array)));
        };
        Ok(items
            .into_iter()
            .enumerate()
            .map(|(place, item)| Self {
                field: self.field.then(Segment::Index(Index(place))),
                value: item.into_inner(),
            })
            .collect())
    }

    /// The value as a string, empty or not.
    ///
    /// # Specification
    /// - ensures: the string's text.
    /// - fails: [`Reason::Type`] for a value that is no string.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no string.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a verifier's arguments read back as written, an empty
    ///   one among them, and a step's `why` given as an integer is refused as
    ///   no string.
    /// - witness: `playbook::tests::a_playbook_reads_its_steps_in_order`
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    pub(crate) fn text(self) -> Result<String, Refusal>
    {
        match self.value {
            | DeValue::String(text) => Ok(text.into_owned()),
            | DeValue::Integer(_)
            | DeValue::Float(_)
            | DeValue::Boolean(_)
            | DeValue::Datetime(_)
            | DeValue::Array(_)
            | DeValue::Table(_) => Err(self.field.refused(Reason::Type(Expected::String))),
        }
    }

    /// The value as a string holding something.
    ///
    /// # Specification
    /// - ensures: the string's text, never empty.
    /// - fails: [`Reason::Type`] for a value that is no string, then
    ///   [`Reason::Empty`] for the empty string.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no string.
    /// - [`Reason::Empty`]: the string is empty.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an empty `why` and an empty criterion are refused at
    ///   their fields.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn filled(self) -> Result<String, Refusal>
    {
        let field = self.field.clone();
        let text = self.text()?;
        if text.is_empty() {
            return Err(field.refused(Reason::Empty));
        }
        Ok(text)
    }

    /// The value as a string read as a `Parsed`.
    ///
    /// # Specification
    /// - ensures: the string read by `Parsed`'s parser.
    /// - fails: [`Reason::Type`] for a value that is no string, then the reason
    ///   `refused` makes of the parser's refusal.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no string.
    /// - the reason `refused` gives: the parser refuses the string.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a step's identifier, a document's name, a rubric file
    ///   and a state file read back as written, and each refused at its field
    ///   when malformed.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn parsed<Parsed>(
        self,
        refused: fn(Parsed::Err) -> Reason,
    ) -> Result<Parsed, Refusal>
    where
        Parsed: FromStr,
    {
        let field = self.field.clone();
        let text = self.text()?;
        text.parse::<Parsed>()
            .map_err(|error| field.refused(refused(error)))
    }

    /// The value as a probability: a float from zero to one.
    ///
    /// # Specification
    /// - ensures: the probability the float's text reads as.
    /// - fails: [`Reason::Type`] for a value that is no float — an integer
    ///   among them — then [`Reason::Probability`] for a float outside `[0, 1]`
    ///   or not a number.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Type`]: the value is no float.
    /// - [`Reason::Probability`]: the float is no probability.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a band of `0.25` and `0.75` reads back exactly, an
    ///   integer bound is refused as no float, and bounds of `1.5` and `nan` as
    ///   no probability.
    /// - witness: `rubric::tests::a_rubric_reads_its_state_band_and_questions`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn probability(self) -> Result<Probability, Refusal>
    {
        let DeValue::Float(ref float) = self.value
        else {
            return Err(self.field.refused(Reason::Type(Expected::Float)));
        };
        let number = float.as_str().parse::<f64>().unwrap_or(f64::NAN);
        Probability::try_from(number)
            .map_err(|error| self.field.refused(Reason::Probability(error)))
    }
}

/// A table of a document, its fields taken one by one.
#[derive(Debug)]
pub struct Table<'input>
{
    /// Where the table sits.
    field: Field,
    /// The fields not taken yet.
    entries: DeTable<'input>,
}

/// A field of a table, given or absent.
#[derive(Debug)]
pub enum Slot<'input>
{
    /// The field's value.
    Given(Value<'input>),
    /// The table holds no such field.
    Absent,
}

impl<'input> Table<'input>
{
    /// Take the field `key`, given or absent.
    ///
    /// # Specification
    /// trivial.
    pub(crate) fn take(
        &mut self,
        key: Key,
    ) -> Slot<'input>
    {
        match self.entries.remove(key.0) {
            | Some(value) => Slot::Given(Value {
                field: self.field.then(Segment::from(key.0)),
                value: value.into_inner(),
            }),
            | None => Slot::Absent,
        }
    }

    /// Take the field `key`, which the table holds.
    ///
    /// # Specification
    /// - ensures: the field's value at its field.
    /// - fails: [`Reason::Missing`] at the field when the table holds none.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`Reason::Missing`]: the table holds no such field.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a playbook without `name`, a step without `why` and a
    ///   rubric's question without `criteria` are each refused at the field
    ///   missing.
    /// - witness: `playbook::tests::a_malformed_playbook_is_refused_at_its_field`
    /// - witness: `rubric::tests::a_malformed_rubric_is_refused_at_its_field`
    pub(crate) fn require(
        &mut self,
        key: Key,
    ) -> Result<Value<'input>, Refusal>
    {
        match self.take(key) {
            | Slot::Given(value) => Ok(value),
            | Slot::Absent => Err(self
                .field
                .then(Segment::from(key.0))
                .refused(Reason::Missing)),
        }
    }

    /// Where the table sits.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn field(&self) -> &Field
    {
        &self.field
    }
}
