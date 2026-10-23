//! The keyed-index schema a project's store is of, and the canonical bytes
//! of each attribute.
//!
//! Tasks, attempts, moves, refusals, subjects and namings are the tables of
//! `gandr_storage_schema::keyed::schema()`. Each reference is a total arrow
//! the store checks; `naming_task_agrees` holds a naming's task to its
//! move's. A task is found by the preimage of `task_name`, its attempts by
//! `attempt_task`, their moves by `move_attempt`, its refusals by
//! `refusal_task`, and a subject's namings by `subject_digest`, then
//! `naming_subject`.
//!
//! The store compares values as bytes; the codecs here read them. A
//! `Number` is `u64le`; `Text` is UTF-8; [`Standing`] and
//! [`Field`](crate::provenance::Field) are one tag byte; a `Digest` is a
//! commit's 32 bytes or a subject's family byte and digest; heads are
//! ascending 32-byte identities; a move is
//! [`MoveValue`](crate::dialogue::MoveValue)'s canonical value.
//!
//! The standing is a tag: the rest of `Current` is recomputed from the
//! task's last attempt ([`crate::prove::current`]). No tree is held: each
//! move's receipt names its tree.

use anodized::spec;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Heads;
use gandr_storage_records::TreeParams;
use gandr_storage_schema::ArrowId;
use gandr_storage_schema::AttributeId;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::ObjectId;
use gandr_storage_schema::Schema;
use gandr_storage_schema::SchemaError;
use gandr_storage_schema::keyed;

/// The pinned identity of the keyed-index schema every project store is of.
pub const IDENTITY: &str = "c41fca723d8f72d631faab68a9b243250a8a428cf8a3a0151a4e72e92a9ff5c5";

/// The record-plane parameters every project store is built under.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub const fn params() -> TreeParams
{
    TreeParams::current()
}

/// The schema, resolved once per process.
static SHARED: std::sync::OnceLock<Result<Keyed, SchemaError>> = std::sync::OnceLock::new();

/// The keyed-index schema with every element it is read through.
#[derive(Clone, Debug)]
pub struct Keyed
{
    /// The schema.
    pub schema: Schema,
    /// A task bound by the project.
    pub task: ObjectId,
    /// One dispatch of a task and the moves answering it.
    pub attempt: ObjectId,
    /// One admitted move.
    pub movement: ObjectId,
    /// A refused commit of a task.
    pub refusal: ObjectId,
    /// An evidence manifest or a landed revision.
    pub subject: ObjectId,
    /// One move's naming of one subject.
    pub naming: ObjectId,
    /// An attempt's task.
    pub attempt_task: ArrowId,
    /// A move's attempt.
    pub move_attempt: ArrowId,
    /// A refusal's task.
    pub refusal_task: ArrowId,
    /// A naming's move.
    pub naming_move: ArrowId,
    /// A naming's subject.
    pub naming_subject: ArrowId,
    /// A naming's task, held to its move's by `naming_task_agrees`.
    pub naming_task: ArrowId,
    /// A task's name.
    pub task_name: AttributeId,
    /// A task's standing tag.
    pub task_standing: AttributeId,
    /// A task's heads.
    pub task_heads: AttributeId,
    /// An attempt's one-based number.
    pub attempt_number: AttributeId,
    /// A move's zero-based place in its attempt.
    pub move_seq: AttributeId,
    /// A move's claimed author and original receipt bytes.
    pub move_receipt: AttributeId,
    /// A refused commit.
    pub refusal_commit: AttributeId,
    /// A refusal's displayed reason.
    pub refusal_reason: AttributeId,
    /// A subject's family and digest.
    pub subject_digest: AttributeId,
    /// The receipt field a naming names its subject through.
    pub naming_role: AttributeId,
}

impl Keyed
{
    /// Present the schema and resolve every element by name.
    ///
    /// # Specification
    /// - ensures: on success every element names the schema's own.
    /// - fails: a schema missing a name this crate reads.
    /// - panics: none.
    /// - executable: none — the identity pin is the witness of which schema
    ///   this is.
    ///
    /// # Errors
    /// - [`SchemaError`]: the presentation or a name is refused.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the schema presents with its pinned identity.
    /// - witness: `keyed::tests::the_keyed_schema_identity_is_pinned`
    #[inline]
    pub fn new() -> Result<Self, SchemaError>
    {
        let schema = keyed::schema()?;
        Ok(Self {
            task: schema.object("Task")?,
            attempt: schema.object("Attempt")?,
            movement: schema.object("Move")?,
            refusal: schema.object("Refusal")?,
            subject: schema.object("Subject")?,
            naming: schema.object("Naming")?,
            attempt_task: schema.arrow("attempt_task")?,
            move_attempt: schema.arrow("move_attempt")?,
            refusal_task: schema.arrow("refusal_task")?,
            naming_move: schema.arrow("naming_move")?,
            naming_subject: schema.arrow("naming_subject")?,
            naming_task: schema.arrow("naming_task")?,
            task_name: schema.attribute("task_name")?,
            task_standing: schema.attribute("task_standing")?,
            task_heads: schema.attribute("task_heads")?,
            attempt_number: schema.attribute("attempt_number")?,
            move_seq: schema.attribute("move_seq")?,
            move_receipt: schema.attribute("move_receipt")?,
            refusal_commit: schema.attribute("refusal_commit")?,
            refusal_reason: schema.attribute("refusal_reason")?,
            subject_digest: schema.attribute("subject_digest")?,
            naming_role: schema.attribute("naming_role")?,
            schema,
        })
    }

    /// The schema, resolved on first use and shared by every reader after.
    ///
    /// # Specification
    /// - ensures: every call returns the one resolution [`Keyed::new`] made.
    /// - fails: as [`Keyed::new`], on every call.
    /// - panics: none.
    /// - executable: none — the cell is its own specification.
    ///
    /// # Errors
    /// - [`SchemaError`]: as [`Keyed::new`].
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the schema presents with its pinned identity.
    /// - witness: `keyed::tests::the_keyed_schema_identity_is_pinned`
    #[inline]
    pub fn shared() -> Result<&'static Self, SchemaError>
    {
        SHARED.get_or_init(Self::new).as_ref().map_err(Clone::clone)
    }

    /// An empty store of the schema.
    ///
    /// # Specification
    /// trivial.
    ///
    /// # Errors
    /// - [`gandr_storage_schema::StoreError`]: the refusal of
    ///   [`gandr_storage_schema::Store::new`].
    #[inline]
    pub fn store(&self) -> Result<gandr_storage_schema::Store, gandr_storage_schema::StoreError>
    {
        gandr_storage_schema::Store::new(self.schema.clone(), params())
    }
}

/// Where a task stands, as the tag `task_standing` holds.
///
/// Each kind is a line [`domhringr_record_tree::Current`] prints, plus
/// `unheld` for a binding whose task the deriver does not hold.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Standing
{
    /// The deriver does not hold the task's Open.
    Unheld,
    /// No dispatch was admitted.
    Undispatched,
    /// The current dispatch's slot is held and unreported.
    Dispatched,
    /// The slot was retired from without a report.
    Stalled,
    /// The current dispatch is reported on.
    Reported,
    /// A verifier ran on the current dispatch.
    Verified,
    /// A verdict on the current dispatch was graded.
    Graded,
    /// The operator decided the current dispatch.
    Decided,
    /// The current dispatch's change landed.
    Landed,
}

/// The kinds in tag order, so a tag reads back by position.
const STANDINGS: [Standing; 9] = [
    Standing::Unheld,
    Standing::Undispatched,
    Standing::Dispatched,
    Standing::Stalled,
    Standing::Reported,
    Standing::Verified,
    Standing::Graded,
    Standing::Decided,
    Standing::Landed,
];

impl Standing
{
    /// The kind of a held task's standing.
    ///
    /// # Specification
    /// - ensures: the kind is the first word `current` prints.
    /// - panics: none.
    /// - executable: none — the classifier mirrors the standing's `Display` arm
    ///   for arm; the entry witness compares the two at every standing.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — every reachable standing's tag names the word its
    ///   line starts with.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[inline]
    #[must_use]
    pub fn of(current: &domhringr_record_tree::Current) -> Self
    {
        use domhringr_record_tree::Answer;
        use domhringr_record_tree::Current;
        use domhringr_record_tree::Progress;
        use domhringr_record_tree::Slot;
        let Current::Attempt(ref attempt) = *current
        else {
            return Self::Undispatched;
        };
        match (attempt.progress(), attempt.answer(), attempt.slot()) {
            (&Progress::Landed { .. }, ..) => Self::Landed,
            (&Progress::Decided { .. }, ..) => Self::Decided,
            (&Progress::Graded { .. }, ..) => Self::Graded,
            (&Progress::Verified(_), ..) => Self::Verified,
            (&Progress::Unchecked, Answer::Reported(_), _) => Self::Reported,
            (&Progress::Unchecked, Answer::Awaited, Slot::Retired { .. }) => Self::Stalled,
            (&Progress::Unchecked, Answer::Awaited, Slot::Held(_)) => Self::Dispatched,
        }
    }

    /// The tag's canonical bytes: the kind's position in tag order.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn value(self) -> AttributeValue
    {
        let tag: u8 = match self {
            Self::Unheld => 0,
            Self::Undispatched => 1,
            Self::Dispatched => 2,
            Self::Stalled => 3,
            Self::Reported => 4,
            Self::Verified => 5,
            Self::Graded => 6,
            Self::Decided => 7,
            Self::Landed => 8,
        };
        AttributeValue::from(&[tag][..])
    }

    /// Read a tag back.
    ///
    /// # Specification
    /// - ensures: `Standing::read(&s.value()) == Ok(s)` for every kind.
    /// - fails: anything other than one known tag byte.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueFault::Standing`]: not a standing tag.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every tag round-trips and the next byte is refused.
    /// - witness: `keyed::tests::every_tag_reads_back_and_no_other_byte_does`
    #[inline]
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |standing| standing.value() == *value))]
    pub fn read(value: &AttributeValue) -> Result<Self, ValueFault>
    {
        match *value.as_ref() {
            [tag] => STANDINGS
                .get(usize::from(tag))
                .copied()
                .ok_or(ValueFault::Standing),
            _ => Err(ValueFault::Standing),
        }
    }
}

impl core::fmt::Display for Standing
{
    /// Write the word `current` prints first for this kind.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut core::fmt::Formatter<'_>,
    ) -> core::fmt::Result
    {
        f.write_str(match *self {
            Self::Unheld => "unheld",
            Self::Undispatched => "undispatched",
            Self::Dispatched => "dispatched",
            Self::Stalled => "stalled",
            Self::Reported => "reported",
            Self::Verified => "verified",
            Self::Graded => "graded",
            Self::Decided => "decided",
            Self::Landed => "landed",
        })
    }
}

/// An attribute value that is not the canonical bytes of its type.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
pub enum ValueFault
{
    /// Not one known standing tag.
    #[error("not a standing tag")]
    Standing,
    /// Not one known role tag.
    #[error("not a role tag")]
    Role,
    /// Not eight little-endian bytes, or past the coordinate's width.
    #[error("not a number")]
    Number,
    /// Not UTF-8, or not a task name.
    #[error("not text")]
    Text,
    /// Not a commit identity, or not a subject's family and digest.
    #[error("not a digest")]
    Digest,
    /// Not ascending 32-byte commit identities.
    #[error("not heads")]
    Heads,
}

/// A `Number` attribute's value: an attempt's number or a move's place.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct Number(pub u64);

/// A count or coordinate as a `Number` attribute.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn number(value: Number) -> AttributeValue
{
    AttributeValue::from(&value.0.to_le_bytes()[..])
}

/// Read a `Number` attribute.
///
/// # Specification
/// - ensures: `read_number(&number(n)) == Ok(n)`.
/// - fails: anything but eight bytes.
/// - panics: none.
///
/// # Errors
/// - [`ValueFault::Number`]: not eight bytes.
///
/// # Adequacy
/// - hypothesis: L3 — a number round-trips; seven and nine bytes are refused.
/// - witness: `keyed::tests::every_tag_reads_back_and_no_other_byte_does`
#[inline]
#[spec(ensures: |ret| ret.as_ref().map_or(true, |count| number(*count) == *value))]
pub fn read_number(value: &AttributeValue) -> Result<Number, ValueFault>
{
    let bytes: [u8; 8] = value
        .as_ref()
        .try_into()
        .map_err(|_width| ValueFault::Number)?;
    Ok(Number(u64::from_le_bytes(bytes)))
}

/// A commit identity as a `Digest` attribute.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn commit(commit: CommitId) -> AttributeValue
{
    AttributeValue::from(&commit.as_bytes()[..])
}

/// Read a commit identity.
///
/// # Specification
/// - ensures: `read_commit(&commit(c)) == Ok(c)`.
/// - fails: anything but 32 bytes.
/// - panics: none.
///
/// # Errors
/// - [`ValueFault::Digest`]: not 32 bytes.
///
/// # Adequacy
/// - hypothesis: L2 — every refusal of the entry fixture reads back.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
#[spec(ensures: |ret| ret.as_ref().map_or(true, |id| commit(*id) == *value))]
pub fn read_commit(value: &AttributeValue) -> Result<CommitId, ValueFault>
{
    let bytes: [u8; 32] = value
        .as_ref()
        .try_into()
        .map_err(|_width| ValueFault::Digest)?;
    Ok(CommitId::new(bytes))
}

/// A task's heads as a `Bytes` attribute: ascending 32-byte identities.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn heads(heads: &Heads) -> AttributeValue
{
    let mut bytes = Vec::new();
    for head in heads.iter() {
        bytes.extend_from_slice(head.as_bytes());
    }
    AttributeValue::from(bytes)
}

/// Read a task's heads.
///
/// # Specification
/// - ensures: `read_heads(&heads(h)) == Ok(h)`.
/// - fails: a width not a multiple of 32, or identities out of strictly
///   ascending order.
/// - panics: none.
///
/// # Errors
/// - [`ValueFault::Heads`]: not canonical heads.
///
/// # Adequacy
/// - hypothesis: L3 — heads round-trip; a repeated or descending pair is
///   refused.
/// - witness: `keyed::tests::every_tag_reads_back_and_no_other_byte_does`
#[inline]
#[spec(ensures: |ret| ret.as_ref().map_or(true, |read| heads(read) == *value))]
pub fn read_heads(value: &AttributeValue) -> Result<Heads, ValueFault>
{
    let (chunks, rest) = value.as_ref().as_chunks::<32>();
    if !rest.is_empty()
        || chunks
            .windows(2)
            .any(|pair| matches!(pair, [left, right] if left >= right))
    {
        return Err(ValueFault::Heads);
    }
    Ok(Heads::from_iter(
        chunks.iter().map(|chunk| CommitId::new(*chunk)),
    ))
}

/// A `Text` attribute's text: a task's name or a refusal's reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Text<'text>(pub &'text str);

/// Text as a `Text` attribute.
///
/// # Specification
/// trivial.
#[inline]
#[must_use]
pub fn text(text: Text<'_>) -> AttributeValue
{
    AttributeValue::from(text.0.as_bytes())
}

/// Read a `Text` attribute.
///
/// # Specification
/// - ensures: `read_text(&text(t)) == Ok(t)`.
/// - fails: bytes that are not UTF-8.
/// - panics: none.
///
/// # Errors
/// - [`ValueFault::Text`]: not UTF-8.
///
/// # Adequacy
/// - hypothesis: L3 — names and reasons round-trip; an invalid byte is refused.
/// - witness: `keyed::tests::every_tag_reads_back_and_no_other_byte_does`
#[inline]
#[spec(ensures: |ret| ret.as_ref().map_or(true, |read| text(*read) == *value))]
pub fn read_text(value: &AttributeValue) -> Result<Text<'_>, ValueFault>
{
    core::str::from_utf8(value.as_ref())
        .map(Text)
        .map_err(|_utf8| ValueFault::Text)
}

#[cfg(test)]
mod tests
{
    use domhringr_record_tree::CommitId;
    use domhringr_record_tree::Heads;
    use gandr_storage_schema::AttributeValue;

    use super::IDENTITY;
    use super::Keyed;
    use super::Number;
    use super::STANDINGS;
    use super::Standing;
    use super::Text;
    use super::ValueFault;

    #[test]
    fn the_keyed_schema_identity_is_pinned()
    {
        let keyed = Keyed::new().unwrap();
        assert_eq!(keyed.schema.identity().to_string(), IDENTITY);
        assert_eq!(
            IDENTITY,
            "c41fca723d8f72d631faab68a9b243250a8a428cf8a3a0151a4e72e92a9ff5c5"
        );
    }

    #[test]
    fn every_tag_reads_back_and_no_other_byte_does()
    {
        for (tag, standing) in (0_u8 ..).zip(STANDINGS) {
            assert_eq!(standing.value(), AttributeValue::from(&[tag][..]));
            assert_eq!(Standing::read(&standing.value()), Ok(standing));
        }
        for refused in [&[9_u8][..], &[], &[1, 1]] {
            assert_eq!(
                Standing::read(&AttributeValue::from(refused)),
                Err(ValueFault::Standing)
            );
        }
        for count in [0_u64, 1, u64::MAX] {
            assert_eq!(
                super::read_number(&super::number(Number(count))),
                Ok(Number(count))
            );
        }
        for refused in [&[0_u8; 7][..], &[0; 9]] {
            assert_eq!(
                super::read_number(&AttributeValue::from(refused)),
                Err(ValueFault::Number)
            );
        }
        let low = CommitId::new([1; 32]);
        let high = CommitId::new([2; 32]);
        let heads = Heads::from_iter([high, low]);
        assert_eq!(super::read_heads(&super::heads(&heads)), Ok(heads));
        assert_eq!(
            super::read_heads(&super::heads(&Heads::from_iter([]))).map(|h| h.iter().count()),
            Ok(0)
        );
        for refused in [[high, low], [low, low]] {
            let bytes: Vec<u8> = refused.iter().flat_map(|head| *head.as_bytes()).collect();
            assert_eq!(
                super::read_heads(&AttributeValue::from(bytes)),
                Err(ValueFault::Heads)
            );
        }
        assert_eq!(
            super::read_heads(&AttributeValue::from(&[0_u8; 33][..])),
            Err(ValueFault::Heads)
        );
        assert_eq!(
            super::read_text(&super::text(Text("alpha"))),
            Ok(Text("alpha"))
        );
        assert_eq!(
            super::read_text(&AttributeValue::from(&[0xff_u8][..])),
            Err(ValueFault::Text)
        );
    }
}
