//! Evidence and landed revisions mapped to the admitted moves naming them.
//!
//! A subject is an evidence manifest or a landed revision. It is a `Subject`
//! part whose `subject_digest` is its family byte, `1` for evidence and `2`
//! for a revision, then its digest of 32 or 20 bytes. The family byte keeps
//! a SHA-256 revision apart from an evidence digest with the same bytes.
//! Each move naming a subject is a `Naming` part. It has arrows to the move,
//! the subject and the task, and a `naming_role` tag for the receipt field:
//! report content, verifier output, judged transcript or landed revision.
//! The holder isn't stored. It is the field's peer in the move's own
//! receipt, so a reader takes it from there.
//!
//! When one tree is bound under several names, only the first name in
//! order carries namings. Aliases of one task don't duplicate its
//! provenance.

#[cfg(test)]
mod tests;

use core::fmt;

use anodized::spec;
use domhringr_record_tree::Kind;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use gandr_storage_schema::AttributeValue;
use gandr_storage_values::ManifestDigest;

use crate::keyed::ValueFault;

/// The value or repository revision whose naming moves a reader asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Subject
{
    /// A value-plane manifest named by a report, verification or verdict.
    Evidence(ManifestDigest),
    /// A Git object named by a landing, retaining its hash width.
    Revision(Revision),
}

impl Subject
{
    /// The subject's `subject_digest`: its family byte, then its digest.
    ///
    /// # Specification
    /// - ensures: evidence is `0x01 || digest`; a revision is `0x02 ||
    ///   revision`, of 20 or 32 bytes.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — an evidence digest and a SHA-256 revision of the same
    ///   bytes are two subjects.
    /// - witness: `provenance::tests::a_digest_named_twice_has_two_records`
    #[spec(ensures: |ret| matches!(ret.as_ref().len(), 21 | 33))]
    #[inline]
    #[must_use]
    pub fn value(self) -> AttributeValue
    {
        let mut bytes = Vec::with_capacity(33);
        match self {
            Self::Evidence(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(digest.as_ref());
            },
            Self::Revision(revision) => {
                bytes.push(2);
                bytes.extend_from_slice(revision.as_ref());
            },
        }
        AttributeValue::from(bytes)
    }
}

/// The receipt field through which a move names its subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Field
{
    /// A report's content manifest.
    Content,
    /// A verification's output manifest.
    Output,
    /// A verdict's transcript manifest.
    Transcript,
    /// A landing's repository revision.
    Revision,
}

impl Field
{
    /// The field's `naming_role` tag.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn value(self) -> AttributeValue
    {
        let tag: u8 = match self {
            Self::Content => 1,
            Self::Output => 2,
            Self::Transcript => 3,
            Self::Revision => 4,
        };
        AttributeValue::from(&[tag][..])
    }

    /// Read a `naming_role` tag back.
    ///
    /// # Specification
    /// - ensures: `Field::read(&f.value()) == Ok(f)` for every field.
    /// - fails: anything but one known tag byte.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueFault::Role`]: not a role tag.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — every fixture naming's field reads back.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[inline]
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |field| field.value() == *value))]
    pub fn read(value: &AttributeValue) -> Result<Self, ValueFault>
    {
        match *value.as_ref() {
            [1] => Ok(Self::Content),
            [2] => Ok(Self::Output),
            [3] => Ok(Self::Transcript),
            [4] => Ok(Self::Revision),
            _ => Err(ValueFault::Role),
        }
    }
}

impl fmt::Display for Field
{
    /// Write the field's receipt-language name.
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
            Self::Content => "content",
            Self::Output => "output",
            Self::Transcript => "transcript",
            Self::Revision => "revision",
        })
    }
}

/// The field and responsible peer of one naming.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribution
{
    /// Which receipt field names the subject.
    pub field: Field,
    /// The evidence holder, or the landing's operator.
    pub holder: PeerKey,
}

/// Whether an admitted move names evidence or a repository revision.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Naming
{
    /// This move has no provenance-bearing field.
    None,
    /// This field names the subject and its responsible peer.
    Named(Subject, Attribution),
}

/// Read only the provenance-bearing fields of an original receipt.
///
/// # Specification
/// - ensures: reports name content held by their author; verifications and
///   verdicts name output/transcript held by runner/judge; landings name the
///   merge revision and author. All other kinds name nothing.
/// - panics: none.
/// - executable: none — the receipt classifier is its own specification; the
///   fold independently supplies evidence holders and landed revisions.
///
/// # Adequacy
/// - hypothesis: L2 — `Task::evidence` supplies independent digest/holder
///   pairs; folded landing steps supply revision/operator pairs.
/// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
#[inline]
#[must_use]
pub fn naming(
    author: PeerKey,
    receipt: &Receipt,
) -> Naming
{
    let (subject, field, holder) = match *receipt.kind() {
        Kind::Report { content, .. } => (Subject::Evidence(content), Field::Content, author),
        Kind::Verified { output, runner, .. } => (Subject::Evidence(output), Field::Output, runner),
        Kind::Verdict {
            transcript, judge, ..
        } => (Subject::Evidence(transcript), Field::Transcript, judge),
        Kind::Landed { merge, .. } => (Subject::Revision(merge), Field::Revision, author),
        Kind::Open { .. }
        | Kind::Grant { .. }
        | Kind::Note { .. }
        | Kind::Bind { .. }
        | Kind::Claim { .. }
        | Kind::Introduce { .. }
        | Kind::Present { .. }
        | Kind::Withdraw { .. }
        | Kind::Indexed { .. }
        | Kind::Dispatch { .. }
        | Kind::Handoff { .. }
        | Kind::Retire { .. }
        | Kind::Pause { .. }
        | Kind::Graded { .. }
        | Kind::Decide { .. } => return Naming::None,
    };
    Naming::Named(subject, Attribution { field, holder })
}
