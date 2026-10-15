//! Evidence and landed revisions mapped to the admitted moves naming them.
//!
//! Provenance keys evidence by `0x01 || digest || task || attempt || seq` and
//! landings by `0x02 || width || revision || task || attempt || seq`, where
//! revision width is 20 or 32. Each value names the field and its holder:
//! report content, verifier output, judged transcript or landed revision.
//! Repeated use of a digest retains every naming move; aliases of one task do
//! not duplicate its records.

use alloc::collections::BTreeMap;
use core::fmt;

use anodized::spec;
use domhringr_record_tree::Kind;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::TreeId;
use gandr_storage_records::OwnedKeyBound;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::OwnedRecordKey;
use gandr_storage_records::OwnedRecordValue;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::TreeParams;
use gandr_storage_values::CanonicalValue;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::TokenBody;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::Index;
use crate::IndexKind;
use crate::MoveKey;
use crate::dialogue::MoveValue;

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
    /// The complete family prefix, excluding the task and move coordinates.
    ///
    /// # Specification
    /// - ensures: evidence uses `0x01 || digest`; revisions use `0x02 || width
    ///   || revision`, with width 20 or 32.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — repeated digests and both revision widths separate
    ///   family, subject and move boundaries.
    /// - witness: `provenance::tests::a_digest_named_twice_has_two_records`
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[spec(ensures: |ret| matches!(ret.as_ref().len(), 22 | 33 | 34))]
    #[inline]
    #[must_use]
    pub fn prefix(self) -> OwnedRecordKey
    {
        let mut bytes = Vec::with_capacity(34);
        match self {
            Self::Evidence(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(digest.as_ref());
            },
            Self::Revision(revision) => {
                bytes.push(2);
                bytes.push(match revision {
                    Revision::Sha1(_) => 20,
                    Revision::Sha256(_) => 32,
                });
                bytes.extend_from_slice(revision.as_ref());
            },
        }
        OwnedRecordKey::from(bytes.into_boxed_slice())
    }

    /// Select every naming move of this subject, and no adjacent subject.
    ///
    /// # Specification
    /// - ensures: the lower bound includes the complete prefix and the upper
    ///   bound excludes its shortest lexicographic successor.
    /// - fails: propagates a record range refusal.
    /// - panics: none.
    /// - executable: none — the prefix-bound constructor is its own
    ///   specification; verified ranges and maximal suffix bytes provide the
    ///   independent oracle.
    ///
    /// # Errors
    /// - [`RecordTreeError`]: the record plane refused the bounds.
    ///
    /// # Adequacy
    /// - hypothesis: L1/L3 — verified prefix ranges contain exactly the named
    ///   moves, including a digest ending in all maximal bytes.
    /// - witness: `provenance::tests::a_digest_named_twice_has_two_records`
    #[inline]
    pub fn range(self) -> Result<OwnedKeyRange, RecordTreeError>
    {
        let prefix = self.prefix();
        let mut upper = prefix.as_ref().to_vec();
        while let Some(last) = upper.pop() {
            if let Ok(next) = quenchant_arith::arith::checked_add(
                quenchant_arith::arith::Int::from(last),
                quenchant_arith::arith::Int::from(1_u8),
            ) {
                upper.push(u8::from(next));
                break;
            }
        }
        let lower = OwnedKeyBound::Included(prefix);
        let upper = OwnedKeyBound::Excluded(upper.into());
        let range = gandr_storage_records::KeyRange::new(lower.as_bound(), upper.as_bound())?;
        Ok(OwnedKeyRange::from_range(range))
    }

    /// Append the task identity and its fixed-width move coordinate.
    ///
    /// # Specification
    /// - ensures: decoding the key recovers this subject, task and coordinate.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L2/L3 — the fold's evidence and distinct naming moves
    ///   distinguish loss of a subject, task or coordinate.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    /// - witness: `provenance::tests::a_digest_named_twice_has_two_records`
    #[spec(ensures: |ret| Reference::try_from(ret.as_ref()).is_ok_and(|reference|
        reference == Reference { subject: self, tree, position }))]
    #[inline]
    #[must_use]
    pub fn key(
        self,
        tree: TreeId,
        position: MoveKey,
    ) -> OwnedRecordKey
    {
        let mut bytes = Vec::with_capacity(74);
        match self {
            Self::Evidence(digest) => {
                bytes.push(1);
                bytes.extend_from_slice(digest.as_ref());
            },
            Self::Revision(revision) => {
                bytes.push(2);
                bytes.push(match revision {
                    Revision::Sha1(_) => 20,
                    Revision::Sha256(_) => 32,
                });
                bytes.extend_from_slice(revision.as_ref());
            },
        }
        bytes.extend_from_slice(tree.as_ref());
        bytes.extend_from_slice(position.as_ref());
        OwnedRecordKey::from(bytes.into_boxed_slice())
    }
}

/// A decoded provenance key, sufficient to locate the original receipt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Reference
{
    /// The evidence manifest or landed revision.
    pub subject: Subject,
    /// The task tree, independent of its aliases in the project.
    pub tree: TreeId,
    /// The move at the attested dialogue frontier.
    pub position: MoveKey,
}

impl TryFrom<&[u8]> for Reference
{
    type Error = ProvenanceError;

    /// Decode a key without accepting suffixes, foreign families or bad widths.
    ///
    /// # Specification
    /// - ensures: re-encoding the decoded reference yields exactly the input.
    /// - fails: malformed keys return `ProvenanceError::Key`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ProvenanceError::Key`]: an unsupported family, width or tree key.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — both revision widths and malformed/trailing keys
    ///   separate all key boundaries.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[spec(ensures: |ret| ret.is_err() || matches!(bytes.len(), 62 | 73 | 74))]
    #[inline]
    fn try_from(bytes: &[u8]) -> Result<Self, Self::Error>
    {
        let (tag, bytes) = bytes.split_first().ok_or(ProvenanceError::Key)?;
        let (subject, bytes) = match *tag {
            1 => {
                let (digest, bytes) = bytes.split_at_checked(32).ok_or(ProvenanceError::Key)?;
                let digest = <[u8; 32]>::try_from(digest).map_err(|_width| ProvenanceError::Key)?;
                (Subject::Evidence(ManifestDigest::from(digest)), bytes)
            },
            2 => {
                let (width, bytes) = bytes.split_first().ok_or(ProvenanceError::Key)?;
                let (revision, bytes) = bytes
                    .split_at_checked(usize::from(*width))
                    .ok_or(ProvenanceError::Key)?;
                let revision =
                    Revision::try_from(revision).map_err(|_width| ProvenanceError::Key)?;
                (Subject::Revision(revision), bytes)
            },
            _foreign => return Err(ProvenanceError::Key),
        };
        let (tree, position) = bytes.split_at_checked(32).ok_or(ProvenanceError::Key)?;
        let tree = <[u8; 32]>::try_from(tree).map_err(|_width| ProvenanceError::Key)?;
        let tree = TreeId::try_from(tree).map_err(|_key| ProvenanceError::Key)?;
        let position = MoveKey::try_from(position).map_err(|_coordinate| ProvenanceError::Key)?;
        Ok(Self {
            subject,
            tree,
            position,
        })
    }
}

/// The receipt field through which a move names its subject.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
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

/// The field and responsible peer carried by a provenance record.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attribution
{
    /// Which receipt field names the subject.
    pub field: Field,
    /// The evidence holder, or the landing's operator.
    pub holder: PeerKey,
}

impl CanonicalValue for Attribution
{
    /// Encode the field tag and responsible peer without losing either.
    ///
    /// # Specification
    /// - ensures: tags one through four name content, output, transcript and
    ///   revision respectively, followed by the peer's 32 bytes.
    /// - fails: propagates token sink failures.
    /// - panics: none.
    /// - executable: none — the generic sink exposes no readback; decoded
    ///   fields and holders are compared with independently folded evidence.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — all fields retain the independently folded holder.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        let tag = match self.field {
            Field::Content => 1,
            Field::Output => 2,
            Field::Transcript => 3,
            Field::Revision => 4,
        };
        sink.open(ConstructorTag::from(tag))?;
        sink.bytes(TokenBytes::from(self.holder.as_ref()))?;
        sink.close()
    }

    /// Decode the field and peer, refusing unsupported fields and widths.
    ///
    /// # Specification
    /// - ensures: preserves every encoded field and holder.
    /// - fails: unknown tags, malformed peers and framing return `ValueError`.
    /// - panics: none.
    /// - executable: none — the consuming token reader exposes no replay; all
    ///   four fields and malformed widths are checked independently.
    ///
    /// # Errors
    /// - [`ValueError`]: malformed attribution.
    ///
    /// # Adequacy
    /// - hypothesis: L2/L3 — all four fields round-trip; an unknown tag and
    ///   wrong peer width cannot masquerade as an attribution.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let position = reader.position();
        let found = reader.read_tag()?;
        let refused = || ValueError::UnexpectedConstructor { found, position };
        let field = match u8::from(found) {
            1 => Field::Content,
            2 => Field::Output,
            3 => Field::Transcript,
            4 => Field::Revision,
            _foreign => return Err(refused()),
        };
        let holder = reader.read_bytes()?;
        let holder = <[u8; 32]>::try_from(<&[u8]>::from(holder)).map_err(|_width| refused())?;
        reader.read_close()?;
        Ok(Self {
            field,
            holder: PeerKey::from(holder),
        })
    }
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

/// Sorted provenance records collected from distinct task dialogues.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Records(BTreeMap<OwnedRecordKey, OwnedRecordValue>);

impl Records
{
    /// Collect naming moves, retaining one record per subject/task/coordinate.
    ///
    /// # Specification
    /// - requires: `dialogue` is independently derived or authenticated.
    /// - ensures: aliases of one task do not duplicate its records; every
    ///   provenance-bearing move has its original field and holder.
    /// - fails: foreign index kinds, malformed move keys/values and receipts
    ///   naming another task are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ProvenanceError`]: a source dialogue is malformed.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — compare all records with the fold's evidence and
    ///   landing steps, including aliases and non-evidence moves.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[spec(captures: before = self.0.len(), ensures: |ret| ret.is_err() ||
        arith::checked_sub(Int::from(self.0.len()), Int::from(before))
            .is_ok_and(|added| usize::from(added) <= dialogue.tree.records().len()))]
    #[inline]
    pub fn extend(
        &mut self,
        tree: TreeId,
        dialogue: &Index,
    ) -> Result<(), ProvenanceError>
    {
        if dialogue.manifest.kind() != IndexKind::Dialogue {
            return Err(ProvenanceError::Dialogue);
        }
        for record in dialogue.tree.records() {
            let position =
                MoveKey::try_from(record.key().as_ref()).map_err(|_key| ProvenanceError::Key)?;
            let value = decode_flat::<MoveValue<'_>>(TokenBody::from(record.value().as_ref()))?;
            let receipt = value.receipt()?;
            if receipt.tree() != tree {
                return Err(ProvenanceError::Tree {
                    expected: tree,
                    actual: receipt.tree(),
                });
            }
            if let Naming::Named(subject, attribution) = naming(value.author, &receipt) {
                let value = encode_flat(&attribution)?;
                let _previous = self.0.insert(
                    subject.key(tree, position),
                    OwnedRecordValue::from(value.as_ref()),
                );
            }
        }
        Ok(())
    }

    /// Build the one provenance tree covering the collected dialogues.
    ///
    /// # Specification
    /// - ensures: the manifest binds kind provenance and every collected
    ///   record.
    /// - fails: propagates a record-tree construction refusal.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`RecordTreeError`]: the record plane refused construction.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — exact records agree with independent folded evidence.
    /// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |index| index.tree.records().len() == self.0.len()))]
    #[inline]
    pub fn build(&self) -> Result<Index, RecordTreeError>
    {
        let records: Vec<_> = self
            .0
            .iter()
            .map(|(key, value)| RecordRef::new(key.as_ref(), value.as_ref()))
            .collect();
        let tree = RecordTree::build(&records, TreeParams::current())?;
        Ok(Index::new(IndexKind::Provenance, tree))
    }
}

/// A malformed provenance key or source dialogue.
#[derive(Debug, thiserror::Error)]
pub enum ProvenanceError
{
    /// A key has an unsupported family, width, task or coordinate.
    #[error("malformed provenance key")]
    Key,
    /// Only dialogue indexes contain original admitted moves.
    #[error("provenance source is not a dialogue")]
    Dialogue,
    /// A source move names another task.
    #[error("provenance move names {actual}, expected {expected}")]
    Tree
    {
        /// The task whose dialogue was supplied.
        expected: TreeId,
        /// The tree carried by the original receipt.
        actual: TreeId,
    },
    /// The move or its attribution is not a canonical value.
    #[error(transparent)]
    Value(#[from] ValueError),
}

#[cfg(test)]
mod tests;
