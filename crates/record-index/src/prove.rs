//! Questions authenticated against an attested manifest, without a held tree.

#[cfg(test)]
mod tests;

use anodized::spec;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Kind;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::TreeId;
use gandr_storage_records::MembershipProof;
use gandr_storage_records::NonMembershipEvidence;
use gandr_storage_records::NonMembershipProof;
use gandr_storage_records::OwnedKeyRange;
use gandr_storage_records::OwnedRecordKey;
use gandr_storage_records::RangeProof;
use gandr_storage_records::Record;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::RecordValue;
use gandr_storage_values::TokenBody;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;

use crate::Index;
use crate::IndexKind;
use crate::Manifest;
use crate::ManifestError;
use crate::dialogue::MoveValue;
use crate::wire::WireError;

/// One key or one contiguous range in the named index.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Query
{
    /// Presence or authenticated absence of this key.
    Key(OwnedRecordKey),
    /// Exactly the records in these bounds.
    Range(OwnedKeyRange),
}

/// Untrusted material answering one of the three record questions.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Proof
{
    /// A key and its claimed value.
    Present(MembershipProof),
    /// A key and its claimed neighbours.
    Absent(NonMembershipProof),
    /// The claimed complete range.
    Range(RangeProof),
}

/// A manifest and proof; neither is trusted before verification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Answer
{
    /// The proposed manifest, checked against the chosen attestation.
    pub manifest: Manifest,
    /// The material authenticated against its resealed root.
    pub proof: Proof,
}

/// An answer after root verification; presence borrows the authenticated bytes.
#[derive(Debug, PartialEq, Eq)]
pub enum Verified<'proof>
{
    /// The authenticated value at the requested key.
    Present(RecordValue<'proof>),
    /// The authenticated immediate neighbours of the absent key.
    Absent(NonMembershipEvidence),
    /// Every authenticated record in the requested range.
    Range(Box<[Record]>),
}

/// A decoded move whose receipt names the task selected by its project entry.
#[derive(Debug, PartialEq, Eq)]
pub struct Move
{
    /// The receipt's attested author.
    pub author: PeerKey,
    /// BLAKE3 of the original receipt image.
    pub commit: CommitId,
    /// The decoded original receipt, never reconstructed from a display.
    pub receipt: Receipt,
    /// The original receipt image, including any supported legacy layout.
    pub image: Box<[u8]>,
}

/// Whether a proved next-attempt key carries a later dispatch.
#[derive(Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "keep the decoded receipt inline rather than allocate on each authenticated later-attempt question"
)]
pub enum Later
{
    /// Sequence zero of the next attempt is a dispatch.
    Dispatch(Move),
    /// The absent next key has no successor in the whole dialogue.
    None,
}

/// Why a proof or decoded move cannot be trusted for this question.
#[derive(Debug, thiserror::Error)]
pub enum ProveError
{
    /// The received manifest is not the chosen content identity.
    #[error("index identity differs from attested {0}")]
    Identity(IndexDigest),
    /// The manifest belongs to another index language.
    #[error("index kind differs from the question")]
    Kind,
    /// A different question was answered.
    #[error("index proof answers another question")]
    Question,
    /// A later coordinate has a successor without its required dispatch.
    #[error("malformed dialogue: missing next dispatch")]
    MissingDispatch,
    /// The original receipt names another task tree.
    #[error("move names {actual}, expected {expected}")]
    Tree
    {
        /// The tree selected by the project entry.
        expected: TreeId,
        /// The tree in the original receipt.
        actual: TreeId,
    },
    /// A record proof failed its root or shape check.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
    /// A manifest cannot reseal a supported root.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// Manifest framing failed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// A move's canonical value or receipt is malformed.
    #[error(transparent)]
    Value(#[from] ValueError),
}

/// Answer a question from a held tree without conferring trust on the material.
///
/// # Specification
/// - ensures: the proof answers exactly the requested key or range.
/// - fails: a range or proof shape is refused by the record plane.
/// - panics: none.
///
/// # Errors
/// - [`ProveError`]: proof construction fails.
///
/// # Adequacy
/// - hypothesis: L1 — all keys and separating absent probes verify root-only.
/// - witness: `prove::tests::every_key_proves_against_the_manifest_alone`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |answer| match answer.proof {
    Proof::Present(ref proof) => match *query {
        Query::Key(ref key) => proof.verify(&index.tree.root(), key.as_borrowed(), proof.value()).is_ok(),
        Query::Range(_) => false,
    },
    Proof::Absent(ref proof) => match *query {
        Query::Key(ref key) => proof.verify(&index.tree.root(), key.as_borrowed()).is_ok(),
        Query::Range(_) => false,
    },
    Proof::Range(ref proof) => match *query {
        Query::Range(ref range) => range.as_range().is_ok_and(|range| proof.verify(&index.tree.root(), range).is_ok()),
        Query::Key(_) => false,
    },
}))]
#[inline]
pub fn answer(
    index: &Index,
    query: &Query,
) -> Result<Answer, ProveError>
{
    let proof = match *query {
        Query::Key(ref key) => {
            if index.tree.lookup(key.as_borrowed()).is_some() {
                let proof = index.tree.prove_membership(key.as_borrowed())?;
                Proof::Present(proof)
            }
            else {
                let proof = index.tree.prove_non_membership(key.as_borrowed())?;
                Proof::Absent(proof)
            }
        },
        Query::Range(ref range) => {
            let range = range.as_range()?;
            let proof = index.tree.prove_range(range)?;
            Proof::Range(proof)
        },
    };
    Ok(Answer {
        manifest: index.manifest,
        proof,
    })
}

impl Answer
{
    /// Authenticate an answer against the digest selected from the record tree.
    ///
    /// # Specification
    /// - ensures: returned bytes or neighbours are authenticated by the chosen
    ///   manifest's resealed root and answer exactly `query`.
    /// - fails: wrong identity, kind, query or record proof.
    /// - panics: none.
    /// - executable: none — the authentication boundary is its own
    ///   specification; root-only answers and forged proofs distinguish
    ///   acceptance from refusal.
    ///
    /// # Errors
    /// - [`ProveError`]: the answer does not establish this question.
    ///
    /// # Adequacy
    /// - hypothesis: L1 — present and separating absent probes verify
    ///   root-only; L3 — an invented dispatch fails by record error variant.
    /// - witness: `prove::tests::every_key_proves_against_the_manifest_alone`
    /// - witness: `prove::tests::a_forged_later_attempt_is_refused`
    #[inline]
    pub fn verify(
        &self,
        digest: IndexDigest,
        kind: IndexKind,
        query: &Query,
    ) -> Result<Verified<'_>, ProveError>
    {
        if self.manifest.kind() != kind {
            return Err(ProveError::Kind);
        }
        let actual = self.manifest.identity()?;
        if actual != digest {
            return Err(ProveError::Identity(digest));
        }
        let root = self.manifest.root()?;
        match (&self.proof, query) {
            (&Proof::Present(ref proof), &Query::Key(ref key)) => {
                proof.verify(&root, key.as_borrowed(), proof.value())?;
                Ok(Verified::Present(proof.value()))
            },
            (&Proof::Absent(ref proof), &Query::Key(ref key)) => {
                let evidence = proof.verify(&root, key.as_borrowed())?;
                Ok(Verified::Absent(evidence))
            },
            (&Proof::Range(ref proof), &Query::Range(ref range)) => {
                let range = range.as_range()?;
                let records = proof.verify(&root, range)?;
                Ok(Verified::Range(records))
            },
            _different => Err(ProveError::Question),
        }
    }
}

/// Decode an authenticated move and check its original receipt's task identity.
///
/// # Specification
/// - requires: `value` was authenticated under the entry's dialogue manifest.
/// - ensures: the returned receipt names `tree`; its commit hashes the original
///   bytes and its author is the author carried by the authenticated value.
/// - fails: malformed value, receipt or foreign task identity.
/// - panics: none.
/// - executable: none — the decoding and tree-identity boundary is its own
///   specification; authentic membership carrying a foreign task is the refusal
///   oracle.
///
/// # Errors
/// - [`ProveError`]: the value is not a move of the selected task.
///
/// # Adequacy
/// - hypothesis: L3 — an authentic membership carrying a foreign tree is
///   refused.
/// - witness: `prove::tests::a_move_naming_another_tree_is_refused`
#[inline]
pub fn read_move(
    tree: TreeId,
    value: RecordValue<'_>,
) -> Result<Move, ProveError>
{
    let value = decode_flat::<MoveValue<'_>>(TokenBody::from(value.as_ref()))?;
    let receipt = value.receipt()?;
    if receipt.tree() != tree {
        return Err(ProveError::Tree {
            expected: tree,
            actual: receipt.tree(),
        });
    }
    Ok(Move {
        author: value.author,
        commit: value.commit(),
        receipt,
        image: value.blob.into_owned().into_boxed_slice(),
    })
}

/// Authenticate an attempt's complete range and retain its original moves.
///
/// # Specification
/// - ensures: every returned coordinate belongs to `attempt`, in strict order;
///   each receipt names `tree` and retains its original image.
/// - fails: the proof, coordinate, or original receipt is malformed.
/// - panics: none.
///
/// # Errors
/// Returns `ProveError` for a different question or invalid proof or value.
///
/// # Adequacy
/// - hypothesis: L1 range authentication distinguishes altered and foreign
///   answers; L2 original bytes agree with the admitted receipt sources.
/// - witness: `replay::tests::proved_attempts_replay_every_standing`
#[spec(ensures: |ref output| output.as_ref().map_or(true, |moves|
    moves.iter().all(|entry| entry.0.coordinates().0 == attempt && entry.1.receipt.tree() == tree)
    && moves.windows(2).all(|pair| matches!(pair, [left, right] if left.0 < right.0))))]
#[inline]
pub fn play(
    answer: &Answer,
    digest: IndexDigest,
    tree: TreeId,
    attempt: crate::AttemptNumber,
) -> Result<Vec<(crate::MoveKey, Move)>, ProveError>
{
    let range = attempt.range()?;
    let Verified::Range(records) =
        answer.verify(digest, IndexKind::Dialogue, &Query::Range(range))?
    else {
        return Err(ProveError::Question);
    };
    records
        .iter()
        .map(|record| {
            let key = crate::MoveKey::try_from(record.key().as_ref())
                .map_err(|_key| ProveError::Question)?;
            let movement = read_move(tree, record.value())?;
            Ok((key, movement))
        })
        .collect()
}

/// Interpret the proved key immediately after an attempt as dispatch or end.
///
/// # Specification
/// - requires: `verified` answers `(n + 1, 0)` under the selected dialogue.
/// - ensures: dispatch membership returns that move; absence returns none only
///   when there is no successor; an absent dispatch before later records fails.
/// - fails: non-dispatch membership, foreign tree, range answer or malformed
///   move.
/// - panics: none.
/// - executable: none — the next-attempt classifier is its own specification;
///   authenticated end and invented dispatch probes distinguish its outcomes.
///
/// # Errors
/// - [`ProveError`]: this is not a well-formed next-attempt answer.
///
/// # Adequacy
/// - hypothesis: L3 — an invented dispatch fails; authentic end has no
///   successor.
/// - witness: `prove::tests::a_forged_later_attempt_is_refused`
#[inline]
pub fn later(
    tree: TreeId,
    verified: &Verified<'_>,
) -> Result<Later, ProveError>
{
    match *verified {
        Verified::Present(value) => {
            let step = read_move(tree, value)?;
            if !matches!(step.receipt.kind(), Kind::Dispatch { .. }) {
                return Err(ProveError::MissingDispatch);
            }
            Ok(Later::Dispatch(step))
        },
        Verified::Absent(ref evidence) if evidence.successor().is_none() => Ok(Later::None),
        Verified::Absent(_) => Err(ProveError::MissingDispatch),
        Verified::Range(_) => Err(ProveError::Question),
    }
}
