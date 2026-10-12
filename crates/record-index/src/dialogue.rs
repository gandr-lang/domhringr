//! Canonical fold positions and original receipt bytes form a dialogue.
//!
//! A dialogue keys admitted moves by `(attempt, seq)`: two big-endian `u32`
//! fields, with attempts starting at one and each dispatch at sequence zero.
//! Numbering follows the fold's canonical order, not arrival order. A move
//! value retains its original receipt bytes and verified author; its commit
//! identity is recomputed from those bytes. Refused receipts and non-move
//! receipts have no dialogue entry. Coordinates belong to one manifest: a late
//! concurrent move can shift later coordinates in its attempt.

use alloc::borrow::Cow;
use alloc::collections::BTreeMap;

use anodized::spec;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::MoveSource;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Step;
use domhringr_record_tree::Task;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::TreeParams;
use gandr_storage_values::CanonicalValue;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBody;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::AttemptNumber;
use crate::Index;
use crate::IndexKind;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::key::KeyError;

/// A move's attested author and original, unmodified receipt image.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MoveValue<'receipt>
{
    /// The author claimed by the attester; re-derivation checks the signature.
    pub author: PeerKey,
    /// The original receipt bytes, borrowed during derivation.
    pub blob: Cow<'receipt, [u8]>,
}

impl<'receipt> From<&'receipt MoveSource> for MoveValue<'receipt>
{
    /// Borrow an admitted move without copying its receipt.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(source: &'receipt MoveSource) -> Self
    {
        Self {
            author: source.author,
            blob: Cow::Borrowed(source.blob.as_slice()),
        }
    }
}

impl MoveValue<'_>
{
    /// Recompute the original receipt's commit identity.
    ///
    /// # Specification
    /// - ensures: the digest covers exactly the carried receipt bytes.
    /// - panics: none.
    /// - executable: none — the digest is its own specification; the signed
    ///   commits admitted by the fold supply independent identities.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the fold's commit identities independently agree.
    /// - witness: `dialogue::tests::the_dialogue_agrees_with_the_fold_on_every_kind`
    #[inline]
    #[must_use]
    pub fn commit(&self) -> CommitId
    {
        CommitId::new(*blake3::hash(self.blob.as_ref()).as_bytes())
    }

    /// Read the receipt without re-encoding its original bytes.
    ///
    /// # Specification
    /// - ensures: decodes the original receipt, including editionless
    ///   dispatches.
    /// - fails: malformed receipt tokens are refused by the receipt codec.
    /// - panics: none.
    /// - executable: none — the receipt decoder is its own specification; the
    ///   independently folded steps identify every decoded receipt kind.
    ///
    /// # Errors
    /// - [`ValueError`]: malformed receipt.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — every admitted kind agrees with the fold's step.
    /// - witness: `dialogue::tests::the_dialogue_agrees_with_the_fold_on_every_kind`
    #[inline]
    pub fn receipt(&self) -> Result<Receipt, ValueError>
    {
        decode_flat(TokenBody::from(self.blob.as_ref()))
    }
}

impl CanonicalValue for MoveValue<'_>
{
    /// Emit `open move · bytes author · bytes receipt · close`.
    ///
    /// # Specification
    /// - ensures: preserves author and original blob exactly, under tag one.
    /// - fails: propagates the sink refusal.
    /// - panics: none.
    /// - executable: none — the generic sink exposes no readback; decoded
    ///   values are compared with the original signed commits.
    ///
    /// # Errors
    /// - [`ValueError`]: the sink refused a token.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — decoded values agree with original signed commits.
    /// - witness: `dialogue::tests::the_dialogue_agrees_with_the_fold_on_every_kind`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        sink.open(ConstructorTag::from(1))?;
        sink.bytes(TokenBytes::from(self.author.as_ref()))?;
        sink.bytes(TokenBytes::from(self.blob.as_ref()))?;
        sink.close()
    }

    /// Decode a move's claim, leaving signature checking to re-derivation.
    ///
    /// # Specification
    /// - ensures: reads exactly one move with a 32-byte author.
    /// - fails: unknown tags, malformed authors and token framing are refused.
    /// - panics: none.
    /// - executable: none — the consuming token reader exposes no replay;
    ///   decoded authors and blobs are checked against the signed commits.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, author or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — all admitted kinds retain author and original bytes.
    /// - witness: `dialogue::tests::the_dialogue_agrees_with_the_fold_on_every_kind`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let position = reader.position();
        let found = reader.read_tag()?;
        let refused = || ValueError::UnexpectedConstructor { found, position };
        if u8::from(found) != 1 {
            return Err(refused());
        }
        let author = reader.read_bytes()?;
        let author = <[u8; 32]>::try_from(<&[u8]>::from(author)).map_err(|_width| refused())?;
        let blob = reader.read_bytes()?;
        let blob = Cow::Owned(<&[u8]>::from(blob).to_vec());
        reader.read_close()?;
        Ok(Self {
            author: PeerKey::from(author),
            blob,
        })
    }
}

/// One derived dialogue and its number of admitted dispatches.
#[derive(Debug)]
pub struct Dialogue
{
    /// The committed record tree.
    pub index: Index,
    /// The last one-based attempt, or zero for an undispatched task.
    pub attempts: AttemptNumber,
}

/// Why the fold's moves could not become a dialogue.
#[derive(Debug, thiserror::Error)]
pub enum DialogueError
{
    /// A coordinate exceeded its wire width.
    #[error(transparent)]
    Coordinate(#[from] KeyError),
    /// The admitted steps and original sources do not correspond.
    #[error("admitted move sources do not match the fold")]
    Sources,
    /// A step named no previously admitted dispatch.
    #[error("no admitted dispatch {0}")]
    Dispatch(CommitId),
    /// The value codec refused the move image.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// The record plane refused the records.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
}

/// Derive positions from canonical admission order, grouped by dispatch.
///
/// # Specification
/// - ensures: each admitted step has one distinct coordinate; dispatches count
///   from one and each dispatch occupies sequence zero.
/// - fails: missing source, dispatch, overflowing coordinate or record refusal.
/// - panics: none.
///
/// # Errors
/// - [`DialogueError`]: a source invariant or storage boundary failed.
///
/// # Adequacy
/// - hypothesis: L2 — the fold supplies independent kinds, authors and
///   identities; L3 — concurrent dispatches and moves distinguish both
///   counters.
/// - witness: `dialogue::tests::the_dialogue_agrees_with_the_fold_on_every_kind`
/// - witness: `dialogue::tests::concurrent_moves_of_two_authors_take_distinct_keys`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |dialogue|
    dialogue.index.tree.records().len() == task.steps().len()
    && usize::try_from(dialogue.attempts.0).is_ok_and(|count|
        count == task.steps().iter().filter(|entry| matches!(entry.1, Step::Dispatch { .. })).count())))]
#[inline]
pub fn derive(task: &Task) -> Result<Dialogue, DialogueError>
{
    if task.steps().len() != task.sources().len() {
        return Err(DialogueError::Sources);
    }
    let mut attempts = AttemptNumber(0);
    let mut positions = BTreeMap::new();
    let mut encoded = Vec::with_capacity(task.steps().len());
    for (&(commit, ref step), source) in task.steps().iter().zip(task.sources()) {
        if commit != source.commit {
            return Err(DialogueError::Sources);
        }
        let (attempt, seq) = match *step {
            | Step::Dispatch { .. } => {
                attempts = attempts.next()?;
                let previous = positions.insert(commit, (attempts, SequenceNumber(0)));
                if previous.is_some() {
                    return Err(DialogueError::Sources);
                }
                (attempts, SequenceNumber(0))
            },
            | Step::Report { ref dispatch, .. }
            | Step::Handoff { ref dispatch, .. }
            | Step::Retire { ref dispatch, .. }
            | Step::Pause { ref dispatch, .. }
            | Step::Verdict { ref dispatch, .. }
            | Step::Verified { ref dispatch, .. }
            | Step::Graded { ref dispatch, .. }
            | Step::Decide { ref dispatch, .. }
            | Step::Landed { ref dispatch, .. } => {
                let position = positions
                    .get_mut(dispatch)
                    .ok_or(DialogueError::Dispatch(*dispatch))?;
                let seq = arith::checked_add(Int::from(position.1.0), Int::from(1))
                    .map_err(|_overflow| KeyError::Overflow)?;
                position.1 = SequenceNumber(u32::from(seq));
                *position
            },
        };
        let value = encode_flat(&MoveValue::from(source))?;
        encoded.push((MoveKey::new(attempt, seq), value));
    }
    encoded.sort_unstable_by_key(|&(key, _)| key);
    let records: Vec<_> = encoded
        .iter()
        .map(|entry| RecordRef::new(entry.0.as_ref(), entry.1.as_ref()))
        .collect();
    let tree = RecordTree::build(&records, TreeParams::current())?;
    Ok(Dialogue {
        index: Index::new(IndexKind::Dialogue, tree),
        attempts,
    })
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;
    use alloc::collections::BTreeSet;

    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Brief;
    use domhringr_record_tree::Code;
    use domhringr_record_tree::Current;
    use domhringr_record_tree::Edition;
    use domhringr_record_tree::Heads;
    use domhringr_record_tree::IndexDigest;
    use domhringr_record_tree::Kind;
    use domhringr_record_tree::Receipt;
    use domhringr_record_tree::Status;
    use domhringr_record_tree::Step;
    use domhringr_record_tree::Target;
    use gandr_storage_values::TokenBody;
    use gandr_storage_values::decode_flat;
    use quenchant_arith::arith;
    use quenchant_arith::arith::Int;

    use super::MoveValue;
    use super::derive;
    use crate::AttemptNumber;
    use crate::MoveKey;
    use crate::SequenceNumber;
    use crate::testing::Fence;
    use crate::testing::Fixture;
    use crate::testing::evidence;
    use crate::testing::fenced;
    use crate::testing::hash;
    use crate::testing::key;
    use crate::testing::member;
    use crate::testing::owner;
    use crate::testing::peer;
    use crate::testing::runtime;
    use crate::testing::seal;
    use crate::testing::seat;
    use crate::testing::stranger;
    use crate::testing::tree;

    #[test]
    fn concurrent_moves_of_two_authors_take_distinct_keys()
    {
        runtime().block_on(async {
            let mut fixture = Fixture::new().await;
            fixture.commits.truncate(4);
            let dispatch = fixture.commits[2].payload().head();
            let report = fixture.commits[3].payload().head();
            let verified = seal(
                &owner(),
                &fenced(
                    &Receipt::verified(
                        tree(),
                        dispatch,
                        key(&owner()),
                        hash(),
                        "check".parse().unwrap(),
                        evidence(),
                        Status::Exited(Code::from(0_i32)),
                    )
                    .unwrap(),
                    Fence(100),
                ),
                BTreeSet::from([report]),
            )
            .await;
            let verification = verified.payload().head();
            let mut fence = 101_u128;
            let retired = loop {
                let candidate = seal(
                    &seat(),
                    &fenced(&Receipt::retire(tree(), dispatch).unwrap(), Fence(fence)),
                    BTreeSet::from([report]),
                )
                .await;
                if candidate.payload().head() < verification {
                    break candidate;
                }
                fence = u128::from(arith::checked_add(Int::from(fence), Int::from(1)).unwrap());
            };
            let retirement = retired.payload().head();
            let parents = BTreeSet::from([retirement, verification]);
            let a = seal(
                &owner(),
                &fenced(
                    &Receipt::dispatch(
                        tree(),
                        key(&seat()),
                        Edition::CURRENT,
                        Brief::Content(hash()),
                    )
                    .unwrap(),
                    Fence(200),
                ),
                parents.clone(),
            )
            .await;
            let b = seal(
                &member(),
                &fenced(
                    &Receipt::dispatch(
                        tree(),
                        key(&seat()),
                        Edition::CURRENT,
                        Brief::Content(hash()),
                    )
                    .unwrap(),
                    Fence(201),
                ),
                parents,
            )
            .await;
            let later = [a.payload().head(), b.payload().head()];
            fixture.commits.extend([verified, retired, a, b]);
            let root = tempfile::tempdir().unwrap();
            let peer = peer(root.path(), fixture.commits).await;
            let early = peer
                .view_at(tree(), &Heads::from_iter([verification]))
                .await
                .unwrap();
            let late = peer
                .view_at(tree(), &Heads::from_iter([retirement, verification]))
                .await
                .unwrap();
            let positions = |view: &domhringr_record_tree::View| {
                derive(view.task())
                    .unwrap()
                    .index
                    .tree
                    .records()
                    .iter()
                    .map(|record| {
                        let value: MoveValue<'_> =
                            decode_flat(TokenBody::from(record.value().as_ref())).unwrap();
                        (
                            value.commit(),
                            MoveKey::try_from(record.key().as_ref())
                                .unwrap()
                                .coordinates(),
                        )
                    })
                    .collect::<BTreeMap<_, _>>()
            };
            assert_eq!(
                positions(&early),
                BTreeMap::from([
                    (dispatch, (AttemptNumber(1), SequenceNumber(0))),
                    (report, (AttemptNumber(1), SequenceNumber(1))),
                    (verification, (AttemptNumber(1), SequenceNumber(2))),
                ])
            );
            assert_eq!(
                positions(&late),
                BTreeMap::from([
                    (dispatch, (AttemptNumber(1), SequenceNumber(0))),
                    (report, (AttemptNumber(1), SequenceNumber(1))),
                    (retirement, (AttemptNumber(1), SequenceNumber(2))),
                    (verification, (AttemptNumber(1), SequenceNumber(3))),
                ])
            );
            let view = peer.view(tree()).await.unwrap();
            drop(peer);
            let ordered = positions(&view);
            assert_eq!(
                ordered[&later[0].min(later[1])],
                (AttemptNumber(2), SequenceNumber(0))
            );
            assert_eq!(
                ordered[&later[0].max(later[1])],
                (AttemptNumber(3), SequenceNumber(0))
            );
            let Current::Attempt(ref current) = *view.task().current()
            else {
                panic!("current dispatch");
            };
            assert_eq!(current.dispatch(), later[0].max(later[1]));
            assert_eq!(derive(view.task()).unwrap().attempts, AttemptNumber(3));
        });
    }

    #[test]
    fn the_dialogue_agrees_with_the_fold_on_every_kind()
    {
        runtime().block_on(async {
            let mut fixture = Fixture::new().await;
            let root = tempfile::tempdir().unwrap();
            let original = peer(root.path(), fixture.commits.clone()).await;
            let reference = original.view(tree()).await.unwrap();
            drop(original);
            assert!(reference.refused().is_empty(), "{:?}", reference.refused());
            assert_eq!(
                reference.task().steps().len(),
                if Edition::CURRENT == Edition::TWO {
                    12
                }
                else {
                    11
                }
            );
            let mut rejected = BTreeSet::new();
            let first = fixture.commits[2].payload().head();
            let first_report = fixture.commits[3].payload().head();
            let mut fence = 999_u128;
            let premature = loop {
                let candidate = seal(
                    &seat(),
                    &fenced(&Receipt::retire(tree(), first).unwrap(), Fence(fence)),
                    BTreeSet::from([first]),
                )
                .await;
                if candidate.payload().head() < first_report {
                    break candidate;
                }
                fence = u128::from(arith::checked_add(Int::from(fence), Int::from(1)).unwrap());
            };
            let premature_id = premature.payload().head();
            assert!(rejected.insert(premature_id));
            fixture.commits.push(premature);
            let paused = fixture
                .push(
                    &stranger(),
                    Receipt::pause(tree(), fixture.dispatch).unwrap(),
                    Fence(998),
                )
                .await;
            assert!(rejected.insert(paused));
            for (offset, source) in reference.task().sources().iter().enumerate() {
                let receipt: Receipt =
                    decode_flat(TokenBody::from(source.blob.as_slice())).unwrap();
                let id = fixture
                    .push(
                        &stranger(),
                        receipt,
                        Fence(u128::from(
                            arith::checked_add(
                                Int::from(1000_u128),
                                Int::from(u128::try_from(offset).unwrap()),
                            )
                            .unwrap(),
                        )),
                    )
                    .await;
                assert!(rejected.insert(id));
            }
            for (offset, receipt) in [
                Receipt::note(tree(), "not a move".into()).unwrap(),
                Receipt::bind(
                    tree(),
                    "tasks/example".parse().unwrap(),
                    Target::Anchor(Anchor::key(tree())),
                )
                .unwrap(),
                Receipt::claim(tree(), "example.test".parse().unwrap()).unwrap(),
                Receipt::introduce(tree(), "example".parse().unwrap(), tree()).unwrap(),
                Receipt::indexed(tree(), IndexDigest::from([0; 32])).unwrap(),
                crate::testing::presence(),
                Receipt::withdraw(tree(), key(&owner())).unwrap(),
            ]
            .into_iter()
            .enumerate()
            {
                let _nonmove = fixture
                    .push(
                        &owner(),
                        receipt,
                        Fence(u128::from(
                            arith::checked_add(
                                Int::from(2000_u128),
                                Int::from(u128::try_from(offset).unwrap()),
                            )
                            .unwrap(),
                        )),
                    )
                    .await;
            }
            let root = tempfile::tempdir().unwrap();
            let peer = peer(root.path(), fixture.commits).await;
            let view = peer.view(tree()).await.unwrap();
            drop(peer);
            let refused: BTreeSet<_> = view.refused().iter().map(|entry| entry.0).collect();
            assert_eq!(rejected, refused);
            assert!(matches!(
                view.refused()
                    .iter()
                    .find(|entry| entry.0 == premature_id)
                    .unwrap()
                    .1,
                domhringr_record_tree::Refusal::Protocol(_)
            ));
            let dialogue = derive(view.task()).unwrap();
            assert_eq!(dialogue.attempts, AttemptNumber(2));
            assert_eq!(
                dialogue.index.tree.records().len(),
                reference.task().steps().len()
            );
            let originals: BTreeMap<_, _> = reference
                .task()
                .sources()
                .iter()
                .map(|source| (source.commit, source))
                .collect();
            let steps: BTreeMap<_, _> = reference
                .task()
                .steps()
                .iter()
                .map(|entry| (entry.0, &entry.1))
                .collect();
            for record in dialogue.index.tree.records() {
                let value: MoveValue<'_> =
                    decode_flat(TokenBody::from(record.value().as_ref())).unwrap();
                let source = originals[&value.commit()];
                assert_eq!(value.author, source.author);
                assert_eq!(value.blob.as_ref(), source.blob.as_slice());
                assert!(!rejected.contains(&value.commit()));
                let receipt = value.receipt().unwrap();
                assert_eq!(receipt.tree(), tree());
                let step = match *receipt.kind() {
                    | Kind::Dispatch {
                        ref edition,
                        ref seat,
                        ref brief,
                    } => Step::Dispatch {
                        edition: *edition,
                        seat: *seat,
                        brief: brief.clone(),
                    },
                    | Kind::Report {
                        ref dispatch,
                        ref content,
                        ref summary,
                    } => Step::Report {
                        dispatch: *dispatch,
                        author: value.author,
                        content: *content,
                        summary: summary.clone(),
                    },
                    | Kind::Handoff {
                        ref dispatch,
                        ref to,
                    } => Step::Handoff {
                        dispatch: *dispatch,
                        from: value.author,
                        to: *to,
                    },
                    | Kind::Retire { ref dispatch } => Step::Retire {
                        dispatch: *dispatch,
                        author: value.author,
                    },
                    | Kind::Pause { ref dispatch } => Step::Pause {
                        dispatch: *dispatch,
                        author: value.author,
                    },
                    | Kind::Verdict {
                        ref dispatch,
                        ref judge,
                        ref rubric,
                        ref transcript,
                        ref answers,
                    } => Step::Verdict {
                        dispatch: *dispatch,
                        judge: *judge,
                        rubric: *rubric,
                        transcript: *transcript,
                        answers: answers.clone(),
                    },
                    | Kind::Verified {
                        ref dispatch,
                        ref runner,
                        ref playbook,
                        ref step,
                        ref output,
                        ref status,
                    } => Step::Verified {
                        dispatch: *dispatch,
                        runner: *runner,
                        playbook: *playbook,
                        step: step.clone(),
                        output: *output,
                        status: *status,
                    },
                    | Kind::Graded {
                        ref verdict,
                        ref grades,
                        ref composed,
                    } => {
                        let verdict_source = MoveValue::from(originals[verdict]);
                        let verdict_receipt = verdict_source.receipt().unwrap();
                        let Kind::Verdict {
                            ref dispatch,
                            ref rubric,
                            ref answers,
                            ..
                        } = *verdict_receipt.kind()
                        else {
                            panic!("graded verdict");
                        };
                        Step::Graded {
                            dispatch: *dispatch,
                            verdict: *verdict,
                            rubric: *rubric,
                            grades: answers
                                .iter()
                                .zip(grades)
                                .map(|(answer, grade)| (answer.0, *grade))
                                .collect(),
                            composed: *composed,
                        }
                    },
                    | Kind::Decide {
                        ref dispatch,
                        ref operator,
                        ref decision,
                    } => Step::Decide {
                        dispatch: *dispatch,
                        operator: *operator,
                        decision: decision.clone(),
                    },
                    | Kind::Landed {
                        ref decided,
                        ref merge,
                    } => {
                        let decision_source = MoveValue::from(originals[decided]);
                        let decision_receipt = decision_source.receipt().unwrap();
                        let Kind::Decide {
                            ref dispatch,
                            ref operator,
                            ..
                        } = *decision_receipt.kind()
                        else {
                            panic!("land decision");
                        };
                        Step::Landed {
                            dispatch: *dispatch,
                            decided: *decided,
                            operator: *operator,
                            merge: *merge,
                        }
                    },
                    | ref _nonmove => panic!("non-move in dialogue"),
                };
                assert_eq!(&step, steps[&value.commit()]);
            }
        });
    }
}
