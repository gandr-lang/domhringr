//! Questions about a project store, answered from a held store or by a
//! proof against an attested root.
//!
//! Every read is one [`Question`] of the keyed schema and its [`Answer`]. A
//! reader that holds the store answers from its columns ([`Local`]). A reader
//! that holds only an attested root asks the attester and verifies each proof
//! against that root ([`crate::stream::Remote`]). The readers below are
//! written once, over [`Ask`], so both readers check the same things:
//!
//! - a name has at most one task;
//! - a task's attempts are numbered one to n, and the number of an attempt's
//!   moves runs from zero with the dispatch first;
//! - every move of a task names one tree;
//! - the standing tag is the kind of the standing recomputed from the last
//!   attempt's play.
//!
//! A proof shows what the attester put in its store, not that it agrees with
//! the fold; `index check` re-derives for that.

#[cfg(test)]
mod tests;

use alloc::collections::BTreeMap;

use anodized::spec;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Heads;
use domhringr_record_tree::Kind;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::TreeId;
use gandr_storage_schema::Answer;
use gandr_storage_schema::ArrowId;
use gandr_storage_schema::AttributeId;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::PartKey;
use gandr_storage_schema::Question;
use gandr_storage_schema::Refusal;
use gandr_storage_schema::Store;
use gandr_storage_schema::StoreError;
use gandr_storage_values::TokenBody;
use gandr_storage_values::ValueError;
use gandr_storage_values::decode_flat;

use crate::AttemptNumber;
use crate::MoveKey;
use crate::SequenceNumber;
use crate::dialogue::MoveValue;
use crate::key::KeyError;
use crate::keyed;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::keyed::Text;
use crate::keyed::ValueFault;
use crate::project::Refused;
use crate::project::TaskName;
use crate::provenance::Field;
use crate::provenance::Naming;
use crate::provenance::Subject;
use crate::provenance::naming as named_by;
use crate::replay;

/// Something that answers questions about one project store.
pub trait Ask
{
    /// Answer one question.
    ///
    /// # Specification
    /// - ensures: on success the answer the store holds for `question`; a
    ///   remote answer is verified against the attested root before it is
    ///   returned.
    /// - fails: the store refuses the question, or a proof doesn't verify.
    /// - panics: none.
    /// - executable: none — an answer is checked against the store or root it
    ///   is read from, which the trait does not name; the witness compares the
    ///   two readers.
    ///
    /// # Errors
    /// - [`ProveError`]: no trustworthy answer.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the local and the proving readers read the fixture
    ///   project alike.
    /// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
    fn ask(
        &mut self,
        question: &Question,
    ) -> impl Future<Output = Result<Answer, ProveError>> + Send;
}

/// A reader of a store it holds.
#[derive(Clone, Copy, Debug)]
#[repr(transparent)]
pub struct Local<'store>(pub &'store Store);

impl Local<'_>
{
    /// Read the answer from the store's columns.
    ///
    /// # Specification
    /// - ensures: the answer [`Store`]'s reads give; a preimage of a part that
    ///   isn't live is empty, as its proof would be.
    /// - fails: the store's refusal of an identifier or a dead cell.
    /// - panics: none.
    /// - executable: none — the function is the store's own reads; the witness
    ///   compares it with a proof of each question.
    ///
    /// # Errors
    /// - [`ProveError::Store`]: the store refuses the question.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the local and the proving readers read the fixture
    ///   project alike.
    /// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
    fn answer(
        self,
        question: &Question,
    ) -> Result<Answer, ProveError>
    {
        let store = self.0;
        let refused = |refusal: Refusal| ProveError::Store(StoreError::Refused(refusal));
        Ok(match *question {
            Question::Part { object, part } => {
                Answer::Liveness(store.liveness(object, part).map_err(refused)?)
            },
            Question::Arrow { arrow, part } => {
                Answer::Target(store.target(arrow, part).map_err(refused)?)
            },
            Question::Value { attribute, part } => {
                Answer::Value(store.value(attribute, part).map_err(refused)?.clone())
            },
            Question::Preimage { arrow, target } => match store.preimage(arrow, target) {
                Ok(parts) => Answer::Preimage(parts.into()),
                Err(Refusal::NotLive { .. }) => Answer::Preimage(Box::from([])),
                Err(refusal) => return Err(refused(refusal)),
            },
            Question::ValuePreimage {
                attribute,
                ref value,
            } => Answer::Preimage(
                store
                    .value_preimage(attribute, value)
                    .map_err(refused)?
                    .into(),
            ),
        })
    }
}

impl Ask for Local<'_>
{
    /// Answer from the store's columns, ready at once.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn ask(
        &mut self,
        question: &Question,
    ) -> impl Future<Output = Result<Answer, ProveError>> + Send
    {
        core::future::ready(self.answer(question))
    }
}

/// A decoded move, as its original receipt and claimed author.
#[derive(Clone, Debug, PartialEq, Eq)]
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

/// What a store claims about one task, read without its play.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Claim
{
    /// The task's part.
    pub task: PartKey,
    /// The standing's kind.
    pub standing: Standing,
    /// The frontier the task was derived at; empty when unheld.
    pub heads: Heads,
    /// Each attempt's part, attempt one first.
    pub attempts: Vec<PartKey>,
    /// The refused commits, in fold order.
    pub refused: Vec<Refused>,
}

/// Whether an attempt is followed by another.
#[derive(Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "keep the decoded receipt inline rather than allocate on each later-attempt question"
)]
pub enum Later
{
    /// The next attempt's dispatch.
    Dispatch(Move),
    /// No attempt follows.
    None,
}

/// One move's naming of a subject, read through the provenance tables.
#[derive(Debug, PartialEq, Eq)]
pub struct Named
{
    /// The task the move was made in.
    pub task: TaskName,
    /// The move's place.
    pub key: MoveKey,
    /// The receipt field naming the subject.
    pub field: Field,
    /// The peer holding the subject, or the landing's operator.
    pub holder: PeerKey,
    /// The move.
    pub movement: Move,
}

/// Why an answer can't be trusted for the question asked.
#[derive(Debug, thiserror::Error)]
pub enum ProveError
{
    /// The store refused the question or its proof didn't verify.
    #[error(transparent)]
    Store(#[from] StoreError),
    /// The holder couldn't be asked, or its reply is malformed.
    #[error(transparent)]
    Stream(#[from] crate::stream::StreamError),
    /// An answer of another shape than the question asks for.
    #[error("the answer has another shape than the question")]
    Shape,
    /// An attribute value isn't its type's canonical bytes.
    #[error(transparent)]
    Value(#[from] ValueFault),
    /// A move's canonical value or receipt is malformed.
    #[error(transparent)]
    Codec(#[from] ValueError),
    /// A stored number is past its coordinate's width.
    #[error(transparent)]
    Key(#[from] KeyError),
    /// No task carries the name.
    #[error("no task is named {0}")]
    Absent(TaskName),
    /// Two tasks carry one name.
    #[error("two tasks are named {0}")]
    Duplicate(TaskName),
    /// A task's attempts aren't numbered one to n.
    #[error("attempts are not numbered from one")]
    Attempts,
    /// An attempt's moves aren't placed from zero, or a later attempt
    /// doesn't open with a dispatch.
    #[error("attempt {0} is not placed from zero, or not opened by a dispatch")]
    Sequence(AttemptNumber),
    /// A move names another task tree than the task's other moves.
    #[error("move names {actual}, expected {expected}")]
    Tree
    {
        /// The tree the task's first move names.
        expected: TreeId,
        /// The tree this move names.
        actual: TreeId,
    },
    /// The standing tag isn't the kind of the standing the play reaches.
    #[error("standing {claimed} differs from the play's {recomputed}")]
    Standing
    {
        /// The tag the store holds.
        claimed: Standing,
        /// The kind recomputed from the last attempt.
        recomputed: Standing,
    },
    /// The last attempt's play doesn't resolve to a standing.
    #[error(transparent)]
    Recompute(#[from] replay::Refusal),
    /// A naming disagrees with the move it names.
    #[error("naming {0} disagrees with its move")]
    Naming(PartKey),
}

/// Ask for one attribute value.
///
/// # Specification
/// trivial.
async fn value<A>(
    ask: &mut A,
    attribute: AttributeId,
    part: PartKey,
) -> Result<AttributeValue, ProveError>
where
    A: Ask,
{
    match ask.ask(&Question::Value { attribute, part }).await? {
        Answer::Value(value) => Ok(value),
        Answer::Liveness(_) | Answer::Target(_) | Answer::Preimage(_) => Err(ProveError::Shape),
    }
}

/// Ask where an arrow takes a part.
///
/// # Specification
/// trivial.
async fn target<A>(
    ask: &mut A,
    arrow: ArrowId,
    part: PartKey,
) -> Result<PartKey, ProveError>
where
    A: Ask,
{
    match ask.ask(&Question::Arrow { arrow, part }).await? {
        Answer::Target(target) => Ok(target),
        Answer::Liveness(_) | Answer::Value(_) | Answer::Preimage(_) => Err(ProveError::Shape),
    }
}

/// Ask for an indexed arrow's complete preimage of a part.
///
/// # Specification
/// trivial.
async fn preimage<A>(
    ask: &mut A,
    arrow: ArrowId,
    target: PartKey,
) -> Result<Box<[PartKey]>, ProveError>
where
    A: Ask,
{
    match ask.ask(&Question::Preimage { arrow, target }).await? {
        Answer::Preimage(parts) => Ok(parts),
        Answer::Liveness(_) | Answer::Value(_) | Answer::Target(_) => Err(ProveError::Shape),
    }
}

/// Ask for an indexed attribute's complete preimage of a value.
///
/// # Specification
/// trivial.
async fn value_preimage<A>(
    ask: &mut A,
    attribute: AttributeId,
    value: AttributeValue,
) -> Result<Box<[PartKey]>, ProveError>
where
    A: Ask,
{
    match ask
        .ask(&Question::ValuePreimage { attribute, value })
        .await?
    {
        Answer::Preimage(parts) => Ok(parts),
        Answer::Liveness(_) | Answer::Value(_) | Answer::Target(_) => Err(ProveError::Shape),
    }
}

/// Decode a move's stored value.
///
/// # Specification
/// - ensures: the commit hashes the original bytes; the author is the one the
///   value carries.
/// - fails: a malformed value or receipt.
/// - panics: none.
/// - executable: none — the decoder is its own specification; the dialogue
///   witness compares decoded moves with the fold's sources.
///
/// # Errors
/// - [`ProveError::Codec`]: malformed value or receipt.
///
/// # Adequacy
/// - hypothesis: L2 — every fixture move decodes to its source.
/// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
#[inline]
pub fn read_move(value: &AttributeValue) -> Result<Move, ProveError>
{
    let value = decode_flat::<MoveValue<'_>>(TokenBody::from(value.as_ref()))?;
    let receipt = value.receipt()?;
    Ok(Move {
        author: value.author,
        commit: value.commit(),
        receipt,
        image: value.blob.into_owned().into_boxed_slice(),
    })
}

/// The task a name selects.
///
/// # Specification
/// - ensures: the complete preimage of `task_name` holds exactly this task.
/// - fails: no task of the name, two of it, or the reader's refusal.
/// - panics: none.
/// - executable: none — the read is a question to an asker; the witness
///   compares every fixture name and an unbound one.
///
/// # Errors
/// - [`ProveError::Absent`]: no task of the name.
/// - [`ProveError::Duplicate`]: two tasks of the name.
/// - [`ProveError`]: the reader's refusal.
///
/// # Adequacy
/// - hypothesis: L2 — every fixture name selects its task and an unbound name
///   none.
/// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
#[inline]
pub async fn task<A>(
    ask: &mut A,
    keyed: &Keyed,
    name: &TaskName,
) -> Result<PartKey, ProveError>
where
    A: Ask,
{
    match *value_preimage(ask, keyed.task_name, keyed::text(Text(name.as_ref()))).await? {
        [] => Err(ProveError::Absent(name.clone())),
        [task] => Ok(task),
        [_, _, ..] => Err(ProveError::Duplicate(name.clone())),
    }
}

/// What the store claims about a task, without its play.
///
/// # Specification
/// - ensures: attempts in order one to n; refusals in the order the store
///   minted them, which is fold order.
/// - fails: a malformed value, attempts not numbered from one, or the reader's
///   refusal.
/// - panics: none.
/// - executable: none — the reads are questions to an asker; the witness
///   compares every fixture claim with the fold.
///
/// # Errors
/// - [`ProveError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — the claim of every fixture task equals the fold's.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub async fn claim<A>(
    ask: &mut A,
    keyed: &Keyed,
    task: PartKey,
) -> Result<Claim, ProveError>
where
    A: Ask,
{
    let standing = Standing::read(&value(ask, keyed.task_standing, task).await?)?;
    let heads = keyed::read_heads(&value(ask, keyed.task_heads, task).await?)?;
    let mut refused = Vec::new();
    for refusal in preimage(ask, keyed.refusal_task, task).await? {
        let commit = keyed::read_commit(&value(ask, keyed.refusal_commit, refusal).await?)?;
        let reason = value(ask, keyed.refusal_reason, refusal).await?;
        refused.push(Refused::new(
            commit,
            keyed::read_text(&reason)?.0.to_owned(),
        ));
    }
    let mut attempts = Vec::new();
    for attempt in preimage(ask, keyed.attempt_task, task).await? {
        let number = keyed::read_number(&value(ask, keyed.attempt_number, attempt).await?)?;
        attempts.push((AttemptNumber::try_from(number)?, attempt));
    }
    attempts.sort_unstable();
    let numbered = attempts
        .iter()
        .zip(1_u32 ..)
        .all(|(&(number, _), expected)| number == AttemptNumber(expected));
    if !numbered {
        return Err(ProveError::Attempts);
    }
    Ok(Claim {
        task,
        standing,
        heads,
        attempts: attempts.into_iter().map(|(_number, part)| part).collect(),
        refused,
    })
}

/// An attempt's moves, in order.
///
/// # Specification
/// - ensures: the complete preimage of `move_attempt`, placed from zero, each
///   move decoded from its original receipt and of one tree. Whether the play
///   opens with a dispatch is protocol admission's question
///   ([`replay::replay`]).
/// - fails: a gap or repeat in the places, a move of another tree, a malformed
///   move, or the reader's refusal.
/// - panics: none.
///
/// # Errors
/// - [`ProveError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — every fixture attempt reads back as the dialogue the fold
///   derives; L3 — a play without its dispatch reaches replay's refusal.
/// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
/// - witness: `replay::tests::proved_attempts_replay_every_standing`
#[spec(ensures: |ref output| output.as_ref().map_or(true, |moves|
    moves.iter().all(|entry| entry.0.coordinates().0 == number)))]
#[inline]
pub async fn play<A>(
    ask: &mut A,
    keyed: &Keyed,
    number: AttemptNumber,
    attempt: PartKey,
) -> Result<Vec<(MoveKey, Move)>, ProveError>
where
    A: Ask,
{
    let mut moves = Vec::new();
    for movement in preimage(ask, keyed.move_attempt, attempt).await? {
        let seq = keyed::read_number(&value(ask, keyed.move_seq, movement).await?)?;
        let receipt = value(ask, keyed.move_receipt, movement).await?;
        moves.push((
            MoveKey::new(number, SequenceNumber::try_from(seq)?),
            read_move(&receipt)?,
        ));
    }
    moves.sort_unstable_by_key(|entry| entry.0);
    let placed = moves
        .iter()
        .zip(0_u32 ..)
        .all(|(entry, expected)| entry.0.coordinates().1 == SequenceNumber(expected));
    if !placed {
        return Err(ProveError::Sequence(number));
    }
    same_tree(moves.iter().map(|entry| &entry.1))?;
    Ok(moves)
}

/// Refuse moves of more than one tree.
///
/// # Specification
/// - ensures: success exactly when every move names the first's tree.
/// - fails: [`ProveError::Tree`] at the first move naming another.
/// - panics: none.
/// - executable: none — the function is its own specification.
///
/// # Errors
/// - [`ProveError::Tree`]: as above.
///
/// # Adequacy
/// - hypothesis: L3 — a move of another tree in a task is refused.
/// - witness: `prove::tests::a_move_naming_another_tree_is_refused`
#[inline]
pub fn same_tree<'moves, I>(mut moves: I) -> Result<(), ProveError>
where
    I: Iterator<Item = &'moves Move>,
{
    let Some(first) = moves.next()
    else {
        return Ok(());
    };
    let expected = first.receipt.tree();
    for movement in moves {
        let actual = movement.receipt.tree();
        if actual != expected {
            return Err(ProveError::Tree { expected, actual });
        }
    }
    Ok(())
}

/// The standing a claim's last attempt reaches.
///
/// # Specification
/// - ensures: on success the standing the fold holds when the store agrees with
///   it: undispatched without attempts, otherwise the last attempt's play
///   projected through each move; its kind is the claim's tag.
/// - fails: the play doesn't resolve, or its kind isn't the tag.
/// - panics: none.
/// - executable: none — the reads are questions to an asker; the witness
///   compares the recomputed standing with the fold's at every standing.
///
/// # Errors
/// - [`ProveError::Standing`] and the play's own refusals.
///
/// # Adequacy
/// - hypothesis: L2 — every reachable standing recomputes from its play to the
///   fold's; L3 — a forged tag is refused naming both kinds.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub async fn current<A>(
    ask: &mut A,
    keyed: &Keyed,
    claim: &Claim,
) -> Result<Current, ProveError>
where
    A: Ask,
{
    let current = match claim.attempts.last() {
        None => Current::Undispatched,
        Some(&attempt) => {
            let number =
                u32::try_from(claim.attempts.len()).map_err(|_width| KeyError::Overflow)?;
            let moves = play(ask, keyed, AttemptNumber(number), attempt).await?;
            replay::recompute(&moves)?
        },
    };
    let recomputed = Standing::of(&current);
    if claim.standing != Standing::Unheld && recomputed != claim.standing {
        return Err(ProveError::Standing {
            claimed: claim.standing,
            recomputed,
        });
    }
    Ok(current)
}

/// Whether another attempt follows one.
///
/// # Specification
/// - ensures: the next attempt's dispatch when the claim has one, none when the
///   attempt is the last.
/// - fails: the next attempt's play fails to read.
/// - panics: none.
/// - executable: none — the reads are questions to an asker; the witness reads
///   the fixture's last and earlier attempts.
///
/// # Errors
/// - [`ProveError`]: as [`play`].
///
/// # Adequacy
/// - hypothesis: L3 — the last attempt has none after it and an earlier one its
///   successor's dispatch.
/// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
#[inline]
pub async fn later<A>(
    ask: &mut A,
    keyed: &Keyed,
    claim: &Claim,
    attempt: AttemptNumber,
) -> Result<Later, ProveError>
where
    A: Ask,
{
    let next = attempt.next()?;
    let index = usize::try_from(attempt.0).map_err(|_width| KeyError::Overflow)?;
    let Some(&part) = claim.attempts.get(index)
    else {
        return Ok(Later::None);
    };
    let mut moves = play(ask, keyed, next, part).await?;
    let dispatched = moves
        .first()
        .is_some_and(|entry| matches!(entry.1.receipt.kind(), Kind::Dispatch { .. }));
    if !dispatched {
        return Err(ProveError::Sequence(next));
    }
    Ok(Later::Dispatch(moves.swap_remove(0).1))
}

/// Every move naming a subject, through the provenance tables.
///
/// # Specification
/// - ensures: one entry per naming of the subject, each checked against its
///   move: the move's receipt names the subject in the stored field, and the
///   naming's task is its attempt's.
/// - fails: a naming that disagrees with its move, a malformed value, or the
///   reader's refusal.
/// - panics: none.
/// - executable: none — the reads are questions to an asker; the witness
///   compares every fixture subject with the fold.
///
/// # Errors
/// - [`ProveError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — every fixture subject's namings equal the fold's evidence
///   and landings.
/// - witness: `provenance::tests::provenance_agrees_with_every_tasks_evidence`
#[inline]
pub async fn named<A>(
    ask: &mut A,
    keyed: &Keyed,
    subject: Subject,
) -> Result<Vec<Named>, ProveError>
where
    A: Ask,
{
    let Some(&part) = value_preimage(ask, keyed.subject_digest, subject.value())
        .await?
        .first()
    else {
        return Ok(Vec::new());
    };
    let mut named = Vec::new();
    for naming in preimage(ask, keyed.naming_subject, part).await? {
        let movement = target(ask, keyed.naming_move, naming).await?;
        let task = target(ask, keyed.naming_task, naming).await?;
        let field = Field::read(&value(ask, keyed.naming_role, naming).await?)?;
        let attempt = target(ask, keyed.move_attempt, movement).await?;
        if target(ask, keyed.attempt_task, attempt).await? != task {
            return Err(ProveError::Naming(naming));
        }
        let number = keyed::read_number(&value(ask, keyed.attempt_number, attempt).await?)?;
        let seq = keyed::read_number(&value(ask, keyed.move_seq, movement).await?)?;
        let read = read_move(&value(ask, keyed.move_receipt, movement).await?)?;
        let Naming::Named(named_subject, attribution) = named_by(read.author, &read.receipt)
        else {
            return Err(ProveError::Naming(naming));
        };
        if named_subject != subject || attribution.field != field {
            return Err(ProveError::Naming(naming));
        }
        let name = value(ask, keyed.task_name, task).await?;
        let name = keyed::read_text(&name)?
            .0
            .parse::<TaskName>()
            .map_err(|_name| ValueFault::Text)?;
        named.push(Named {
            task: name,
            key: MoveKey::new(
                AttemptNumber::try_from(number)?,
                SequenceNumber::try_from(seq)?,
            ),
            field,
            holder: attribution.holder,
            movement: read,
        });
    }
    Ok(named)
}

/// One task's contents, without part keys.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct TaskContents
{
    /// The standing's kind.
    pub standing: Standing,
    /// The frontier the task was derived at.
    pub heads: Heads,
    /// The refused commits, in fold order.
    pub refused: Vec<Refused>,
    /// Each attempt's moves, attempt one first.
    pub plays: Vec<Vec<(MoveKey, Move)>>,
    /// The task's namings: subject, move and field, in that order.
    pub namings: Vec<(AttributeValue, MoveKey, Field)>,
}

/// A store's contents by task name, without part keys: what two stores
/// derived along different histories agree on.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Contents(pub BTreeMap<TaskName, TaskContents>);

/// Read the named tasks' contents.
///
/// # Specification
/// - ensures: one entry per name with a task, holding its claim, every
///   attempt's play and its namings; a name without a task is absent.
/// - fails: as [`claim`], [`play`] and the namings' reads.
/// - panics: none.
/// - executable: none — the reads are questions to an asker; the witness
///   compares a refreshed store with one derived whole.
///
/// # Errors
/// - [`ProveError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — a refreshed store's contents equal a whole derive's after
///   every kind of change, while their roots may differ.
/// - witness: `derive::tests::a_refreshed_index_equals_one_derived_whole`
#[inline]
pub async fn contents<A, N>(
    ask: &mut A,
    keyed: &Keyed,
    names: N,
) -> Result<Contents, ProveError>
where
    A: Ask,
    N: IntoIterator<Item = TaskName>,
{
    let mut contents = BTreeMap::new();
    for name in names {
        let task = match task(ask, keyed, &name).await {
            Ok(task) => task,
            Err(ProveError::Absent(_name)) => continue,
            Err(failure) => return Err(failure),
        };
        let claim = claim(ask, keyed, task).await?;
        let mut plays = Vec::new();
        for (attempt, number) in claim.attempts.iter().zip(1_u32 ..) {
            plays.push(play(ask, keyed, AttemptNumber(number), *attempt).await?);
        }
        let mut namings = Vec::new();
        for naming in preimage(ask, keyed.naming_task, task).await? {
            let subject = target(ask, keyed.naming_subject, naming).await?;
            let subject = value(ask, keyed.subject_digest, subject).await?;
            let movement = target(ask, keyed.naming_move, naming).await?;
            let attempt = target(ask, keyed.move_attempt, movement).await?;
            let number = keyed::read_number(&value(ask, keyed.attempt_number, attempt).await?)?;
            let seq = keyed::read_number(&value(ask, keyed.move_seq, movement).await?)?;
            let field = Field::read(&value(ask, keyed.naming_role, naming).await?)?;
            let key = MoveKey::new(
                AttemptNumber::try_from(number)?,
                SequenceNumber::try_from(seq)?,
            );
            namings.push((subject, key, field));
        }
        namings.sort_unstable();
        let _previous = contents.insert(name, TaskContents {
            standing: claim.standing,
            heads: claim.heads,
            refused: claim.refused,
            plays,
            namings,
        });
    }
    Ok(Contents(contents))
}
