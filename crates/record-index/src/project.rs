//! Task bindings, their typed standings, and nested index identities.

use alloc::collections::BTreeMap;
use core::fmt;
use core::str::FromStr;

use anodized::spec;
use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::Current;
use domhringr_record_tree::Heads;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Path;
use domhringr_record_tree::Target;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::View;
use gandr_storage_records::OwnedRecordKey;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::RecordTreeError;
use gandr_storage_records::TreeParams;
use gandr_storage_values::CanonicalValue;
use gandr_storage_values::CanonicalWord;
use gandr_storage_values::ConstructorTag;
use gandr_storage_values::TokenBytes;
use gandr_storage_values::TokenReader;
use gandr_storage_values::TokenSink;
use gandr_storage_values::ValueError;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::AttemptNumber;
use crate::Index;
use crate::IndexKind;

/// One path segment beneath a project's `tasks/` binding family.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct TaskName(Path);

/// A task name is empty, reserved, or contains more than one path segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a task name is one nonempty path segment")]
pub struct NameError;

impl FromStr for TaskName
{
    type Err = NameError;

    /// Validate a task name using the record plane's path language.
    ///
    /// # Specification
    /// - ensures: the name is one nonempty, unreserved segment, unchanged.
    /// - fails: an invalid path or a slash is refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`NameError`]: invalid name.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the binding family selects names, not nested paths.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[spec(ensures: |ret| ret.as_ref().map_or(true, |name| name.as_ref() == text && !text.contains('/')))]
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        if text.contains('/') {
            return Err(NameError);
        }
        text.parse::<Path>().map(Self).map_err(|_path| NameError)
    }
}

impl AsRef<str> for TaskName
{
    /// Borrow the exact task name.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn as_ref(&self) -> &str
    {
        self.0.as_ref()
    }
}

impl fmt::Display for TaskName
{
    /// Write the task name without its project prefix.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(self.as_ref())
    }
}

impl TaskName
{
    /// The project's task-family key, ordered exactly as the task name.
    ///
    /// # Specification
    /// - ensures: returns `0x01` followed by the name's unchanged UTF-8 bytes.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — task ordering and reserved family separation are
    ///   pinned.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[spec(ensures: |ret| ret.as_ref().split_first().is_some_and(|(tag, name)| *tag == 1 && name == self.as_ref().as_bytes()))]
    #[inline]
    #[must_use]
    pub fn key(&self) -> OwnedRecordKey
    {
        let length = arith::saturating_add(Int::from(self.as_ref().len()), Int::from(1));
        let mut bytes = Vec::with_capacity(usize::from(length));
        bytes.push(1);
        bytes.extend_from_slice(self.as_ref().as_bytes());
        OwnedRecordKey::from(bytes.into_boxed_slice())
    }
}

/// A task's fold at named heads, or an explicit unheld binding.
#[derive(Clone, Debug, PartialEq, Eq)]
#[expect(
    clippy::large_enum_variant,
    reason = "entries normally hold a standing; boxing would allocate per task to compact only unheld bindings"
)]
pub enum TaskEntry
{
    /// The deriving peer held and folded the task.
    Held
    {
        /// The bound task tree.
        tree: TreeId,
        /// The frontier used to derive this entry.
        heads: Heads,
        /// The complete typed standing at that frontier.
        current: Current,
        /// The number of admitted dispatches.
        attempts: AttemptNumber,
        /// The dialogue manifest at that frontier.
        dialogue: IndexDigest,
    },
    /// The project binds the tree, but the deriver does not hold its Open.
    Unheld
    {
        /// The bound task tree.
        tree: TreeId,
    },
}

impl TaskEntry
{
    /// The tree this task binding names.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn tree(&self) -> TreeId
    {
        match *self {
            | Self::Held { tree, .. } | Self::Unheld { tree } => tree,
        }
    }
}

impl CanonicalValue for TaskEntry
{
    /// Encode the held or unheld claim with sorted, unique heads.
    ///
    /// # Specification
    /// - ensures: tag one carries tree, counted heads, current, attempts and
    ///   dialogue; tag two carries only the tree. Neither discards a field.
    /// - fails: propagates sink refusals and unrepresentable head counts.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: token sink or head count refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — every reachable standing equals the independent fold.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        match *self {
            | Self::Held {
                ref tree,
                ref heads,
                ref current,
                ref attempts,
                ref dialogue,
            } => {
                sink.open(ConstructorTag::from(1))?;
                sink.bytes(TokenBytes::from(tree.as_ref()))?;
                let count = u64::try_from(heads.iter().count()).map_err(|_count| {
                    ValueError::ArithmeticOverflow {
                        quantity: gandr_storage_values::ValueQuantity::TokenCount,
                    }
                })?;
                sink.word(CanonicalWord::from(count))?;
                for head in heads.iter() {
                    sink.bytes(TokenBytes::from(head.as_bytes().as_slice()))?;
                }
                current.emit_tokens(sink)?;
                sink.word(CanonicalWord::from(u64::from(attempts.0)))?;
                sink.bytes(TokenBytes::from(dialogue.as_ref()))?;
            },
            | Self::Unheld { ref tree } => {
                sink.open(ConstructorTag::from(2))?;
                sink.bytes(TokenBytes::from(tree.as_ref()))?;
            },
        }
        sink.close()
    }

    /// Decode an entry without treating its attested fields as derived facts.
    ///
    /// # Specification
    /// - ensures: reads exactly the emitted fields; the frontier is canonical.
    /// - fails: unknown tags, duplicate or unordered heads, invalid tree keys,
    ///   overflowing coordinates and malformed token framing are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: invalid constructor, fields or framing.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — each reachable standing and unheld binding
    ///   round-trips.
    /// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let position = reader.position();
        let found = reader.read_tag()?;
        let refused = || ValueError::UnexpectedConstructor { found, position };
        let bytes = reader.read_bytes()?;
        let bytes = <[u8; 32]>::try_from(<&[u8]>::from(bytes)).map_err(|_width| refused())?;
        let tree = TreeId::try_from(bytes).map_err(|_key| refused())?;
        let entry = match u8::from(found) {
            | 1 => {
                let count = reader.read_word()?;
                let count = u64::from(count);
                let mut heads = Vec::new();
                for _head in 0 .. count {
                    let bytes = reader.read_bytes()?;
                    let bytes =
                        <[u8; 32]>::try_from(<&[u8]>::from(bytes)).map_err(|_width| refused())?;
                    let head = CommitId::new(bytes);
                    if heads.last().is_some_and(|last| *last >= head) {
                        return Err(refused());
                    }
                    heads.push(head);
                }
                let current = Current::decode_tokens(reader)?;
                let attempts = reader.read_word()?;
                let attempts = u32::try_from(u64::from(attempts)).map_err(|_width| refused())?;
                let dialogue = reader.read_bytes()?;
                let dialogue =
                    <[u8; 32]>::try_from(<&[u8]>::from(dialogue)).map_err(|_width| refused())?;
                Self::Held {
                    tree,
                    heads: Heads::from_iter(heads),
                    current,
                    attempts: AttemptNumber(attempts),
                    dialogue: IndexDigest::from(dialogue),
                }
            },
            | 2 => Self::Unheld { tree },
            | _unknown => return Err(refused()),
        };
        reader.read_close()?;
        Ok(entry)
    }
}

/// An index identity carried by a project's reserved nested family.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Nested(pub IndexDigest);

impl CanonicalValue for Nested
{
    /// Emit the nested manifest identity as a value-plane flat value.
    ///
    /// # Specification
    /// - ensures: tag one holds exactly the manifest's 32 bytes.
    /// - fails: propagates sink refusal.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: sink refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — nested identities are pinned with the project
    ///   manifest.
    /// - witness: `derive::tests::the_fixture_manifests_are_pinned`
    #[inline]
    fn emit_tokens<Sink>(
        &self,
        sink: &mut Sink,
    ) -> Result<(), ValueError>
    where
        Sink: TokenSink + ?Sized,
    {
        sink.open(ConstructorTag::from(1))?;
        sink.bytes(TokenBytes::from(self.0.as_ref()))?;
        sink.close()
    }

    /// Read one nested manifest identity.
    ///
    /// # Specification
    /// - ensures: retains exactly the nested identity's bytes.
    /// - fails: unknown tags, wrong widths and framing are refused.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ValueError`]: constructor, width or token refusal.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — nested identities are pinned with the project
    ///   manifest.
    /// - witness: `derive::tests::the_fixture_manifests_are_pinned`
    #[inline]
    fn decode_tokens(reader: &mut TokenReader<'_>) -> Result<Self, ValueError>
    {
        let position = reader.position();
        let found = reader.read_tag()?;
        let refused = || ValueError::UnexpectedConstructor { found, position };
        if u8::from(found) != 1 {
            return Err(refused());
        }
        let digest = reader.read_bytes()?;
        let digest = <[u8; 32]>::try_from(<&[u8]>::from(digest)).map_err(|_width| refused())?;
        reader.read_close()?;
        Ok(Self(IndexDigest::from(digest)))
    }
}

/// Select the same one-segment task bindings the operator lists.
///
/// # Specification
/// - ensures: only `tasks/<name>` bound to bare keyed tree anchors are
///   selected, in name order; deeper paths, other families and other targets
///   are absent.
/// - panics: none.
///
/// # Adequacy
/// - hypothesis: L3 — mixed bindings separate names, nested paths and targets.
/// - witness: `project::tests::an_entry_agrees_with_the_fold_at_every_standing`
#[inline]
pub fn bindings(view: &View) -> impl Iterator<Item = (TaskName, TreeId)> + '_
{
    view.bindings()
        .iter()
        .filter_map(|(path, &(_author, ref target))| {
            let name = path.as_ref().strip_prefix("tasks/")?;
            let &Target::Anchor(Anchor::Tree(Authority::Key(tree))) = target
            else {
                return None;
            };
            let name = name.parse().ok()?;
            Some((name, tree))
        })
}

/// Build failure at a value or record boundary.
#[derive(Debug, thiserror::Error)]
pub enum ProjectError
{
    /// A task entry or nested identity could not be encoded.
    #[error(transparent)]
    Value(#[from] ValueError),
    /// The record tree refused the encoded records.
    #[error(transparent)]
    Records(#[from] RecordTreeError),
}

/// Build the project tree, leaving the reserved nested family empty when
/// unused.
///
/// # Specification
/// - ensures: one record per task and nested kind, in byte order, under
///   disjoint task and nested key families.
/// - fails: value encoding or record construction refuses its input.
/// - panics: none.
///
/// # Errors
/// - [`ProjectError`]: an encoding or record-plane failure.
///
/// # Adequacy
/// - hypothesis: L2 — fixed input records pin the project manifest.
/// - witness: `derive::tests::the_fixture_manifests_are_pinned`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |index| {
    let count = arith::saturating_add(Int::from(entries.len()), Int::from(nested.len()));
    index.tree.records().len() == usize::from(count)
}))]
#[inline]
pub fn build(
    entries: &BTreeMap<TaskName, TaskEntry>,
    nested: &BTreeMap<IndexKind, IndexDigest>,
) -> Result<Index, ProjectError>
{
    let mut encoded = BTreeMap::new();
    for (&kind, &digest) in nested {
        let key = OwnedRecordKey::from(Box::<[u8]>::from([0, u8::from(kind)]));
        let _previous = encoded.insert(key, encode_flat(&Nested(digest))?);
    }
    for (name, entry) in entries {
        let _previous = encoded.insert(name.key(), encode_flat(entry)?);
    }
    let records: Vec<_> = encoded
        .iter()
        .map(|(key, value)| RecordRef::new(key.as_ref(), value.as_ref()))
        .collect();
    let tree = RecordTree::build(&records, TreeParams::current())?;
    Ok(Index::new(IndexKind::Project, tree))
}

#[cfg(test)]
mod tests
{
    use alloc::collections::BTreeMap;

    use domhringr_record_tree::Answer;
    use domhringr_record_tree::Current;
    use domhringr_record_tree::Heads;
    use domhringr_record_tree::Progress;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::Step;
    use gandr_storage_values::TokenBody;
    use gandr_storage_values::decode_flat;
    use gandr_storage_values::encode_flat;

    use super::TaskEntry;
    use super::TaskName;
    use crate::AttemptNumber;
    use crate::derive;
    use crate::derive::Deriver;
    use crate::store::Store;
    use crate::testing;

    #[test]
    fn an_entry_agrees_with_the_fold_at_every_standing()
    {
        testing::runtime().block_on(async {
            let fixture = testing::Fixture::new().await;
            let (project, bindings) = testing::project_fixture().await;
            let root = tempfile::tempdir().unwrap();
            let peer =
                testing::peer(root.path(), fixture.commits.iter().cloned().chain(bindings)).await;
            let store = Store::open(&StateDir::from(root.path().to_path_buf()));
            let mut reached: Vec<u8> = Vec::new();
            for head in &fixture.standings {
                let heads = Heads::from_iter([*head]);
                let view = peer.view_at(testing::tree(), &heads).await.unwrap();
                assert!(view.refused().is_empty());
                let expected = view.task().current();
                let standing = match *expected {
                    | Current::Undispatched => 0,
                    | Current::Attempt(ref attempt) => match *attempt.progress() {
                        | Progress::Unchecked => match attempt.answer() {
                            | Answer::Awaited => 1,
                            | Answer::Reported { .. } => 2,
                        },
                        | Progress::Verified { .. } => 3,
                        | Progress::Graded { .. } => 4,
                        | Progress::Decided { .. } => 5,
                        | Progress::Landed { .. } => 6,
                    },
                };
                reached.push(standing);
                let entry = derive::at(&peer, testing::tree(), &heads, &store)
                    .await
                    .unwrap();
                let TaskEntry::Held {
                    tree,
                    heads: ref actual_heads,
                    ref current,
                    attempts,
                    dialogue,
                } = entry
                else {
                    panic!("held task");
                };
                assert_eq!(tree, testing::tree());
                assert_eq!(actual_heads, &heads);
                assert_eq!(current, expected);
                assert_eq!(
                    attempts,
                    AttemptNumber(
                        u32::try_from(
                            view.task()
                                .steps()
                                .iter()
                                .filter(|entry| matches!(entry.1, Step::Dispatch { .. }))
                                .count()
                        )
                        .unwrap()
                    )
                );
                assert_eq!(
                    store.load(dialogue).unwrap().tree.records().len(),
                    view.task().steps().len()
                );
                let encoded = encode_flat(&entry).unwrap();
                assert_eq!(
                    decode_flat::<TaskEntry>(TokenBody::from(encoded.as_ref())).unwrap(),
                    entry
                );
            }
            assert_eq!(reached, [0, 1, 2, 3, 4, 5, 6]);
            let view = peer.view(project).await.unwrap();
            let derived = Deriver::default()
                .project(&peer, &view, &store)
                .await
                .unwrap();
            drop(peer);
            let names: Vec<_> = derived.entries.keys().map(TaskName::as_ref).collect();
            assert_eq!(names, ["alpha", "unheld", "zeta"]);
            assert_eq!(
                derived.entries[&"alpha".parse().unwrap()],
                derived.entries[&"zeta".parse().unwrap()]
            );
            assert!(matches!(
                derived.entries[&"unheld".parse().unwrap()],
                TaskEntry::Unheld { .. }
            ));
            for record in derived.index.tree.records() {
                assert_eq!(record.key().as_ref().first(), Some(&1));
                let name = core::str::from_utf8(&record.key().as_ref()[1 ..])
                    .unwrap()
                    .parse::<TaskName>()
                    .unwrap();
                let decoded =
                    decode_flat::<TaskEntry>(TokenBody::from(record.value().as_ref())).unwrap();
                assert_eq!(decoded, derived.entries[&name]);
            }
            let rebuilt = super::build(&derived.entries, &BTreeMap::new()).unwrap();
            assert_eq!(rebuilt.manifest, derived.index.manifest);
        });
    }
}
