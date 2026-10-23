//! Readers over a held store and over verified proofs, compared.

use alloc::borrow::Cow;

use domhringr_record_tree::Brief;
use domhringr_record_tree::Edition;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::StateDir;
use gandr_storage_records::InMemoryBlockStore;
use gandr_storage_schema::Answer;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::Proof;
use gandr_storage_schema::ProofImage;
use gandr_storage_schema::Question;
use gandr_storage_schema::Row;
use gandr_storage_schema::StoreError;
use gandr_storage_schema::StoreRoot;
use gandr_storage_values::encode_flat;

use super::Ask;
use super::Later;
use super::Local;
use super::ProveError;
use crate::AttemptNumber;
use crate::derive::Derived;
use crate::derive::Deriver;
use crate::dialogue::MoveValue;
use crate::keyed;
use crate::keyed::Keyed;
use crate::keyed::Number;
use crate::provenance::Subject;
use crate::store::Store;
use crate::testing;

/// A reader that proves each answer and verifies it through its image.
struct Proving<'store>
{
    /// The store proving.
    store: &'store gandr_storage_schema::Store,
    /// The root each proof is verified against.
    root: StoreRoot,
}

impl Proving<'_>
{
    /// Prove, encode, decode and verify.
    ///
    /// # Specification
    /// trivial.
    fn answer(
        &self,
        question: &Question,
    ) -> Result<Answer, ProveError>
    {
        let keyed = Keyed::shared().map_err(crate::stream::StreamError::from)?;
        let image = self.store.prove(question)?.encode();
        let proof = Proof::decode(
            ProofImage::from(image.as_ref()),
            &keyed.schema,
            keyed::params(),
            question,
        )?;
        Ok(proof.verify(self.root, &keyed.schema, keyed::params(), question)?)
    }
}

impl Ask for Proving<'_>
{
    /// Answer through a proof, ready at once.
    ///
    /// # Specification
    /// trivial.
    fn ask(
        &mut self,
        question: &Question,
    ) -> impl Future<Output = Result<Answer, ProveError>> + Send
    {
        core::future::ready(self.answer(question))
    }
}

/// The fixture project, derived whole.
///
/// # Specification
/// trivial.
async fn derived(root: &tempfile::TempDir) -> Derived
{
    let fixture = testing::Fixture::new().await;
    let (project, commits) = testing::project_fixture().await;
    let peer = testing::peer(root.path(), commits.into_iter().chain(fixture.commits)).await;
    let files = Store::open(&StateDir::from(root.path().to_path_buf()));
    let view = peer.view(project).await.unwrap();
    let derived = Deriver::default()
        .project(&peer, project, &view, &files)
        .await
        .unwrap();
    drop(peer);
    derived
}

/// A dispatch of the fixture tree, made by a stranger.
///
/// # Specification
/// trivial.
fn stranger_dispatch(tree: domhringr_record_tree::TreeId) -> AttributeValue
{
    let receipt = testing::fenced(
        &Receipt::dispatch(
            tree,
            testing::key(&testing::seat()),
            Edition::CURRENT,
            Brief::Content(testing::hash()),
        )
        .unwrap(),
        testing::Fence(500),
    );
    let blob = encode_flat(&receipt).unwrap();
    let value = encode_flat(&MoveValue {
        author: testing::key(&testing::stranger()),
        blob: Cow::Borrowed(blob.as_ref()),
    })
    .unwrap();
    AttributeValue::from(value.as_ref())
}

#[test]
fn a_proving_reader_reads_what_the_store_holds()
{
    testing::runtime().block_on(async {
        let root = tempfile::tempdir().unwrap();
        let derived = derived(&root).await;
        let keyed = Keyed::shared().unwrap();
        let mut local = Local(&derived.store);
        let mut proving = Proving {
            store: &derived.store,
            root: derived.root(),
        };
        let names: Vec<_> = derived
            .entries
            .keys()
            .cloned()
            .chain(["absent".parse().unwrap()])
            .collect();
        let held = super::contents(&mut local, keyed, names.clone())
            .await
            .unwrap();
        assert_eq!(held.0.len(), derived.entries.len());
        assert_eq!(
            super::contents(&mut proving, keyed, names).await.unwrap(),
            held
        );
        let absent = "absent".parse().unwrap();
        assert!(matches!(
            super::task(&mut proving, keyed, &absent).await,
            Err(ProveError::Absent(name)) if name == absent
        ));
        let alpha = super::task(&mut proving, keyed, &"alpha".parse().unwrap())
            .await
            .unwrap();
        let claim = super::claim(&mut proving, keyed, alpha).await.unwrap();
        let last = AttemptNumber(u32::try_from(claim.attempts.len()).unwrap());
        assert_eq!(
            super::later(&mut proving, keyed, &claim, last)
                .await
                .unwrap(),
            Later::None
        );
        for (index, &attempt) in claim.attempts.iter().enumerate().skip(1) {
            let number = AttemptNumber(u32::try_from(index).unwrap());
            let next = number.next().unwrap();
            let play = super::play(&mut proving, keyed, next, attempt)
                .await
                .unwrap();
            assert_eq!(
                super::later(&mut proving, keyed, &claim, number)
                    .await
                    .unwrap(),
                Later::Dispatch(play[0].1.clone())
            );
        }
        let subject = Subject::Evidence(testing::evidence());
        let named = super::named(&mut proving, keyed, subject).await.unwrap();
        assert!(!named.is_empty());
        assert_eq!(
            super::named(&mut local, keyed, subject).await.unwrap(),
            named
        );
    });
}

#[test]
fn a_forged_later_attempt_is_refused()
{
    testing::runtime().block_on(async {
        let root = tempfile::tempdir().unwrap();
        let derived = derived(&root).await;
        let keyed = Keyed::shared().unwrap();
        let honest = derived.root();
        let mut forged = derived.store.clone();
        let mut local = Local(&derived.store);
        let alpha = super::task(&mut local, keyed, &"alpha".parse().unwrap())
            .await
            .unwrap();
        let claim = super::claim(&mut local, keyed, alpha).await.unwrap();
        let last = AttemptNumber(u32::try_from(claim.attempts.len()).unwrap());
        let next = last.next().unwrap();
        let attempt = forged
            .add_part(
                keyed.attempt,
                &Row::new()
                    .arrow(keyed.attempt_task, alpha)
                    .value(keyed.attempt_number, keyed::number(Number::from(next))),
            )
            .unwrap();
        let _move = forged
            .add_part(
                keyed.movement,
                &Row::new()
                    .arrow(keyed.move_attempt, attempt)
                    .value(keyed.move_seq, keyed::number(Number(0)))
                    .value(keyed.move_receipt, stranger_dispatch(testing::tree())),
            )
            .unwrap();
        let forged_root = forged.commit(&mut InMemoryBlockStore::new()).unwrap();
        // Against the attested root, the forged store's proofs are refused.
        let mut against = Proving {
            store: &forged,
            root: honest,
        };
        assert!(matches!(
            super::claim(&mut against, keyed, alpha).await,
            Err(ProveError::Store(StoreError::RootMismatch { expected, .. })) if expected == honest
        ));
        // Under its own root the forgery proves: a proof shows what the
        // store holds, and the check re-derives to refute it.
        let mut own = Proving {
            store: &forged,
            root: forged_root,
        };
        let forged_claim = super::claim(&mut own, keyed, alpha).await.unwrap();
        assert!(matches!(
            super::later(&mut own, keyed, &forged_claim, last).await.unwrap(),
            Later::Dispatch(movement) if movement.author == testing::key(&testing::stranger())
        ));
    });
}

#[test]
fn a_move_naming_another_tree_is_refused()
{
    let other = domhringr_record_tree::TreeId::try_from(
        *iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes(),
    )
    .unwrap();
    let ours = super::read_move(&stranger_dispatch(testing::tree())).unwrap();
    let theirs = super::read_move(&stranger_dispatch(other)).unwrap();
    assert!(super::same_tree([&ours, &ours].into_iter()).is_ok());
    assert!(matches!(
        super::same_tree([&ours, &theirs].into_iter()),
        Err(ProveError::Tree { expected, actual }) if expected == testing::tree() && actual == other
    ));
}
