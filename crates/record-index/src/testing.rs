//! Fixed signed commits shared by the index's behavioral witnesses.

use alloc::collections::BTreeSet;

use domhringr_record_tree::Brief;
use domhringr_record_tree::Code;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::ContentHash;
use domhringr_record_tree::Decision;
use domhringr_record_tree::Edition;
use domhringr_record_tree::Grade;
use domhringr_record_tree::Identity;
use domhringr_record_tree::Peer;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Receipt;
use domhringr_record_tree::Revision;
use domhringr_record_tree::Ruling;
use domhringr_record_tree::StateDir;
use domhringr_record_tree::Status;
use domhringr_record_tree::TreeId;
use domhringr_record_tree::Unread;
use future_form::Sendable;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::TokenBody;
use gandr_storage_values::decode_flat;
use gandr_storage_values::encode_flat;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;
use sedimentree_core::blob::Blob;
use sedimentree_core::blob::verified::VerifiedBlobMeta;
use sedimentree_core::id::SedimentreeId;
use sedimentree_core::loose_commit::LooseCommit;
use subduction_core::storage::traits::Storage;
use subduction_crypto::signer::memory::MemorySigner;
use subduction_crypto::verified_meta::VerifiedMeta;
use subduction_redb_storage::RedbStorage;

/// A stable operation fence in a fixture's receipt language.
#[derive(Clone, Copy)]
#[repr(transparent)]
pub struct Fence(pub u128);

/// Replace the random fence in a receipt's independently pinned layout.
///
/// # Specification
/// trivial.
pub fn fenced(
    receipt: &Receipt,
    fence: Fence,
) -> Receipt
{
    let mut bytes = encode_flat(receipt).unwrap().as_ref().to_vec();
    bytes[61 .. 77].copy_from_slice(&fence.0.to_le_bytes());
    decode_flat(TokenBody::from(bytes.as_slice())).unwrap()
}

/// A signer whose key is fixed across fixture runs.
///
/// # Specification
/// trivial.
pub fn owner() -> MemorySigner
{
    MemorySigner::from_bytes(&[1; 32])
}

/// The other operator, granted authority by the fixture.
///
/// # Specification
/// trivial.
pub fn member() -> MemorySigner
{
    MemorySigner::from_bytes(&[2; 32])
}

/// A dispatched seat without operator authority.
///
/// # Specification
/// trivial.
pub fn seat() -> MemorySigner
{
    MemorySigner::from_bytes(&[4; 32])
}

/// A stranger whose moves are refused.
///
/// # Specification
/// trivial.
pub fn stranger() -> MemorySigner
{
    MemorySigner::from_bytes(&[5; 32])
}

/// The signer's binary peer identity.
///
/// # Specification
/// trivial.
pub fn key(signer: &MemorySigner) -> PeerKey
{
    PeerKey::from(signer.verifying_key().to_bytes())
}

/// The fixed task tree.
///
/// # Specification
/// trivial.
pub fn tree() -> TreeId
{
    TreeId::try_from(*iroh::SecretKey::from_bytes(&[3; 32]).public().as_bytes()).unwrap()
}

/// The hash used as a brief, rubric, question and playbook in the fixture.
///
/// # Specification
/// trivial.
pub fn hash() -> ContentHash
{
    ContentHash::from(blake3::hash(b"fixture document"))
}

/// The named evidence value; derivation never reads its contents.
///
/// # Specification
/// trivial.
pub fn evidence() -> ManifestDigest
{
    ManifestDigest::from([8; 32])
}

/// The independent opening layout, signed by its fixed tree key.
///
/// # Specification
/// trivial.
pub fn opening(secret: &iroh::SecretKey) -> Receipt
{
    let author = key(&owner());
    let message = [
        b"domhringr record tree open proof".as_slice(),
        author.as_ref(),
    ]
    .concat();
    let proof = secret.sign(&message);
    let bytes = |value: &[u8]| {
        [
            vec![3],
            u64::try_from(value.len()).unwrap().to_le_bytes().to_vec(),
            value.to_vec(),
        ]
        .concat()
    };
    let image = [
        vec![1, 1, 2],
        3_u64.to_le_bytes().to_vec(),
        bytes(secret.public().as_bytes()),
        bytes(&[0; 16]),
        vec![1, 1],
        bytes(&proof.to_bytes()),
        vec![5, 5],
    ]
    .concat();
    decode_flat(TokenBody::from(image.as_slice())).unwrap()
}

/// A fixed endpoint presence, signed independently of the receipt encoder.
///
/// # Specification
/// trivial.
pub fn presence() -> Receipt
{
    let secret = iroh::SecretKey::from_bytes(&[11; 32]);
    let author = key(&owner());
    let proof = secret.sign(
        &[
            b"domhringr record endpoint holder".as_slice(),
            author.as_ref(),
        ]
        .concat(),
    );
    let bytes = |value: &[u8]| {
        [
            vec![3],
            u64::try_from(value.len()).unwrap().to_le_bytes().to_vec(),
            value.to_vec(),
        ]
        .concat()
    };
    let image = [
        vec![1, 1, 2],
        3_u64.to_le_bytes().to_vec(),
        bytes(tree().as_ref()),
        bytes(&[0; 16]),
        vec![1, 7, 1, 1],
        bytes(secret.public().as_bytes()),
        vec![2],
        0_u64.to_le_bytes().to_vec(),
        vec![5],
        bytes(&proof.to_bytes()),
        vec![5, 5],
    ]
    .concat();
    decode_flat(TokenBody::from(image.as_slice())).unwrap()
}

/// Seal a receipt under exactly the supplied parents.
///
/// # Specification
/// trivial.
pub async fn seal(
    signer: &MemorySigner,
    receipt: &Receipt,
    parents: BTreeSet<CommitId>,
) -> VerifiedMeta<LooseCommit>
{
    let flat = encode_flat(receipt).unwrap();
    let blob = Blob::new(flat.as_ref().to_vec());
    let head = CommitId::new(*blake3::hash(blob.as_slice()).as_bytes());
    let tree = SedimentreeId::new(<[u8; 32]>::try_from(receipt.tree().as_ref()).unwrap());
    VerifiedMeta::seal::<Sendable, _>(signer, (tree, head, parents), VerifiedBlobMeta::new(blob))
        .await
}

/// A whole admitted lifecycle, retaining each standing's frontier.
pub struct Fixture
{
    /// Original signed commits in insertion order.
    pub commits: Vec<VerifiedMeta<LooseCommit>>,
    /// A frontier for each standing named by project entry acceptance.
    pub standings: Vec<CommitId>,
    /// The dispatch whose lifecycle follows.
    pub dispatch: CommitId,
}

impl Fixture
{
    /// Build the fixed lifecycle, including a stalled earlier attempt.
    ///
    /// # Specification
    /// trivial.
    pub async fn new() -> Self
    {
        Self::with(
            &iroh::SecretKey::from_bytes(&[3; 32]),
            evidence(),
            Revision::Sha1([9; 20]),
        )
        .await
    }

    /// Build the same lifecycle under independently chosen subject identities.
    ///
    /// # Specification
    /// trivial.
    pub async fn with(
        secret: &iroh::SecretKey,
        evidence: ManifestDigest,
        merge: Revision,
    ) -> Self
    {
        let tree = TreeId::try_from(*secret.public().as_bytes()).unwrap();
        let opened = seal(&owner(), &opening(secret), BTreeSet::new()).await;
        let root = opened.payload().head();
        let mut fixture = Self {
            commits: vec![opened],
            standings: vec![root],
            dispatch: root,
        };
        let _grant = fixture
            .push(
                &owner(),
                Receipt::grant(tree, key(&member())).unwrap(),
                Fence(1),
            )
            .await;
        let dispatch = fixture
            .push(
                &owner(),
                Receipt::dispatch(tree, key(&seat()), Edition::CURRENT, Brief::Content(hash()))
                    .unwrap(),
                Fence(2),
            )
            .await;
        fixture.standings.push(dispatch);
        let _report = fixture
            .push(
                &seat(),
                Receipt::report(tree, dispatch, evidence, "first report".parse().unwrap()).unwrap(),
                Fence(30),
            )
            .await;
        let _retired = fixture
            .push(&seat(), Receipt::retire(tree, dispatch).unwrap(), Fence(3))
            .await;
        let dispatch = fixture
            .push(
                &owner(),
                Receipt::dispatch(tree, key(&seat()), Edition::CURRENT, Brief::Content(hash()))
                    .unwrap(),
                Fence(4),
            )
            .await;
        fixture.dispatch = dispatch;
        if Edition::CURRENT == Edition::TWO {
            let _paused = fixture
                .push(&seat(), Receipt::pause(tree, dispatch).unwrap(), Fence(5))
                .await;
        }
        let reported = fixture
            .push(
                &seat(),
                Receipt::report(tree, dispatch, evidence, "reported".parse().unwrap()).unwrap(),
                Fence(6),
            )
            .await;
        fixture.standings.push(reported);
        let _handoff = fixture
            .push(
                &seat(),
                Receipt::handoff(tree, dispatch, key(&member())).unwrap(),
                Fence(7),
            )
            .await;
        let verified = fixture
            .push(
                &owner(),
                Receipt::verified(
                    tree,
                    dispatch,
                    key(&owner()),
                    hash(),
                    "check".parse().unwrap(),
                    evidence,
                    Status::Exited(Code::from(0_i32)),
                )
                .unwrap(),
                Fence(8),
            )
            .await;
        fixture.standings.push(verified);
        let verdict = fixture
            .push(
                &owner(),
                Receipt::verdict(tree, dispatch, key(&owner()), hash(), evidence, vec![(
                    hash(),
                    Ruling::Unread(Unread::Tied),
                )])
                .unwrap(),
                Fence(9),
            )
            .await;
        let grading = fixture
            .push(
                &owner(),
                Receipt::graded(tree, verdict, vec![Grade::Refused], Grade::Refused).unwrap(),
                Fence(10),
            )
            .await;
        fixture.standings.push(grading);
        let decided = fixture
            .push(
                &owner(),
                Receipt::decide(tree, dispatch, key(&owner()), Decision::Land).unwrap(),
                Fence(11),
            )
            .await;
        fixture.standings.push(decided);
        let landed = fixture
            .push(
                &owner(),
                Receipt::landed(tree, decided, merge).unwrap(),
                Fence(12),
            )
            .await;
        fixture.standings.push(landed);
        fixture
    }

    /// Append one causally later signed receipt.
    ///
    /// # Specification
    /// trivial.
    pub async fn push(
        &mut self,
        signer: &MemorySigner,
        receipt: Receipt,
        fence: Fence,
    ) -> CommitId
    {
        let parents = self
            .commits
            .last()
            .map(|commit| commit.payload().head())
            .into_iter()
            .collect();
        let commit = seal(signer, &fenced(&receipt, fence), parents).await;
        let id = commit.payload().head();
        self.commits.push(commit);
        id
    }
}

/// Store an arbitrary arrival order, then open the real peer over those files.
///
/// # Specification
/// trivial.
pub async fn peer(
    root: &std::path::Path,
    commits: impl IntoIterator<Item = VerifiedMeta<LooseCommit>>,
) -> Peer
{
    let storage = RedbStorage::new(root.join("store")).unwrap();
    for commit in commits {
        let tree = commit.payload().sedimentree_id();
        Storage::<Sendable>::save_loose_commit(&storage, tree, commit)
            .await
            .unwrap();
    }
    drop(storage);
    let state = StateDir::from(root.to_path_buf());
    Peer::open(&state, Identity::load_or_create(&state).unwrap()).unwrap()
}

/// A runtime matching the peer's async engine.
///
/// # Specification
/// trivial.
pub fn runtime() -> tokio::runtime::Runtime
{
    tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .unwrap()
}

/// The output of a future that never waits, such as a held store's reader.
///
/// # Specification
/// trivial.
pub fn ready<F>(future: F) -> F::Output
where
    F: Future,
{
    let mut future = core::pin::pin!(future);
    let mut context = core::task::Context::from_waker(core::task::Waker::noop());
    match future.as_mut().poll(&mut context) {
        core::task::Poll::Ready(output) => output,
        core::task::Poll::Pending => panic!("a held store's reader never waits"),
    }
}

/// A fixed project with aliases, an unheld task and excluded binding shapes.
///
/// # Specification
/// trivial.
pub async fn project_fixture() -> (TreeId, Vec<VerifiedMeta<LooseCommit>>)
{
    use domhringr_record_tree::Anchor;
    use domhringr_record_tree::Authority;
    use domhringr_record_tree::Target;

    let secret = iroh::SecretKey::from_bytes(&[6; 32]);
    let project = TreeId::try_from(*secret.public().as_bytes()).unwrap();
    let unheld =
        TreeId::try_from(*iroh::SecretKey::from_bytes(&[7; 32]).public().as_bytes()).unwrap();
    let opened = seal(&owner(), &opening(&secret), BTreeSet::new()).await;
    let mut commits = vec![opened];
    let targets = [
        (
            "tasks/zeta",
            Target::Anchor(Anchor::Tree(Authority::Key(tree()))),
        ),
        (
            "tasks/alpha",
            Target::Anchor(Anchor::Tree(Authority::Key(tree()))),
        ),
        (
            "tasks/unheld",
            Target::Anchor(Anchor::Tree(Authority::Key(unheld))),
        ),
        (
            "elsewhere",
            Target::Anchor(Anchor::Tree(Authority::Key(tree()))),
        ),
        (
            "tasks/nested/name",
            Target::Anchor(Anchor::Tree(Authority::Key(tree()))),
        ),
        ("tasks/datum", Target::Datum(String::from("not a task"))),
        (
            "tasks/path",
            Target::Anchor(Anchor::Path {
                authority: Authority::Key(tree()),
                path: "inner".parse().unwrap(),
            }),
        ),
        (
            "tasks/domain",
            Target::Anchor(Anchor::Tree(Authority::Domain(
                "example.org".parse().unwrap(),
            ))),
        ),
    ];
    for (number, (path, target)) in targets.into_iter().enumerate() {
        let receipt = Receipt::bind(project, path.parse().unwrap(), target).unwrap();
        let receipt = fenced(
            &receipt,
            Fence(u128::from(arith::saturating_add(
                Int::from(u128::try_from(number).unwrap()),
                Int::from(1),
            ))),
        );
        let parents = commits
            .last()
            .map(|commit| commit.payload().head())
            .into_iter()
            .collect();
        commits.push(seal(&owner(), &receipt, parents).await);
    }
    (project, commits)
}
