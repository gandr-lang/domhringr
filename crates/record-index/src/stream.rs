//! One request per bidirectional stream under `domhringr/index/0`.
//!
//! A request is about one store root: a question of the keyed schema, the
//! root's manifest, or one of its nodes ([`codec`] states the bytes).
//! Dependent questions share one connection. Answers include all framing
//! within an inclusive 1 MiB cap. A reply past the cap is answered with its
//! size alone; a reader also refuses an over-cap stream from a dishonest
//! holder. Readers allow sixty seconds per answer; holders allow ten idle
//! seconds between streams.
//!
//! Nothing a holder sends is trusted. [`Remote`] verifies every proof
//! against the attested root, and [`fetch`] admits a manifest only when it
//! hashes to that root and a node only when it hashes to its identity.

mod codec;

#[cfg(test)]
mod tests;

use alloc::collections::VecDeque;
use core::fmt;
use core::time::Duration;
use std::io;

use anodized::spec;
use domhringr_record_tree::Protocol;
use gandr_storage_records::BlockStore as _;
use gandr_storage_records::ChildRef;
use gandr_storage_records::DecodeWork;
use gandr_storage_records::DecodedNode;
use gandr_storage_records::InMemoryBlockStore;
use gandr_storage_records::NodeHash;
use gandr_storage_records::OwnedEncodedNode;
use gandr_storage_records::StoredNode;
use gandr_storage_records::decode_node;
use gandr_storage_schema::Answer;
use gandr_storage_schema::ManifestImage;
use gandr_storage_schema::Proof;
use gandr_storage_schema::ProofImage;
use gandr_storage_schema::Question;
use gandr_storage_schema::SchemaError;
use gandr_storage_schema::StoreManifest;
use gandr_storage_schema::StoreRoot;
use gandr_storage_schema::TableRoot;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::WireError;
use crate::WireImage;
use crate::keyed;
use crate::keyed::Keyed;
use crate::prove::Ask;
use crate::prove::ProveError;
use crate::store::Store;
use crate::store::StoreError;
use crate::wire::Body;

/// The protocol bound by holders of project stores.
pub const PROTOCOL: Protocol = Protocol(b"domhringr/index/0");

/// The inclusive maximum size of one answer's complete framing.
pub const ANSWER_CAP: ByteSize = ByteSize(0x0010_0000);

/// The reader's deadline for a whole answer.
const DEADLINE: Duration = Duration::from_secs(60);

/// The holder's idle interval between streams, including final consumption.
const LINGER: Duration = Duration::from_secs(10);

/// The most records a store may have for the serving cache to retain it.
const RETAINED: u64 = 0x0004_0000;

/// An encoded byte extent, distinct from record or stream counts.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
#[repr(transparent)]
pub struct ByteSize(pub u64);

impl fmt::Display for ByteSize
{
    /// Write a byte count in decimal.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        self.0.fmt(f)
    }
}

/// What a reader asks a holder about one store root.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request
{
    /// A question, answered with its proof.
    Question
    {
        /// The attested root.
        root: StoreRoot,
        /// The question.
        question: Question,
    },
    /// The root's manifest image.
    Manifest(StoreRoot),
    /// One node of the root's tables.
    Node
    {
        /// The attested root.
        root: StoreRoot,
        /// The node's identity.
        node: NodeHash,
    },
}

impl Request
{
    /// The root the request is about.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn root(&self) -> StoreRoot
    {
        match *self {
            Self::Question { root, .. } | Self::Manifest(root) | Self::Node { root, .. } => root,
        }
    }
}

/// The number of requests answered before the connection closed or idled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Served(pub u64);

/// Reopened stores reused across questions and connections of a serving
/// peer.
///
/// At most four stores are retained, each of at most 262,144 records across
/// its tables; a larger store is reopened for each question. Ownership is
/// exclusive while constructing a proof, never while awaiting I/O.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Cache(VecDeque<gandr_storage_schema::Store>);

impl Cache
{
    /// Prove a question, reopening the store only when this cache misses.
    ///
    /// # Specification
    /// - ensures: a successful proof is of the named root; the cache retains at
    ///   most four stores within the record bound.
    /// - fails: unheld, damaged storage or proof construction failure.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StreamError`]: the proof cannot be constructed.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the stream serves a held proof or its exact over-cap
    ///   extent.
    /// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
    #[spec(ensures: |ret| self.0.len() <= 4)]
    #[inline]
    pub fn prove(
        &mut self,
        store: &Store,
        root: StoreRoot,
        question: &Question,
    ) -> Result<Proof, StreamError>
    {
        if let Some(held) = self.0.iter().find(|held| held.root() == root) {
            return Ok(held.prove(question).map_err(StoreError::from)?);
        }
        let held = store.load(Keyed::shared()?, root)?;
        let proof = held.prove(question).map_err(StoreError::from)?;
        let records = held
            .manifest()
            .tables()
            .iter()
            .fold(Int::from(0_u64), |sum, table| {
                arith::saturating_add(sum, Int::from(u64::from(table.records())))
            });
        if records <= Int::from(RETAINED) {
            if self.0.len() == 4 {
                let _evicted = self.0.pop_front();
            }
            self.0.push_back(held);
        }
        Ok(proof)
    }
}

/// A transport, framing, identity or authenticated-content refusal.
#[derive(Debug, thiserror::Error)]
pub enum StreamError
{
    /// No held manifest has this root.
    #[error("unheld {0}")]
    Unheld(StoreRoot),
    /// An answer exceeds the inclusive one-MiB ceiling.
    #[error("index answer exceeds 1048576 bytes: {0}")]
    Oversize(ByteSize),
    /// A peer did not complete its stream within sixty seconds.
    #[error("index stream did not finish within sixty seconds")]
    Silent,
    /// A stream cannot be opened or accepted.
    #[error("cannot open index stream: {0}")]
    Connection(#[from] iroh::endpoint::ConnectionError),
    /// Stream bytes cannot be written.
    #[error("cannot write index stream: {0}")]
    Write(#[from] iroh::endpoint::WriteError),
    /// The send half cannot be finished.
    #[error("cannot finish index stream: {0}")]
    Finish(#[from] iroh::endpoint::ClosedStream),
    /// Stream bytes cannot be read.
    #[error("cannot read index stream: {0}")]
    Read(#[from] iroh::endpoint::ReadToEndError),
    /// Framing is malformed.
    #[error(transparent)]
    Wire(#[from] WireError),
    /// The keyed schema didn't resolve.
    #[error(transparent)]
    Schema(#[from] SchemaError),
    /// A proof, manifest or node fails verification.
    #[error(transparent)]
    Proof(#[from] gandr_storage_schema::StoreError),
    /// A node fails authentication or decoding.
    #[error(transparent)]
    Records(#[from] gandr_storage_records::RecordTreeError),
    /// Held store files are damaged or unreadable.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Read the bounded transport image, independent of what status the holder
/// sends.
///
/// # Specification
/// - ensures: accepts exactly the cap, rejects any greater extent before
///   decode.
/// - fails: oversize, interrupted stream or deadline expiry.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: the image cannot be read within its size and time bounds.
///
/// # Adequacy
/// - hypothesis: L3 — the inclusive boundary and its next byte separate the
///   cap.
/// - witness: `stream::tests::an_answer_at_the_cap_is_read_and_one_byte_past_is_refused`
#[spec(ensures: |ret| ret.as_ref().map_or(true, |image| u64::try_from(image.as_ref().len()).is_ok_and(|length| length <= ANSWER_CAP.0)))]
async fn read(recv: &mut iroh::endpoint::RecvStream) -> Result<WireImage, StreamError>
{
    let cap = usize::try_from(ANSWER_CAP.0).map_err(|_width| WireError::Length)?;
    let result = tokio::time::timeout(DEADLINE, recv.read_to_end(cap))
        .await
        .map_err(|_elapsed| StreamError::Silent)?;
    match result {
        Ok(bytes) => Ok(WireImage(bytes)),
        Err(iroh::endpoint::ReadToEndError::TooLong) => Err(StreamError::Oversize(ByteSize(
            u64::from(arith::saturating_add(Int::from(ANSWER_CAP.0), Int::from(1))),
        ))),
        Err(failure) => Err(failure.into()),
    }
}

/// Send one request on a fresh stream and read the untrusted reply.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: the reply's body, not yet authenticated; the connection is
///   reusable.
/// - fails: transport, cap, unheld or framing refusal.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: as above.
///
/// # Adequacy
/// - hypothesis: L3 — an unknown root produces a named unheld refusal.
/// - witness: `stream::tests::an_unheld_root_is_answered_unheld`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
async fn request(
    connection: &iroh::endpoint::Connection,
    request: &Request,
) -> Result<WireImage, StreamError>
{
    let image = codec::request(request)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(image.as_ref()).await?;
    send.finish()?;
    read(&mut recv).await
}

/// A reader of a store it holds only the attested root of.
#[derive(Clone, Copy, Debug)]
pub struct Remote<'link>
{
    /// The holder's connection.
    pub connection: &'link iroh::endpoint::Connection,
    /// The attested root every proof is verified against.
    pub root: StoreRoot,
}

impl Ask for Remote<'_>
{
    /// Ask the holder and verify its proof against the attested root.
    ///
    /// # Specification
    /// - requires: a Tokio runtime with time and I/O is active.
    /// - ensures: on success the answer the proof verifies to under `root`.
    /// - fails: transport, an unheld root, a malformed image or a proof that
    ///   doesn't verify.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ProveError::Stream`]: as above.
    ///
    /// # Adequacy
    /// - hypothesis: L2 — the proving reader reads the fixture as the local one
    ///   does; L3 — a proof against another root is refused.
    /// - witness: `prove::tests::a_proving_reader_reads_what_the_store_holds`
    #[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
    #[inline]
    async fn ask(
        &mut self,
        question: &Question,
    ) -> Result<Answer, ProveError>
    {
        let keyed = Keyed::shared().map_err(StreamError::from)?;
        let image = request(self.connection, &Request::Question {
            root: self.root,
            question: question.clone(),
        })
        .await?;
        let body = codec::read_reply(&image, self.root)?;
        let proof = Proof::decode(
            ProofImage::from(body.0),
            &keyed.schema,
            keyed::params(),
            question,
        )?;
        Ok(proof.verify(self.root, &keyed.schema, keyed::params(), question)?)
    }
}

/// Hold a root's whole store, fetching what isn't held from its holder.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: on success the store `root` names, its manifest and nodes kept in
///   `store`; a node already held isn't asked for.
/// - fails: transport, an unheld root, a manifest not hashing to `root`, a node
///   not hashing to its identity, or a store that doesn't reopen.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: as above.
///
/// # Adequacy
/// - hypothesis: L2 — a reader holding nothing holds the served store.
/// - witness: `stream::tests::a_fetched_store_is_the_served_one`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
#[inline]
pub async fn fetch(
    connection: &iroh::endpoint::Connection,
    store: &Store,
    root: StoreRoot,
) -> Result<gandr_storage_schema::Store, StreamError>
{
    let keyed = Keyed::shared()?;
    match store.load(keyed, root) {
        Err(StoreError::Unheld(_root)) => {},
        held => return Ok(held?),
    }
    let image = request(connection, &Request::Manifest(root)).await?;
    let body = codec::read_reply(&image, root)?;
    let manifest = StoreManifest::decode(ManifestImage::from(body.0))?;
    if manifest.identity() != root {
        return Err(StoreError::Mislabeled {
            named: root,
            actual: manifest.identity(),
        }
        .into());
    }
    let mut work = DecodeWork::new();
    let mut blocks = InMemoryBlockStore::new();
    let mut pending: Vec<NodeHash> = manifest.tables().iter().map(TableRoot::root_node).collect();
    while let Some(node) = pending.pop() {
        let bytes = match store.node(node) {
            Ok(bytes) => bytes,
            Err(StoreError::File { ref source, .. })
                if source.kind() == io::ErrorKind::NotFound =>
            {
                let image = request(connection, &Request::Node { root, node }).await?;
                OwnedEncodedNode::from(codec::read_reply(&image, root)?.0)
            },
            Err(failure) => return Err(failure.into()),
        };
        blocks.insert(StoredNode::new(node, bytes.as_borrowed()))?;
        store.hold_node(node, Body(bytes.as_ref()))?;
        if let DecodedNode::Internal(internal) = decode_node(blocks.load(node)?.bytes(), &mut work)?
        {
            pending.extend(internal.children().iter().map(ChildRef::identity));
        }
    }
    store.hold_manifest(root, Body(manifest.encode().as_ref()))?;
    Ok(store.load(keyed, root)?)
}

/// Answer each stream, waiting at most ten idle seconds after the last answer.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: an unheld root receives exactly tag zero; a reply past the cap
///   receives tag two and its extent; dependent requests can use the same
///   connection until it closes or reaches the idle deadline.
/// - fails: request, storage, proof or transport failure.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: a request cannot be answered.
///
/// # Adequacy
/// - hypothesis: L3 — unknown roots are unheld and oversized proofs carry size.
/// - witness: `stream::tests::an_unheld_root_is_answered_unheld`
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
#[inline]
pub async fn answer(
    store: &Store,
    cache: &tokio::sync::Mutex<Cache>,
    connection: iroh::endpoint::Connection,
) -> Result<Served, StreamError>
{
    let keyed = Keyed::shared()?;
    let mut served = Served::default();
    loop {
        let stream = tokio::select! {
            biased;
            _closed = connection.closed() => return Ok(served),
            stream = tokio::time::timeout(LINGER, connection.accept_bi()) => stream,
        };
        let (mut send, mut recv) = match stream {
            Ok(stream) => stream?,
            Err(_idle) => return Ok(served),
        };
        let image = read(&mut recv).await?;
        let request = codec::read_request(&image, keyed)?;
        let reply = match request {
            Request::Question { root, ref question } => {
                let proof = cache.lock().await.prove(store, root, question);
                proof.map(|proof| proof.encode().as_ref().to_vec())
            },
            Request::Manifest(root) => store
                .manifest(root)
                .map(|manifest| manifest.encode().as_ref().to_vec())
                .map_err(StreamError::from),
            Request::Node { root, node } => store
                .manifest(root)
                .and_then(|_manifest| store.node(node))
                .map(|bytes| bytes.as_ref().to_vec())
                .map_err(StreamError::from),
        };
        let image = match reply {
            Ok(reply) => codec::reply(Body(&reply))?,
            Err(StreamError::Unheld(_root) | StreamError::Store(StoreError::Unheld(_root))) => {
                codec::unheld()
            },
            Err(failure) => return Err(failure),
        };
        send.write_all(image.as_ref()).await?;
        send.finish()?;
        served.0 = u64::from(arith::saturating_add(Int::from(served.0), Int::from(1)));
    }
}
