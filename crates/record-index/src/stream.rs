//! One authenticated question per bidirectional stream under
//! `domhringr/index/0`.
//!
//! The protocol carries one question per bidirectional stream. Dependent
//! project and dialogue questions share one connection. Answers include all
//! framing within an inclusive 1 MiB cap. An oversized proof produces only its
//! encoded size; a reader also rejects an over-cap stream from a dishonest
//! holder. Readers allow sixty seconds per answer; holders allow ten idle
//! seconds between streams. Transport returns untrusted proof material; a
//! reader calls `Answer::verify` before reading its contents.

mod codec;

#[cfg(test)]
mod tests;

use alloc::collections::VecDeque;
use core::fmt;
use core::time::Duration;

use anodized::spec;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Protocol;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use crate::Index;
use crate::IndexKind;
use crate::ManifestError;
use crate::WireError;
use crate::WireImage;
use crate::prove;
use crate::prove::Answer;
use crate::prove::ProveError;
use crate::prove::Query;
use crate::store::Store;
use crate::store::StoreError;

/// The protocol bound by holders of derived index manifests.
pub const PROTOCOL: Protocol = Protocol(b"domhringr/index/0");

/// The inclusive maximum size of one answer's complete framing.
pub const ANSWER_CAP: ByteSize = ByteSize(0x0010_0000);

/// The reader's deadline for a whole answer.
const DEADLINE: Duration = Duration::from_secs(60);

/// The holder's idle interval between streams, including final consumption.
const LINGER: Duration = Duration::from_secs(10);

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

/// A content-addressed index and one key or range within it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Request
{
    /// The digest selected by the reader's attestation or project entry.
    pub digest: IndexDigest,
    /// The exact key or range to prove.
    pub query: Query,
}

/// The number of questions answered before the connection closed or idled.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
#[repr(transparent)]
pub struct Served(pub u64);

/// Bounded hydration reused across questions and connections of a serving peer.
///
/// At most four trees are retained, each with at most 65,536 records and 4 MiB
/// of key/value payload. This bounds retained payload to 16 MiB plus bounded
/// tree/node metadata; larger trees are served without entering the cache.
/// Ownership is exclusive while constructing a proof, never while awaiting I/O.
#[derive(Debug, Default)]
#[repr(transparent)]
pub struct Cache(VecDeque<(IndexDigest, Index)>);

impl Cache
{
    /// Construct a proof, hydrating only when this bounded cache misses.
    ///
    /// # Specification
    /// - ensures: a successful answer comes from the named held index; the
    ///   cache retains at most four trees under its record and payload bounds.
    /// - fails: unheld, malformed storage or proof construction failure.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`StreamError`]: the named proof cannot be constructed.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the stream serves a held proof or its exact over-cap
    ///   extent.
    /// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
    #[spec(ensures: |ret| self.0.len() <= 4 && ret.as_ref().map_or(true, |answer|
        answer.manifest.identity().is_ok_and(|digest| digest == request.digest)))]
    #[inline]
    pub fn answer(
        &mut self,
        store: &Store,
        request: &Request,
    ) -> Result<Answer, StreamError>
    {
        if let Some(&(_digest, ref index)) =
            self.0.iter().find(|&&(digest, _)| digest == request.digest)
        {
            let answer = prove::answer(index, &request.query)?;
            return Ok(answer);
        }
        let index = match store.load(request.digest) {
            Ok(index) => index,
            Err(StoreError::Unheld(digest)) => return Err(StreamError::Unheld(digest)),
            Err(failure) => return Err(failure.into()),
        };
        let answer = prove::answer(&index, &request.query)?;
        let payload = index
            .tree
            .records()
            .iter()
            .fold(Int::from(0_usize), |size, record| {
                let size = arith::saturating_add(size, Int::from(record.key().as_ref().len()));
                arith::saturating_add(size, Int::from(record.value().as_ref().len()))
            });
        if index.tree.records().len() <= 0x0001_0000 && payload <= Int::from(0x0040_0000_usize) {
            if self.0.len() == 4 {
                let _evicted = self.0.pop_front();
            }
            self.0.push_back((request.digest, index));
        }
        Ok(answer)
    }
}

/// A transport, framing, identity or authenticated-record refusal.
#[derive(Debug, thiserror::Error)]
pub enum StreamError
{
    /// No held manifest has this digest.
    #[error("unheld {0}")]
    Unheld(IndexDigest),
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
    /// A manifest uses a foreign layout or kind.
    #[error(transparent)]
    Manifest(#[from] ManifestError),
    /// A proof or decoded move fails verification.
    #[error(transparent)]
    Proof(#[from] ProveError),
    /// Held index files are damaged or unreadable.
    #[error(transparent)]
    Store(#[from] StoreError),
}

/// Measure all framing a holder would send for this proof, before applying cap.
///
/// # Specification
/// - ensures: the count includes status, manifest, value/records and node
///   frames.
/// - fails: an unrepresentable field or extent is refused.
/// - panics: none.
/// - executable: none — the counting encoder is its own specification;
///   independently pinned full answer sizes are the oracle.
///
/// # Errors
/// - [`StreamError`]: manifest or framing failure.
///
/// # Adequacy
/// - hypothesis: L2 — pinned measurements compare complete answer sizes.
/// - witness: `measure::tests::the_proof_sizes_are_pinned`
#[inline]
pub fn encoded_size(answer: &Answer) -> Result<ByteSize, StreamError>
{
    codec::size(answer)
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

/// Receive untrusted proof material on a fresh stream of a reusable connection.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: framing, manifest identity and kind are checked; callers must run
///   [`Answer::verify`] before reading proof contents. The connection is
///   reusable.
/// - fails: transport, cap, unheld, framing or manifest identity refusal.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: transport, framing or manifest validation failed.
///
/// # Adequacy
/// - hypothesis: L3 — unknown digests produce a named unheld refusal.
/// - witness: `stream::tests::an_unheld_digest_is_answered_unheld`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
#[inline]
pub async fn ask(
    connection: &iroh::endpoint::Connection,
    request: &Request,
    kind: IndexKind,
) -> Result<Answer, StreamError>
{
    let image = codec::request(request)?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(image.as_ref()).await?;
    send.finish()?;
    let image = read(&mut recv).await?;
    let answer = codec::decode(request, kind, &image)?;
    Ok(answer)
}

/// Answer each stream, waiting at most ten idle seconds after the last answer.
///
/// # Specification
/// - requires: a Tokio runtime with time and I/O is active.
/// - ensures: unknown digests receive exactly tag zero; proofs exceeding the
///   cap receive tag two and their extent, without nodes; dependent requests
///   can use the same connection until it closes or reaches the idle deadline.
/// - fails: request, storage, proof or transport failure.
/// - panics: none.
///
/// # Errors
/// - [`StreamError`]: a request cannot be answered.
///
/// # Adequacy
/// - hypothesis: L3 — unknown digests are unheld and oversized proofs carry
///   size.
/// - witness: `stream::tests::an_unheld_digest_is_answered_unheld`
/// - witness: `stream::tests::a_proof_past_the_cap_is_answered_with_its_size`
#[spec(requires: tokio::runtime::Handle::try_current().is_ok())]
#[inline]
pub async fn answer(
    store: &Store,
    cache: &tokio::sync::Mutex<Cache>,
    connection: iroh::endpoint::Connection,
) -> Result<Served, StreamError>
{
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
        let request = codec::read_request(&image)?;
        let image = {
            let answer = cache.lock().await.answer(store, &request);
            match answer {
                Ok(answer) => codec::encode(&answer)?,
                Err(StreamError::Unheld(_digest)) => WireImage(vec![0]),
                Err(failure) => return Err(failure),
            }
        };
        send.write_all(image.as_ref()).await?;
        send.finish()?;
        served.0 = u64::from(arith::saturating_add(Int::from(served.0), Int::from(1)));
    }
}
