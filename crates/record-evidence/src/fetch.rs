//! The fetch: the one stream a reader opens to a holder under [`PROTOCOL`].
//!
//! The reader writes one line, the manifest digest it wants in 64 lowercase
//! hex digits, and finishes its side. The holder answers with one byte —
//! `0x00` when it holds no manifest under the digest, `0x01` when it does —
//! then, when it does, the manifest image and each chunk of the closure it
//! holds, and finishes:
//!
//! ```text
//! answer := 0x00 | 0x01 framed(manifest) (digest framed(chunk))*
//! framed(image) := u32le length || image
//! ```
//!
//! The reader checks the manifest's identity against the digest it asked for
//! and its profile against the evidence profile before reading any chunk,
//! verifies each chunk against the digest it came under, then walks the
//! closure over the chunks received and those its own store holds. Only a
//! whole closure is kept and its content returned: a chunk neither side holds
//! is refused by its digest before any byte reaches a reader.

use core::time::Duration;

use domhringr_record_tree::Content;
use domhringr_record_tree::DialError;
use domhringr_record_tree::Endpoint;
use domhringr_record_tree::Node;
use domhringr_record_tree::Protocol;
use gandr_storage_values::CHUNK_DIGEST_LEN;
use gandr_storage_values::ChunkCount;
use gandr_storage_values::ChunkDigest;
use gandr_storage_values::ChunkImageBuf;
use gandr_storage_values::MANIFEST_DIGEST_LEN;
use gandr_storage_values::ManifestDigest;
use gandr_storage_values::ManifestImage;
use gandr_storage_values::ValueManifest;

use crate::profile::profile;
use crate::store::Chunks;
use crate::store::Evidence;
use crate::store::EvidenceError;
use crate::store::Held;

/// The protocol a holder answers fetches under.
pub const PROTOCOL: Protocol = Protocol(b"domhringr/evidence/0");

/// The most bytes a request holds: 64 hex digits and a newline.
const REQUEST_BYTES: usize = 65_usize;

/// The most bytes an answer holds: 256 MiB.
const ANSWER_BYTES: usize = 0x1000_0000_usize;

/// How long a reader waits for the whole answer once its request is sent.
const DEADLINE: Duration = Duration::from_secs(60);

/// How long a holder that answered waits for the reader to read the answer
/// and close the connection before it lets the connection go.
const LINGER: Duration = Duration::from_secs(10);

/// The answer's first byte when the holder holds no such manifest.
const UNHELD: u8 = 0x00_u8;

/// The answer's first byte when the manifest and chunks follow.
const HELD: u8 = 0x01_u8;

/// A manifest digest read from its 64 hex digits, as a request and a command
/// line write it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct ParsedDigest(ManifestDigest);

impl core::str::FromStr for ParsedDigest
{
    type Err = ParseDigestError;

    /// Read a manifest digest from its 64 lowercase hex digits.
    ///
    /// # Specification
    /// - ensures: accepts exactly the 64 lowercase hex digits
    ///   [`ManifestDigest`]'s display writes, and yields the digest they spell.
    /// - fails: [`ParseDigestError`] for any other text.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseDigestError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a digest round-trips through its text, and 63 and 65
    ///   digits, an uppercase digit and a non-hex digit are each refused.
    /// - witness: `fetch::tests::a_digest_reads_back_from_its_text`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let mut bytes = [0_u8; MANIFEST_DIGEST_LEN];
        let written = data_encoding::HEXLOWER
            .decode_len(text.len())
            .map_err(ParseDigestError)?;
        if written != MANIFEST_DIGEST_LEN {
            return Err(ParseDigestError(data_encoding::DecodeError {
                position: 0_usize,
                kind: data_encoding::DecodeKind::Length,
            }));
        }
        let _decoded = data_encoding::HEXLOWER
            .decode_mut(text.as_bytes(), &mut bytes)
            .map_err(|partial| ParseDigestError(partial.error))?;
        Ok(Self(ManifestDigest::from(bytes)))
    }
}

impl From<ParsedDigest> for ManifestDigest
{
    /// The digest the text spelled.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn from(parsed: ParsedDigest) -> Self
    {
        parsed.0
    }
}

/// Why a text is no manifest digest.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("a manifest digest is 64 lowercase hex digits")]
#[repr(transparent)]
pub struct ParseDigestError(#[source] data_encoding::DecodeError);

/// An answer's bytes, as written or as read.
#[derive(Debug, Default)]
#[repr(transparent)]
struct Answer(Vec<u8>);

impl Answer
{
    /// The answer saying the manifest is not held.
    ///
    /// # Specification
    /// trivial.
    fn unheld() -> Self
    {
        Self(vec![UNHELD])
    }

    /// The answer carrying `held`: its manifest, then each chunk under its
    /// digest.
    ///
    /// # Specification
    /// - ensures: [`HELD`], the framed manifest, then per chunk in digest order
    ///   its digest and its framed image.
    /// - fails: [`ServeError::Oversized`] for an image whose length does not
    ///   fit the frame's 32 bits.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ServeError::Oversized`]: as listed above.
    fn held(held: &Held) -> Result<Self, ServeError>
    {
        let mut answer = Self(vec![HELD]);
        answer.framed(held.manifest())?;
        for (digest, image) in held.chunks().iter() {
            answer.0.extend_from_slice(digest.as_ref());
            answer.framed(&image)?;
        }
        Ok(answer)
    }

    /// Append `image`'s length, then `image`.
    ///
    /// # Specification
    /// - ensures: the length as a little-endian `u32`, then the bytes.
    /// - fails: [`ServeError::Oversized`] when the length does not fit.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ServeError::Oversized`]: as listed above.
    fn framed<Image>(
        &mut self,
        image: &Image,
    ) -> Result<(), ServeError>
    where
        Image: AsRef<[u8]>,
    {
        let bytes = image.as_ref();
        let length = u32::try_from(bytes.len()).map_err(|_wide| ServeError::Oversized)?;
        self.0.extend_from_slice(&length.to_le_bytes());
        self.0.extend_from_slice(bytes);
        Ok(())
    }
}

/// What an answer opens with.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Status
{
    /// The holder holds no manifest under the digest.
    Unheld,
    /// The manifest and chunks follow.
    Held,
}

/// The next item of an answer's chunk list.
enum Next
{
    /// A chunk under this digest.
    Chunk(ChunkDigest),
    /// The answer ended.
    End,
}

/// An answer's bytes not yet read.
#[repr(transparent)]
struct Cursor<'answer>(&'answer [u8]);

/// One framed image of an answer, not yet checked.
#[repr(transparent)]
struct Framed<'answer>(&'answer [u8]);

/// An answer that is not this protocol's framing.
#[derive(Clone, Copy, Debug)]
struct Malformed;

impl<'answer> Cursor<'answer>
{
    /// Read the status byte.
    ///
    /// # Specification
    /// trivial.
    fn status(&mut self) -> Result<Status, Malformed>
    {
        let Some((&first, rest)) = self.0.split_first()
        else {
            return Err(Malformed);
        };
        self.0 = rest;
        match first {
            | UNHELD => Ok(Status::Unheld),
            | HELD => Ok(Status::Held),
            | _ => Err(Malformed),
        }
    }

    /// Read one framed image.
    ///
    /// # Specification
    /// - ensures: the bytes the length prefix counts, the cursor past them.
    /// - fails: [`Malformed`] when the answer ends inside the frame.
    /// - panics: none.
    fn framed(&mut self) -> Result<Framed<'answer>, Malformed>
    {
        let Some((length, rest)) = self.0.split_first_chunk::<4>()
        else {
            return Err(Malformed);
        };
        let length = usize::try_from(u32::from_le_bytes(*length)).map_err(|_wide| Malformed)?;
        let Some((image, rest)) = rest.split_at_checked(length)
        else {
            return Err(Malformed);
        };
        self.0 = rest;
        Ok(Framed(image))
    }

    /// Read the next chunk's digest, or the answer's end.
    ///
    /// # Specification
    /// - ensures: [`Next::End`] exactly when nothing is left.
    /// - fails: [`Malformed`] when fewer than 32 bytes are left.
    /// - panics: none.
    fn next(&mut self) -> Result<Next, Malformed>
    {
        if self.0.is_empty() {
            return Ok(Next::End);
        }
        let Some((digest, rest)) = self.0.split_first_chunk::<CHUNK_DIGEST_LEN>()
        else {
            return Err(Malformed);
        };
        self.0 = rest;
        Ok(Next::Chunk(ChunkDigest::from(*digest)))
    }
}

/// Fetch the evidence `digest` names from the holder at `remote` into
/// `evidence`, and return its content.
///
/// # Specification
/// - ensures: dials `remote` under [`PROTOCOL`], asks for `digest` and reads
///   the answer within sixty seconds; then checks the manifest's identity and
///   profile before any chunk, each chunk against the digest it came under, and
///   walks the closure over the chunks received and those `evidence` holds.
///   Only then are the closure and the manifest kept in `evidence` and the
///   content returned. The connection is closed whatever the outcome.
/// - fails: [`FetchError::Dial`] when `remote` cannot be dialed under
///   [`PROTOCOL`]; [`FetchError::Stream`], [`FetchError::Send`],
///   [`FetchError::Finish`] and [`FetchError::Receive`] when the stream fails;
///   [`FetchError::Silent`] when no answer ends in time;
///   [`FetchError::Malformed`] for an answer this protocol does not frame;
///   [`FetchError::Unheld`] when `remote` holds no such manifest;
///   [`FetchError::Evidence`] with [`EvidenceError::Refused`] naming the value
///   plane's refusal — [`gandr_storage_values::ValueError::UnknownChunk`] for
///   the first chunk of the closure neither side holds,
///   [`gandr_storage_values::ValueError::DigestMismatch`] for a chunk that is
///   not what it came under,
///   [`gandr_storage_values::ValueError::IncompatibleProfile`] for another
///   profile — with [`EvidenceError::Mislabeled`] for a manifest that is not
///   `digest`'s, and with [`EvidenceError::Store`] when the store cannot keep
///   it.
/// - panics: none.
///
/// # Errors
/// - [`FetchError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a reader fetches a value from a holder serving in-process
///   and reads it again from its own store; a holder missing one chunk yields a
///   refusal naming it and keeps nothing; a digest the holder does not hold is
///   unheld.
/// - witness: `fetch::tests::a_reader_fetches_what_a_holder_holds`
#[inline]
pub async fn fetch(
    node: &Node,
    remote: &Endpoint,
    digest: ManifestDigest,
    evidence: &Evidence,
) -> Result<Content, FetchError>
{
    let connection = node.open(remote, PROTOCOL).await?;
    let asked = ask(&connection, digest).await;
    connection.close(iroh::endpoint::VarInt::from_u32(0), b"fetched");
    let answer = asked?;
    admit(evidence, digest, &answer)
}

/// Ask for `digest` on a fresh stream of `connection` and read the answer.
///
/// # Specification
/// - ensures: the digest's line is written and the send side finished; returns
///   the answer read to its end within sixty seconds.
/// - fails: as [`fetch`] for the stream.
/// - panics: none.
///
/// # Errors
/// - [`FetchError::Stream`], [`FetchError::Send`], [`FetchError::Finish`],
///   [`FetchError::Receive`], [`FetchError::Silent`]: as [`fetch`].
async fn ask(
    connection: &iroh::endpoint::Connection,
    digest: ManifestDigest,
) -> Result<Answer, FetchError>
{
    let (mut send, mut recv) = connection.open_bi().await.map_err(FetchError::Stream)?;
    let line = format!("{digest}\n");
    send.write_all(line.as_bytes())
        .await
        .map_err(FetchError::Send)?;
    send.finish().map_err(FetchError::Finish)?;
    let answered = tokio::time::timeout(DEADLINE, recv.read_to_end(ANSWER_BYTES))
        .await
        .map_err(|_elapsed| FetchError::Silent)?;
    let answered = answered.map_err(FetchError::Receive)?;
    Ok(Answer(answered))
}

/// Check `answer` for `digest` and keep what it carries.
///
/// # Specification
/// - ensures: as [`fetch`] states once the answer is read.
/// - fails: as [`fetch`], but for the stream.
/// - panics: none.
///
/// # Errors
/// - [`FetchError`]: as listed above.
fn admit(
    evidence: &Evidence,
    digest: ManifestDigest,
    answer: &Answer,
) -> Result<Content, FetchError>
{
    let malformed = |_malformed: Malformed| FetchError::Malformed(digest);
    let refused = |refusal| FetchError::Evidence(EvidenceError::Refused { digest, refusal });
    let mut cursor = Cursor(&answer.0);
    let status = cursor.status().map_err(malformed)?;
    if status == Status::Unheld {
        return Err(FetchError::Unheld(digest));
    }
    let image = cursor.framed().map_err(malformed)?;
    let manifest = ValueManifest::decode(ManifestImage::from(image.0)).map_err(refused)?;
    let actual = manifest.identity();
    if actual != digest {
        return Err(FetchError::Evidence(EvidenceError::Mislabeled {
            held: digest,
            actual,
        }));
    }
    manifest
        .profile()
        .ensure_matches(&profile())
        .map_err(refused)?;
    let mut chunks = Chunks::default();
    loop {
        let next = cursor.next().map_err(malformed)?;
        let Next::Chunk(claimed) = next
        else {
            break;
        };
        let image = cursor.framed().map_err(malformed)?;
        chunks
            .admit(claimed, ChunkImageBuf::from(Box::<[u8]>::from(image.0)))
            .map_err(refused)?;
    }
    let content = evidence.receive(digest, &manifest, chunks)?;
    Ok(content)
}

/// What a holder answered.
#[derive(Debug)]
pub enum Served
{
    /// The manifest and the chunks of its closure the holder holds were sent.
    Held
    {
        /// The evidence asked for.
        digest: ManifestDigest,
        /// The chunks sent.
        chunks: ChunkCount,
    },
    /// The answer said unheld, for this reason.
    Unheld
    {
        /// The evidence asked for.
        digest: ManifestDigest,
        /// Why it is not held to send.
        reason: EvidenceError,
    },
}

/// Answer the fetch `connection` carries from `evidence`.
///
/// # Specification
/// - ensures: reads one request line from the stream the reader opens, writes
///   the answer — the manifest held under the digest and every chunk of its
///   closure `evidence` holds, or unheld when the manifest is not held, does
///   not decode or is another's — and finishes, then waits up to ten seconds
///   for the reader to close the connection.
/// - fails: [`ServeError::Stream`], [`ServeError::Receive`],
///   [`ServeError::Send`] and [`ServeError::Finish`] when the stream fails,
///   [`ServeError::Request`] for a request that is no digest's line, and
///   [`ServeError::Oversized`] for a chunk too long to frame.
/// - panics: none.
///
/// # Errors
/// - [`ServeError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — a holder serving in-process answers a held value whole, a
///   value missing a chunk without it, and an unheld digest as unheld.
/// - witness: `fetch::tests::a_reader_fetches_what_a_holder_holds`
#[inline]
pub async fn answer(
    evidence: &Evidence,
    connection: iroh::endpoint::Connection,
) -> Result<Served, ServeError>
{
    let served = respond(evidence, &connection).await;
    let _closed = tokio::time::timeout(LINGER, connection.closed()).await;
    served
}

/// Read the request on `connection` and write its answer.
///
/// # Specification
/// - ensures: as [`answer`] states, but for the wait.
/// - fails: as [`answer`].
/// - panics: none.
///
/// # Errors
/// - [`ServeError`]: as [`answer`].
async fn respond(
    evidence: &Evidence,
    connection: &iroh::endpoint::Connection,
) -> Result<Served, ServeError>
{
    let (mut send, mut recv) = connection.accept_bi().await.map_err(ServeError::Stream)?;
    let asked = recv
        .read_to_end(REQUEST_BYTES)
        .await
        .map_err(ServeError::Receive)?;
    let line = String::from_utf8(asked).map_err(|_unreadable| ServeError::Request)?;
    let text = line.strip_suffix('\n').ok_or(ServeError::Request)?;
    let parsed = text
        .parse::<ParsedDigest>()
        .map_err(|_unparsed| ServeError::Request)?;
    let digest = ManifestDigest::from(parsed);
    let (written, served) = match evidence.held(digest) {
        | Ok(held) => {
            let written = Answer::held(&held)?;
            (written, Served::Held {
                digest,
                chunks: ChunkCount::from(held.chunks().iter().count()),
            })
        },
        | Err(reason) => (Answer::unheld(), Served::Unheld { digest, reason }),
    };
    send.write_all(&written.0).await.map_err(ServeError::Send)?;
    send.finish().map_err(ServeError::Finish)?;
    Ok(served)
}

/// Why a fetch failed.
#[derive(Debug, thiserror::Error)]
pub enum FetchError
{
    /// The holder cannot be dialed under the evidence protocol.
    #[error(transparent)]
    Dial(#[from] DialError),
    /// No stream opens on the connection.
    #[error("cannot open the fetch's stream")]
    Stream(#[source] iroh::endpoint::ConnectionError),
    /// The request cannot be written.
    #[error("cannot write the fetch's request")]
    Send(#[source] iroh::endpoint::WriteError),
    /// The request's stream cannot be finished.
    #[error("cannot finish the fetch's request")]
    Finish(#[source] iroh::endpoint::ClosedStream),
    /// The answer cannot be read.
    #[error("cannot read the holder's answer")]
    Receive(#[source] iroh::endpoint::ReadToEndError),
    /// No answer ended in time.
    #[error("the holder did not answer within sixty seconds")]
    Silent,
    /// The answer is not this protocol's framing.
    #[error("the holder's answer for {0} is malformed")]
    Malformed(ManifestDigest),
    /// The holder holds no manifest under the digest.
    #[error("the holder does not hold evidence {0}")]
    Unheld(ManifestDigest),
    /// The value the answer carries is refused, or cannot be kept.
    #[error(transparent)]
    Evidence(#[from] EvidenceError),
}

/// Why a holder could not answer a fetch.
#[derive(Debug, thiserror::Error)]
pub enum ServeError
{
    /// No stream was opened on the connection.
    #[error("cannot accept the fetch's stream")]
    Stream(#[source] iroh::endpoint::ConnectionError),
    /// The request cannot be read.
    #[error("cannot read the fetch's request")]
    Receive(#[source] iroh::endpoint::ReadToEndError),
    /// The request is not one digest's line.
    #[error("the fetch's request is not a manifest digest's line")]
    Request,
    /// A chunk is too long to frame.
    #[error("a chunk is too long to frame")]
    Oversized,
    /// The answer cannot be written.
    #[error("cannot write the fetch's answer")]
    Send(#[source] iroh::endpoint::WriteError),
    /// The answer's stream cannot be finished.
    #[error("cannot finish the fetch's answer")]
    Finish(#[source] iroh::endpoint::ClosedStream),
}

#[cfg(test)]
mod tests
{
    use alloc::sync::Arc;
    use core::fmt::Write as _;

    use domhringr_record_tree::AcceptError;
    use domhringr_record_tree::BindPort;
    use domhringr_record_tree::Content;
    use domhringr_record_tree::Endpoint;
    use domhringr_record_tree::Identity;
    use domhringr_record_tree::Incoming;
    use domhringr_record_tree::Node;
    use domhringr_record_tree::Peer;
    use domhringr_record_tree::StateDir;
    use domhringr_record_tree::UdpPort;
    use gandr_storage_values::ManifestDigest;
    use gandr_storage_values::ValueError;

    use super::FetchError;
    use super::PROTOCOL;
    use super::ParsedDigest;
    use super::answer;
    use super::fetch;
    use crate::store::Evidence;
    use crate::store::EvidenceError;
    use crate::store::Staged;

    /// A UDP port free on this host now.
    ///
    /// # Specification
    /// trivial.
    fn free_port() -> UdpPort
    {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        port.to_string().parse().unwrap()
    }

    /// Open and bind a peer on the state directory `root`, accepting the
    /// evidence protocol on `port`.
    ///
    /// # Specification
    /// trivial.
    async fn bound(
        root: &tempfile::TempDir,
        port: BindPort,
    ) -> Node
    {
        let state = StateDir::from(root.path().to_path_buf());
        let identity = Identity::load_or_create(&state).unwrap();
        Peer::open(&state, identity)
            .unwrap()
            .bind(port, &[PROTOCOL])
            .await
            .unwrap()
    }

    /// Answer every fetch `node` accepts from `evidence` until its endpoint
    /// closes.
    ///
    /// # Specification
    /// trivial.
    fn serve(
        node: &Arc<Node>,
        evidence: Evidence,
    )
    {
        let node = Arc::clone(node);
        drop(tokio::spawn(async move {
            loop {
                match node.accept().await {
                    | Ok(Incoming::Protocol { connection, .. }) => {
                        let _served = answer(&evidence, connection).await;
                    },
                    | Err(AcceptError::Closed) => break,
                    | Ok(_) | Err(_) => {},
                }
            }
        }));
    }

    #[test]
    fn a_digest_reads_back_from_its_text()
    {
        let digest = Staged::new(&Content::from(b"named\n".to_vec()))
            .unwrap()
            .digest();
        let text = digest.to_string();
        assert_eq!(
            ManifestDigest::from(text.parse::<ParsedDigest>().unwrap()),
            digest
        );
        let short = text.get(.. 63).unwrap();
        let upper = text.to_uppercase();
        for refused in [short, &format!("{text}0"), &upper, &format!("{short}g")] {
            assert!(
                refused.parse::<ParsedDigest>().is_err(),
                "{refused:?} is no digest"
            );
        }
    }

    #[test]
    fn a_reader_fetches_what_a_holder_holds()
    {
        let (holder_root, reader_root) =
            (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let port = free_port();
            let holder = Arc::new(bound(&holder_root, BindPort::Fixed(port)).await);
            let reader = bound(&reader_root, BindPort::Ephemeral).await;
            let holder_state = StateDir::from(holder_root.path().to_path_buf());
            let held = Evidence::open(&holder_state);
            serve(&holder, held.clone());
            let at = format!("{}@127.0.0.1:{port}", holder.endpoint_key())
                .parse::<Endpoint>()
                .unwrap();
            let mine = Evidence::open(&StateDir::from(reader_root.path().to_path_buf()));

            let report = |kind: &str| {
                let mut text = String::new();
                for line in 0_u32 .. 2000_u32 {
                    writeln!(text, "line {line} of {kind}").unwrap();
                }
                Content::from(text.into_bytes())
            };
            let content = report("the report");
            let digest = held.commit(&content).unwrap();
            assert!(
                matches!(mine.read(digest), Err(EvidenceError::Unheld(_))),
                "the reader holds nothing before it fetches"
            );
            assert_eq!(fetch(&reader, &at, digest, &mine).await.unwrap(), content);
            assert_eq!(
                mine.read(digest).unwrap(),
                content,
                "the fetched value is kept by the reader"
            );

            let other = report("another report");
            let staged = Staged::new(&other).unwrap();
            held.keep(&staged).unwrap();
            // A chunk the reader does not hold already: the walk cannot fill
            // it from the reader's own store.
            let kept = reader_root.path().join("evidence").join("chunks");
            let (missing, _image) = staged
                .chunks()
                .find(|&(chunk, _image)| !kept.join(chunk.to_string()).exists())
                .unwrap();
            std::fs::remove_file(
                holder_root
                    .path()
                    .join("evidence")
                    .join("chunks")
                    .join(missing.to_string()),
            )
            .unwrap();
            assert!(
                matches!(
                    fetch(&reader, &at, staged.digest(), &mine).await,
                    Err(FetchError::Evidence(EvidenceError::Refused {
                        refusal: ValueError::UnknownChunk { digest },
                        ..
                    })) if digest == missing
                ),
                "a chunk neither side holds is refused by its digest"
            );
            assert!(
                matches!(mine.read(staged.digest()), Err(EvidenceError::Unheld(_))),
                "a refused value is not kept"
            );

            let unheld = Staged::new(&Content::from(b"never kept\n".to_vec()))
                .unwrap()
                .digest();
            assert!(matches!(
                fetch(&reader, &at, unheld, &mine).await,
                Err(FetchError::Unheld(digest)) if digest == unheld
            ));

            reader.close().await;
            drop(reader);
            holder.close().await;
            drop(holder);
        });
    }
}
