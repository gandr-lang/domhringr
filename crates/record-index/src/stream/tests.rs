//! Real local connections exercise both holder and reader framing boundaries.

use alloc::sync::Arc;

use domhringr_record_tree::BindPort;
use domhringr_record_tree::Endpoint;
use domhringr_record_tree::Identity;
use domhringr_record_tree::Incoming;
use domhringr_record_tree::IndexDigest;
use domhringr_record_tree::Node;
use domhringr_record_tree::Peer;
use domhringr_record_tree::StateDir;
use gandr_storage_records::RecordRef;
use gandr_storage_records::RecordTree;
use gandr_storage_records::TreeParams;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::ANSWER_CAP;
use super::ByteSize;
use super::Cache;
use super::PROTOCOL;
use super::Request;
use super::StreamError;
use super::codec;
use crate::Index;
use crate::IndexKind;
use crate::prove;
use crate::prove::Query;
use crate::prove::Verified;
use crate::store::Store;
use crate::testing;

/// Open the actual record peer endpoint, accepting the index protocol.
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

/// Endpoint pair whose temporary stores outlive both nodes.
struct Pair
{
    /// The holder's actual serving endpoint.
    holder: Arc<Node>,
    /// The reader's actual dialing endpoint.
    reader: Node,
    /// The holder's direct loopback address.
    at: Endpoint,
    /// The holder's node and manifest files.
    holder_root: tempfile::TempDir,
    /// The reader's otherwise empty state.
    _reader_root: tempfile::TempDir,
}

impl Pair
{
    /// Bind two independent peers with an explicit loopback route.
    ///
    /// # Specification
    /// trivial.
    async fn new() -> Self
    {
        let socket = std::net::UdpSocket::bind(("127.0.0.1", 0)).unwrap();
        let port = socket.local_addr().unwrap().port();
        drop(socket);
        let holder_root = tempfile::tempdir().unwrap();
        let reader_root = tempfile::tempdir().unwrap();
        let holder = Arc::new(
            bound(
                &holder_root,
                BindPort::Fixed(port.to_string().parse().unwrap()),
            )
            .await,
        );
        let reader = bound(&reader_root, BindPort::Ephemeral).await;
        let at = format!("{}@127.0.0.1:{port}", holder.endpoint_key())
            .parse()
            .unwrap();
        Self {
            holder,
            reader,
            at,
            holder_root,
            _reader_root: reader_root,
        }
    }

    /// Answer the next connection using the production multi-stream holder.
    ///
    /// # Specification
    /// trivial.
    fn serve(&self) -> tokio::task::JoinHandle<super::Served>
    {
        let holder = Arc::clone(&self.holder);
        let store = Store::open(&StateDir::from(self.holder_root.path().to_path_buf()));
        tokio::spawn(async move {
            let Incoming::Protocol { connection, .. } = holder.accept().await.unwrap()
            else {
                panic!("index protocol");
            };
            super::answer(
                &store,
                &tokio::sync::Mutex::new(Cache::default()),
                connection,
            )
            .await
            .unwrap()
        })
    }
}

#[test]
fn an_answer_at_the_cap_is_read_and_one_byte_past_is_refused()
{
    testing::runtime().block_on(async {
        let pair = Pair::new().await;
        let holder = Arc::clone(&pair.holder);
        let serving = tokio::spawn(async move {
            let Incoming::Protocol { connection, .. } = holder.accept().await.unwrap()
            else {
                panic!("index protocol");
            };
            for size in [
                ANSWER_CAP,
                ByteSize(u64::from(arith::saturating_add(
                    Int::from(ANSWER_CAP.0),
                    Int::from(1),
                ))),
            ] {
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                assert_eq!(recv.read_to_end(1).await.unwrap(), [0]);
                let bytes = vec![0xa5; usize::try_from(size.0).unwrap()];
                send.write_all(&bytes).await.unwrap();
                send.finish().unwrap();
            }
            let _closed = connection.closed().await;
        });
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        for size in [
            ANSWER_CAP,
            ByteSize(u64::from(arith::saturating_add(
                Int::from(ANSWER_CAP.0),
                Int::from(1),
            ))),
        ] {
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(&[0]).await.unwrap();
            send.finish().unwrap();
            let result = super::read(&mut recv).await;
            if size == ANSWER_CAP {
                let image = result.unwrap();
                assert_eq!(image.0, vec![0xa5; usize::try_from(ANSWER_CAP.0).unwrap()]);
            }
            else {
                assert!(matches!(result, Err(StreamError::Oversize(actual)) if actual == size));
            }
        }
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        serving.await.unwrap();
    });
}

#[test]
fn a_proof_past_the_cap_is_answered_with_its_size()
{
    testing::runtime().block_on(async {
        let pair = Pair::new().await;
        let value = vec![0x7b; 600_000];
        let tree = RecordTree::build(&[RecordRef::new(b"key", value.as_slice())], TreeParams::current()).unwrap();
        let index = Index::new(IndexKind::Dialogue, tree);
        let store = Store::open(&StateDir::from(pair.holder_root.path().to_path_buf()));
        let digest = store.keep(&index).unwrap();
        let request = Request { digest, query: Query::Key(b"key".as_slice().into()) };
        let proof = prove::answer(&index, &request.query).unwrap();
        let size = super::encoded_size(&proof).unwrap();
        assert!(size > ANSWER_CAP);
        let serving = pair.serve();
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(codec::request(&request).unwrap().as_ref()).await.unwrap();
        send.finish().unwrap();
        let image = super::read(&mut recv).await.unwrap();
        let mut expected = vec![2];
        expected.extend_from_slice(&size.0.to_le_bytes());
        assert_eq!(image.0, expected);
        assert!(matches!(codec::decode(&request, IndexKind::Dialogue, &image), Err(StreamError::Oversize(actual)) if actual == size));
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        assert_eq!(serving.await.unwrap(), super::Served(1));
    });
}

#[test]
fn an_unheld_digest_is_answered_unheld()
{
    testing::runtime().block_on(async {
        let pair = Pair::new().await;
        let tree = RecordTree::build(&[RecordRef::new(b"key", b"value")], TreeParams::current()).unwrap();
        let index = Index::new(IndexKind::Dialogue, tree);
        let store = Store::open(&StateDir::from(pair.holder_root.path().to_path_buf()));
        let digest = store.keep(&index).unwrap();
        let request = Request { digest, query: Query::Key(b"key".as_slice().into()) };
        let serving = pair.serve();
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        let answer = super::ask(&connection, &request, IndexKind::Dialogue).await.unwrap();
        assert_eq!(answer.verify(digest, IndexKind::Dialogue, &request.query).unwrap(), Verified::Present(b"value".as_slice().into()));
        let missing = IndexDigest::from([0xff; 32]);
        let request = Request { digest: missing, query: request.query };
        assert!(matches!(super::ask(&connection, &request, IndexKind::Dialogue).await, Err(StreamError::Unheld(actual)) if actual == missing));
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(codec::request(&request).unwrap().as_ref()).await.unwrap();
        send.finish().unwrap();
        assert_eq!(super::read(&mut recv).await.unwrap().0, [0]);
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        assert_eq!(serving.await.unwrap(), super::Served(3));
    });
}
