//! Real local connections exercise both holder and reader framing boundaries.

use alloc::sync::Arc;

use domhringr_record_tree::BindPort;
use domhringr_record_tree::Endpoint;
use domhringr_record_tree::Identity;
use domhringr_record_tree::Incoming;
use domhringr_record_tree::Node;
use domhringr_record_tree::Peer;
use domhringr_record_tree::StateDir;
use gandr_storage_records::NodeHash;
use gandr_storage_schema::Answer;
use gandr_storage_schema::AttributeValue;
use gandr_storage_schema::PartKey;
use gandr_storage_schema::Question;
use gandr_storage_schema::Row;
use gandr_storage_schema::StoreRoot;
use quenchant_arith::arith;
use quenchant_arith::arith::Int;

use super::ANSWER_CAP;
use super::ByteSize;
use super::Cache;
use super::PROTOCOL;
use super::Remote;
use super::Request;
use super::StreamError;
use super::codec;
use crate::WireImage;
use crate::keyed;
use crate::keyed::Keyed;
use crate::keyed::Standing;
use crate::prove::Ask as _;
use crate::prove::ProveError;
use crate::store::Store;
use crate::testing;

/// A store of one task named `name`, kept in `files`.
///
/// # Specification
/// trivial.
fn one_task(
    files: &Store,
    name: AttributeValue,
) -> (gandr_storage_schema::Store, PartKey)
{
    let keyed = Keyed::shared().unwrap();
    let mut store = keyed.store().unwrap();
    let task = store
        .add_part(
            keyed.task,
            &Row::new()
                .value(keyed.task_name, name)
                .value(keyed.task_standing, Standing::Unheld.value())
                .value(keyed.task_heads, AttributeValue::from(Vec::new())),
        )
        .unwrap();
    let _root = files.keep(&mut store).unwrap();
    (store, task)
}

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
        .with_relay(domhringr_record_tree::Relay::Off)
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
        let keyed = Keyed::shared().unwrap();
        let files = Store::open(&StateDir::from(pair.holder_root.path().to_path_buf()));
        let (store, task) = one_task(&files, AttributeValue::from(vec![0x7b; 0x0011_0000]));
        let question = Question::Value {
            attribute: keyed.task_name,
            part: task,
        };
        let image = store.prove(&question).unwrap().encode();
        let length = u64::try_from(image.as_ref().len()).unwrap();
        let size = ByteSize(u64::from(
            arith::checked_add(Int::from(length), Int::from(1_u64)).unwrap(),
        ));
        assert!(size > ANSWER_CAP);
        let serving = pair.serve();
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        let request = Request::Question {
            root: store.root(),
            question: question.clone(),
        };
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(codec::request(&request).unwrap().as_ref())
            .await
            .unwrap();
        send.finish().unwrap();
        let image = super::read(&mut recv).await.unwrap();
        let mut expected = vec![2];
        expected.extend_from_slice(&size.0.to_le_bytes());
        assert_eq!(image.0, expected);
        let mut remote = Remote {
            connection: &connection,
            root: store.root(),
        };
        assert!(matches!(
            remote.ask(&question).await,
            Err(ProveError::Stream(StreamError::Oversize(actual))) if actual == size
        ));
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        assert_eq!(serving.await.unwrap(), super::Served(2));
    });
}

#[test]
fn an_unheld_root_is_answered_unheld()
{
    testing::runtime().block_on(async {
        let pair = Pair::new().await;
        let keyed = Keyed::shared().unwrap();
        let files = Store::open(&StateDir::from(pair.holder_root.path().to_path_buf()));
        let (store, task) = one_task(&files, keyed::text(keyed::Text("task")));
        let question = Question::Value {
            attribute: keyed.task_name,
            part: task,
        };
        let serving = pair.serve();
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        let mut remote = Remote {
            connection: &connection,
            root: store.root(),
        };
        assert_eq!(
            remote.ask(&question).await.unwrap(),
            Answer::Value(keyed::text(keyed::Text("task")))
        );
        let missing = StoreRoot::from([0xff; 32]);
        let mut unheld = Remote {
            connection: &connection,
            root: missing,
        };
        assert!(matches!(
            unheld.ask(&question).await,
            Err(ProveError::Stream(StreamError::Unheld(actual))) if actual == missing
        ));
        let request = Request::Manifest(missing);
        let (mut send, mut recv) = connection.open_bi().await.unwrap();
        send.write_all(codec::request(&request).unwrap().as_ref())
            .await
            .unwrap();
        send.finish().unwrap();
        assert_eq!(super::read(&mut recv).await.unwrap().0, [0]);
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        assert_eq!(serving.await.unwrap(), super::Served(3));
    });
}

#[test]
fn a_fetched_store_is_the_served_one()
{
    testing::runtime().block_on(async {
        let pair = Pair::new().await;
        let files = Store::open(&StateDir::from(pair.holder_root.path().to_path_buf()));
        let names: Vec<_> = (0 .. 512_u32)
            .map(|index| format!("task-{index}"))
            .collect();
        let keyed = Keyed::shared().unwrap();
        let mut store = keyed.store().unwrap();
        for name in &names {
            let _task = store
                .add_part(
                    keyed.task,
                    &Row::new()
                        .value(keyed.task_name, keyed::text(keyed::Text(name)))
                        .value(keyed.task_standing, Standing::Unheld.value())
                        .value(keyed.task_heads, AttributeValue::from(Vec::new())),
                )
                .unwrap();
        }
        let root = files.keep(&mut store).unwrap();
        let serving = pair.serve();
        let connection = pair.reader.open(&pair.at, PROTOCOL).await.unwrap();
        let reader_root = tempfile::tempdir().unwrap();
        let reader = Store::open(&StateDir::from(reader_root.path().to_path_buf()));
        let fetched = super::fetch(&connection, &reader, root).await.unwrap();
        assert_eq!(fetched, store);
        // Held now, the store loads without asking.
        assert_eq!(reader.load(keyed, root).unwrap(), store);
        assert!(matches!(
            super::fetch(&connection, &reader, StoreRoot::from([0xff; 32])).await,
            Err(StreamError::Unheld(_))
        ));
        connection.close(iroh::endpoint::VarInt::from_u32(0), b"checked");
        drop(pair);
        let served = serving.await.unwrap();
        assert!(served.0 > 2, "{served:?}");
    });
}

#[test]
fn every_question_round_trips_through_its_request()
{
    let keyed = Keyed::shared().unwrap();
    let root = StoreRoot::from([3; 32]);
    let part = PartKey::from(0x0102_0304_0506_0708_u64);
    let questions = [
        Question::Part {
            object: keyed.naming,
            part,
        },
        Question::Arrow {
            arrow: keyed.naming_task,
            part,
        },
        Question::Value {
            attribute: keyed.move_receipt,
            part,
        },
        Question::Preimage {
            arrow: keyed.move_attempt,
            target: part,
        },
        Question::ValuePreimage {
            attribute: keyed.subject_digest,
            value: AttributeValue::from(vec![2; 33]),
        },
    ];
    let mut requests: Vec<_> = questions
        .into_iter()
        .map(|question| Request::Question { root, question })
        .collect();
    requests.push(Request::Manifest(root));
    requests.push(Request::Node {
        root,
        node: NodeHash::from([4; 32]),
    });
    for request in requests {
        let mut image = codec::request(&request).unwrap();
        assert_eq!(codec::read_request(&image, keyed).unwrap(), request);
        image.0.push(0);
        assert_eq!(
            codec::read_request(&image, keyed),
            Err(crate::WireError::Trailing)
        );
        let _trailing = image.0.pop();
        let _last = image.0.pop();
        assert_eq!(
            codec::read_request(&image, keyed),
            Err(crate::WireError::Truncated)
        );
    }
    // An ordinal past the schema names no element.
    let mut image = WireImage(vec![1]);
    image.0.extend_from_slice(root.as_ref());
    image.0.push(3);
    image.0.extend_from_slice(&u64::MAX.to_le_bytes());
    image.0.extend_from_slice(&0_u64.to_le_bytes());
    assert_eq!(
        codec::read_request(&image, keyed),
        Err(crate::WireError::Tag)
    );
}
