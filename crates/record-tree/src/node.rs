//! A peer bound to an iroh endpoint: reached by endpoint id, accepting
//! connections, and dialing other peers to sync a tree.
//!
//! The endpoint uses n0's preset (relay, DNS address publishing and lookup)
//! plus mDNS address lookup, so a peer is reached by its endpoint id alone:
//! on the LAN through mDNS and direct addresses, across networks through the
//! relay and DNS. Each connection reports the network path iroh selected for
//! it ([`SelectedPath`]).

use core::convert::Infallible;
use core::fmt;
use core::net::Ipv4Addr;
use core::net::Ipv6Addr;
use core::net::SocketAddr;
use core::net::SocketAddrV4;
use core::net::SocketAddrV6;
use core::num::NonZeroU16;
use core::str::FromStr;
use core::time::Duration;

use futures::StreamExt as _;
use subduction_core::connection::managed::CallError;
use subduction_core::connection::message::SyncMessage;
use subduction_core::handshake::MAX_PLAUSIBLE_DRIFT;
use subduction_core::handshake::audience::Audience;
use subduction_core::subduction::error::AddConnectionError;
use subduction_core::subduction::error::IoError;
use subduction_core::timeout::call::CallTimeout;
use subduction_core::transport::message::MessageTransport;
use subduction_iroh::error::DisconnectionError;
use subduction_iroh::error::SendError;
use subduction_redb_storage::RedbStorage;

use crate::id::EndpointKey;
use crate::id::PeerKey;
use crate::id::RemotePeer;
use crate::id::TreeId;
use crate::store::Heads;
use crate::store::HeadsError;
use crate::store::Peer;
use crate::store::Transport;

/// A failed exchange during a sync, as subduction reports it for this engine.
type EngineIoError = IoError<future_form::Sendable, RedbStorage, Transport, SyncMessage>;

/// How long a dialer gives iroh, from the start of its sync round, to select
/// a direct path before it reports whatever path is selected.
const SETTLE: Duration = Duration::from_secs(2);

impl Peer
{
    /// Bind the peer to an iroh endpoint under its endpoint key, its UDP
    /// sockets on `port`.
    ///
    /// # Specification
    /// - ensures: the returned node's endpoint id is the identity's endpoint
    ///   key; the endpoint accepts subduction's ALPN and publishes and looks up
    ///   addresses through n0's DNS and through mDNS.
    /// - ensures: with [`BindPort::Fixed`] the endpoint's IPv4 socket is bound
    ///   on every interface at that port, and its IPv6 socket too where the
    ///   host has IPv6; with [`BindPort::Ephemeral`] the system picks the
    ///   ports.
    /// - fails: [`BindError::Endpoint`] when the endpoint cannot bind its
    ///   sockets, the IPv4 port among them (in use, or not permitted), or start
    ///   its address lookups; [`BindError::Address`] when iroh refuses the
    ///   socket addresses.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`BindError::Address`]: iroh refuses a socket address.
    /// - [`BindError::Endpoint`]: iroh refuses the bind.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two peers bound in one process reach each other by
    ///   endpoint id alone, which needs the key, the ALPN and the lookup; a
    ///   peer bound to a fixed port reports a socket on it.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_fixed_port_is_the_bound_port`
    #[inline]
    pub async fn bind(
        self,
        port: BindPort,
    ) -> Result<Node, BindError>
    {
        let builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(self.identity().endpoint_secret().clone())
            .alpns(vec![subduction_iroh::ALPN.to_vec()])
            .address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder());
        let builder = match port {
            | BindPort::Ephemeral => Ok(builder),
            | BindPort::Fixed(port) => port.sockets(builder),
        };
        let builder = builder.map_err(BindError::Address)?;
        let endpoint = builder.bind().await.map_err(BindError::Endpoint)?;
        Ok(Node {
            peer: self,
            endpoint,
        })
    }
}

/// A UDP port a peer's endpoint binds, never zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct UdpPort(NonZeroU16);

impl UdpPort
{
    /// Ask `builder` for its IPv4 and IPv6 sockets on this port, on every
    /// interface.
    ///
    /// # Specification
    /// - ensures: the IPv4 socket is required, as iroh's own default is; the
    ///   IPv6 socket is not, so a host without IPv6 still binds.
    /// - fails: iroh's [`InvalidSocketAddr`] when it refuses an address.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`InvalidSocketAddr`]: iroh refuses a socket address.
    ///
    /// [`InvalidSocketAddr`]: iroh::endpoint::InvalidSocketAddr
    fn sockets(
        self,
        builder: iroh::endpoint::Builder,
    ) -> Result<iroh::endpoint::Builder, iroh::endpoint::InvalidSocketAddr>
    {
        let port = self.0.get();
        let builder = builder.bind_addr_with_opts(
            SocketAddrV4::new(Ipv4Addr::UNSPECIFIED, port),
            iroh::endpoint::BindOpts::default(),
        )?;
        builder.bind_addr_with_opts(
            SocketAddrV6::new(Ipv6Addr::UNSPECIFIED, port, 0, 0),
            iroh::endpoint::BindOpts::default().set_is_required(false),
        )
    }
}

impl FromStr for UdpPort
{
    type Err = ParsePortError;

    /// Read a port from its decimal text.
    ///
    /// # Specification
    /// - ensures: accepts the decimal numbers 1 through 65535.
    /// - fails: [`ParsePortError`] for zero, a number out of range, or text
    ///   that is not a decimal number.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParsePortError`]: the text is not a port from 1 through 65535.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the boundaries 0, 1, 65535 and 65536 and a word
    ///   separate acceptance from refusal, and a round trip through `Display`
    ///   pins the value.
    /// - witness: `node::tests::a_port_is_one_through_65535`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        text.parse::<NonZeroU16>().map(Self).map_err(ParsePortError)
    }
}

impl fmt::Display for UdpPort
{
    /// Write the port in decimal.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        fmt::Display::fmt(&self.0, f)
    }
}

/// Where a peer's endpoint binds its UDP sockets.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BindPort
{
    /// Ports the system picks.
    Ephemeral,
    /// This port, so a firewall rule can name it.
    Fixed(UdpPort),
}

/// The network path iroh selected for a connection's application data.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SelectedPath
{
    /// A direct UDP path to this remote address.
    Direct(SocketAddr),
    /// A path through this relay server.
    Relay(iroh::RelayUrl),
    /// A path over a transport iroh adds beyond IP and relays.
    Other(iroh::TransportAddr),
    /// No path is selected yet.
    Pending,
}

impl SelectedPath
{
    /// The path `connection` has selected now.
    ///
    /// # Specification
    /// - ensures: as [`SelectedPath::among`] over the connection's open paths
    ///   now.
    /// - panics: none.
    fn of(connection: &iroh::endpoint::Connection) -> Self
    {
        Self::among(&connection.paths())
    }

    /// The path selected among `paths`.
    ///
    /// # Specification
    /// - ensures: the remote address of the path iroh marks selected, or
    ///   [`SelectedPath::Pending`] when none is.
    /// - panics: none.
    fn among(paths: &iroh::endpoint::PathList<'_>) -> Self
    {
        let selected = paths
            .iter()
            .find(iroh::endpoint::Path::is_selected)
            .map(|path| path.remote_addr().clone());
        match selected {
            | None => Self::Pending,
            | Some(iroh::TransportAddr::Ip(address)) => Self::Direct(address),
            | Some(iroh::TransportAddr::Relay(url)) => Self::Relay(url),
            | Some(other) => Self::Other(other),
        }
    }

    /// Wait until iroh selects a direct path for `connection`, the connection
    /// closes, or [`SETTLE`] elapses, whichever comes first.
    ///
    /// # Specification
    /// - ensures: returns at the first snapshot of `connection`'s paths with a
    ///   direct path selected, when the snapshots end because the connection
    ///   closed, or once [`SETTLE`] has elapsed.
    /// - panics: none.
    /// - intension: a connection dialed by endpoint id can open over a relay
    ///   before address lookup finds the peer's direct addresses; iroh then
    ///   holepunches and moves to a direct path. The wait lets a short sync
    ///   report the path the connection settles on rather than the first one it
    ///   opened.
    async fn settle(connection: &iroh::endpoint::Connection)
    {
        let direct = async {
            let mut snapshots = connection.paths_stream();
            while let Some(paths) = snapshots.next().await {
                if matches!(Self::among(&paths), Self::Direct(_)) {
                    break;
                }
            }
        };
        let _settled = tokio::time::timeout(SETTLE, direct).await;
    }
}

impl fmt::Display for SelectedPath
{
    /// Write the path as `direct <addr>`, `relay <url>`, `other <addr>` or
    /// `pending`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Direct(address) => write!(f, "direct {address}"),
            | Self::Relay(ref url) => write!(f, "relay {url}"),
            | Self::Other(ref address) => write!(f, "other {address}"),
            | Self::Pending => f.write_str("pending"),
        }
    }
}

/// A peer admitted by [`Node::accept`], and the path its connection took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Accepted
{
    /// The admitted peer's id.
    peer: PeerKey,
    /// The path selected once the handshake completed.
    path: SelectedPath,
}

impl Accepted
{
    /// The admitted peer's id.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn peer(&self) -> PeerKey
    {
        self.peer
    }

    /// The path selected once the handshake completed.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn path(&self) -> &SelectedPath
    {
        &self.path
    }
}

/// The outcome of [`Node::sync`]: this peer's heads after it, and the path
/// the sync took.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Synced
{
    /// This peer's heads for the tree after the sync.
    heads: Heads,
    /// The path selected when the sync round ended.
    path: SelectedPath,
}

impl Synced
{
    /// This peer's heads for the tree after the sync.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn heads(&self) -> &Heads
    {
        &self.heads
    }

    /// The path selected when the sync round ended.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn path(&self) -> &SelectedPath
    {
        &self.path
    }
}

/// A peer bound to an iroh endpoint.
///
/// Concurrency: each connection's reader and writer tasks run detached on the
/// peer's runtime and end when the connection closes; [`Node::close`] closes
/// every connection and stops the engine.
pub struct Node
{
    /// The peer and its tree store.
    peer: Peer,
    /// The bound endpoint.
    endpoint: iroh::Endpoint,
}

impl Node
{
    /// The peer and its tree store.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn peer(&self) -> &Peer
    {
        &self.peer
    }

    /// The endpoint id this node is dialed by.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub fn endpoint_key(&self) -> EndpointKey
    {
        EndpointKey::new(self.endpoint.id())
    }

    /// Accept the next incoming connection and admit its peer.
    ///
    /// # Specification
    /// - ensures: on success the remote peer has passed the subduction
    ///   handshake addressed to this peer's identity, its connection is
    ///   registered with the engine, and the engine answers its sync requests;
    ///   returns the remote's peer id and the path iroh selected for the
    ///   connection when the handshake completed.
    /// - fails: [`AcceptError::Closed`] once the endpoint is closed: no
    ///   connection will arrive again. [`AcceptError::Handshake`] for a
    ///   connection that fails the QUIC or subduction handshake, and
    ///   [`AcceptError::Register`] for one the engine cannot take; after
    ///   either, the next call accepts the next connection.
    /// - panics: none.
    /// - intension: handshakes run one at a time, in arrival order.
    ///
    /// # Errors
    /// - [`AcceptError::Closed`]: the endpoint is closed.
    /// - [`AcceptError::Handshake`]: the connection failed its handshake.
    /// - [`AcceptError::Register`]: the engine refused the connection.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a dialer that names this peer is accepted and synced,
    ///   and a dialer that names another peer id is refused, so the handshake's
    ///   audience check is observed from both sides; the accepted peer and a
    ///   selected path are read back.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    #[inline]
    pub async fn accept(&self) -> Result<Accepted, AcceptError>
    {
        // economy: `accept_one` couples the QUIC accept with the handshake, so
        // a slow handshake holds up the connections behind it. Split the two
        // and run handshakes concurrently once subduction_iroh exposes them
        // apart.
        let accepted = subduction_iroh::server::accept_one(
            &self.endpoint,
            self.peer.identity().signer(),
            self.peer.engine().nonce_cache(),
            self.peer.engine().peer_id(),
            None,
            MAX_PLAUSIBLE_DRIFT,
        )
        .await;
        let accepted = match accepted {
            | Ok(accepted) => accepted,
            | Err(subduction_iroh::error::AcceptError::NoIncoming) => {
                return Err(AcceptError::Closed);
            },
            | Err(failure) => return Err(AcceptError::Handshake(failure)),
        };
        drop(self.peer.runtime().spawn(accepted.listener_task));
        drop(self.peer.runtime().spawn(accepted.sender_task));
        let path = SelectedPath::of(accepted.authenticated.inner().quic_connection());
        let connection = accepted.authenticated.map(MessageTransport::new);
        self.peer
            .engine()
            .add_connection(connection)
            .await
            .map_err(AcceptError::Register)?;
        Ok(Accepted {
            peer: PeerKey::new(accepted.peer_id),
            path,
        })
    }

    /// Dial `remote` by endpoint id, batch-sync `tree` with it, and
    /// disconnect.
    ///
    /// # Specification
    /// - ensures: on success the remote proved it holds `remote`'s peer key;
    ///   every commit the remote held for `tree` when it answered is durable in
    ///   this peer's store; the connection is closed; returns this peer's heads
    ///   for `tree` after the sync, so a dialer holding nothing the remote
    ///   lacks reports exactly the remote's heads, and the path iroh had
    ///   selected for the connection once both the sync round ended and the
    ///   connection had settled ([`SelectedPath::settle`]): a direct path, or
    ///   whatever is selected [`SETTLE`] after the round starts.
    /// - ensures: a round that ends with a direct path selected waits for
    ///   nothing more; a connection still on a relay holds the sync open until
    ///   [`SETTLE`] after the round starts at most.
    /// - ensures: commits the remote asks this peer for are queued to it before
    ///   the disconnect, best effort: their delivery is not awaited.
    /// - fails: [`SyncError::Connect`] when the remote cannot be reached or
    ///   fails the handshake, [`SyncError::Register`] when the engine refuses
    ///   the connection, [`SyncError::Exchange`] and [`SyncError::Call`] when
    ///   the sync round fails, [`SyncError::Refused`] when the remote answers
    ///   without a diff, [`SyncError::Disconnect`] when closing fails, and
    ///   [`SyncError::Heads`] when the heads cannot be read back. The
    ///   connection is closed after a failed round as after a good one.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Connect`]: dialing or the handshake fails.
    /// - [`SyncError::Register`]: the engine refuses the connection.
    /// - [`SyncError::Exchange`]: storage or the connection fails mid-sync.
    /// - [`SyncError::Call`]: the sync request gets no answer.
    /// - [`SyncError::Refused`]: the remote answers without a diff.
    /// - [`SyncError::Disconnect`]: the connection cannot be closed.
    /// - [`SyncError::Heads`]: the heads cannot be read back.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two peers holding divergent commits on one tree: the
    ///   dialer's heads after the sync are compared exactly with the union of
    ///   both frontiers, which a pull that dropped either side, or one that
    ///   skipped storage, would not produce; a dial naming the wrong peer key
    ///   is refused as a connect failure; the dialer reports a selected path.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    #[inline]
    pub async fn sync(
        &self,
        remote: &RemotePeer,
        tree: TreeId,
    ) -> Result<Synced, SyncError>
    {
        let peer = remote.peer().peer_id();
        let address = iroh::EndpointAddr::from(remote.endpoint().endpoint_id());
        let connected = subduction_iroh::client::connect(
            &self.endpoint,
            address,
            self.peer.identity().signer(),
            Audience::known(peer),
        )
        .await
        .map_err(SyncError::Connect)?;
        drop(self.peer.runtime().spawn(connected.listener_task));
        drop(self.peer.runtime().spawn(connected.sender_task));
        let quic = connected.authenticated.inner().quic_connection().clone();
        let connection = connected.authenticated.map(MessageTransport::new);
        self.peer
            .engine()
            .add_connection(connection)
            .await
            .map_err(SyncError::Register)?;
        let round = self.peer.engine().sync_with_peer(
            &peer,
            tree.sedimentree(),
            false,
            CallTimeout::Default,
        );
        let (round, ()) = futures::future::join(round, SelectedPath::settle(&quic)).await;
        let path = SelectedPath::of(&quic);
        let disconnected = self.peer.engine().disconnect_from_peer(&peer).await;
        let (answered, _statistics, failures) = round.map_err(SyncError::Exchange)?;
        if !answered {
            let failure = failures.into_iter().next();
            return Err(match failure {
                | Some((_connection, failure)) => SyncError::Call(failure),
                | None => SyncError::Refused,
            });
        }
        let _was_connected = disconnected.map_err(SyncError::Disconnect)?;
        let heads = self.peer.heads(tree).await.map_err(SyncError::Heads)?;
        Ok(Synced { heads, path })
    }

    /// Close every connection and the endpoint, and stop the engine.
    ///
    /// # Specification
    /// - ensures: on return the endpoint is closed, so a pending
    ///   [`Node::accept`] fails with [`AcceptError::Closed`], and the engine's
    ///   background tasks have been told to stop.
    /// - panics: none.
    #[inline]
    pub async fn close(&self)
    {
        self.peer.engine().shutdown();
        self.endpoint.close().await;
    }
}

/// Why a peer cannot bind its endpoint.
#[derive(Debug, thiserror::Error)]
pub enum BindError
{
    /// Iroh refuses a socket address.
    #[error("iroh refuses the socket address")]
    Address(#[source] iroh::endpoint::InvalidSocketAddr),
    /// Iroh refuses the bind.
    #[error("cannot bind the iroh endpoint")]
    Endpoint(#[source] iroh::endpoint::BindError),
}

/// Why a text is not a UDP port.
#[derive(Debug, thiserror::Error)]
#[error("a port is a decimal number from 1 through 65535")]
#[repr(transparent)]
pub struct ParsePortError(#[source] core::num::ParseIntError);

/// Why an incoming connection was not admitted.
#[derive(Debug, thiserror::Error)]
pub enum AcceptError
{
    /// The endpoint is closed; no connection will arrive again.
    #[error("the endpoint is closed")]
    Closed,
    /// The connection failed its QUIC or subduction handshake.
    #[error("an incoming connection failed its handshake")]
    Handshake(#[source] subduction_iroh::error::AcceptError),
    /// The engine refused the connection.
    #[error("the engine refused an incoming connection")]
    Register(#[source] AddConnectionError<Infallible>),
}

/// Why a sync with a remote peer failed.
#[derive(Debug, thiserror::Error)]
pub enum SyncError
{
    /// The remote cannot be reached or fails the handshake.
    #[error("cannot connect to the remote peer")]
    Connect(#[source] subduction_iroh::error::ConnectError),
    /// The engine refuses the connection.
    #[error("the engine refused the connection")]
    Register(#[source] AddConnectionError<Infallible>),
    /// Storage or the connection fails mid-sync.
    #[error("the sync exchange failed")]
    Exchange(#[source] EngineIoError),
    /// The sync request gets no answer.
    #[error("the remote peer did not answer the sync request")]
    Call(#[source] CallError<SendError>),
    /// The remote answers without a diff: it refuses the tree.
    #[error("the remote peer refused to sync the tree")]
    Refused,
    /// The connection cannot be closed.
    #[error("cannot close the connection")]
    Disconnect(#[source] DisconnectionError),
    /// The heads cannot be read back.
    #[error("cannot read the heads after the sync")]
    Heads(#[source] HeadsError),
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::sync::Arc;

    use sedimentree_core::loose_commit::id::CommitId;

    use super::AcceptError;
    use super::BindPort;
    use super::Node;
    use super::SelectedPath;
    use super::SyncError;
    use super::UdpPort;
    use crate::id::RemotePeer;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;
    use crate::receipt::Receipt;
    use crate::store::Peer;
    use crate::testing::runtime;

    /// The tree both peers commit to.
    const TREE: &str = "6e6f64656e6f64656e6f64656e6f64656e6f64656e6f64656e6f64656e6f6465";

    /// Open and bind a peer on a fresh state directory beneath `root`.
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
            .bind(port)
            .await
            .unwrap()
    }

    /// Accept connections on `node` until its endpoint closes.
    ///
    /// # Specification
    /// trivial.
    fn serve(node: &Arc<Node>)
    {
        let node = Arc::clone(node);
        drop(tokio::spawn(async move {
            loop {
                match node.accept().await {
                    | Err(AcceptError::Closed) => break,
                    | Ok(_) | Err(_) => {},
                }
            }
        }));
    }

    /// Commit a note of `text` to `tree` on `node`.
    ///
    /// # Specification
    /// trivial.
    async fn commit(
        node: &Node,
        tree: TreeId,
        text: String,
    ) -> CommitId
    {
        let receipt = Receipt::note(tree, text).unwrap();
        node.peer().commit(tree, receipt).await.unwrap()
    }

    #[test]
    fn a_dialer_takes_the_union_of_both_frontiers()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = TREE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a, BindPort::Ephemeral).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            serve(&a);
            commit(&a, tree, "a1".into()).await;
            let a2 = commit(&a, tree, "a2".into()).await;
            let b1 = commit(&b, tree, "b1".into()).await;
            let remote = RemotePeer::new(a.endpoint_key(), a.peer().identity().peer_key());
            let synced = b.sync(&remote, tree).await.unwrap();
            let mut expected = vec![a2, b1];
            expected.sort();
            assert_eq!(
                synced.heads().iter().copied().collect::<Vec<_>>(),
                expected,
                "the dialer holds both frontiers"
            );
            let stored = b.peer().heads(tree).await.unwrap();
            assert_eq!(
                &stored,
                synced.heads(),
                "the synced commits are in the dialer's store"
            );
            assert_ne!(
                synced.path(),
                &SelectedPath::Pending,
                "a connection that carried a sync round has a selected path"
            );
            b.close().await;
            drop(b);
            a.close().await;
            drop(a);
        });
    }

    #[test]
    fn a_dialer_naming_another_peer_is_refused()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = TREE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a, BindPort::Ephemeral).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            serve(&a);
            commit(&a, tree, "a1".into()).await;
            let impostor = b.peer().identity().peer_key();
            let remote = RemotePeer::new(a.endpoint_key(), impostor);
            let refused = b.sync(&remote, tree).await;
            assert!(
                matches!(refused, Err(SyncError::Connect(_))),
                "the handshake refuses the wrong peer key"
            );
            assert_eq!(
                b.peer().heads(tree).await.unwrap().iter().count(),
                0,
                "nothing was synced"
            );
            b.close().await;
            drop(b);
            a.close().await;
            drop(a);
        });
    }

    #[test]
    fn a_fixed_port_is_the_bound_port()
    {
        let root = tempfile::tempdir().unwrap();
        let free = std::net::UdpSocket::bind("0.0.0.0:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let port = free.to_string().parse::<UdpPort>().unwrap();
        runtime().block_on(async {
            let node = bound(&root, BindPort::Fixed(port)).await;
            assert!(
                node.endpoint
                    .bound_sockets()
                    .iter()
                    .any(|socket| socket.is_ipv4() && socket.port() == free),
                "the IPv4 socket is bound on the fixed port: {:?}",
                node.endpoint.bound_sockets()
            );
            node.close().await;
            drop(node);
        });
    }

    #[test]
    fn a_port_is_one_through_65535()
    {
        for text in ["1", "49731", "65535"] {
            assert_eq!(
                text.parse::<UdpPort>().unwrap().to_string(),
                text,
                "a port round-trips through its decimal text"
            );
        }
        for text in ["0", "65536", "-1", "port", ""] {
            assert!(text.parse::<UdpPort>().is_err(), "{text:?} is not a port");
        }
    }
}
