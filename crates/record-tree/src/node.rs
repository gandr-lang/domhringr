//! A peer bound to an iroh endpoint: reached by endpoint id, accepting
//! connections, presenting its endpoint in a tree, and dialing other peers to
//! sync a tree.
//!
//! The endpoint uses n0's preset (relay, DNS address publishing and lookup)
//! plus mDNS address lookup, so a peer is reached by its endpoint id alone:
//! on the LAN through mDNS and direct addresses, across networks through the
//! relay and DNS. A dialer that knows the remote's addresses — from a
//! presence in the tree's book, or named by hand — names them in the dial
//! ([`Endpoint`]) and does not wait on the lookups. Each connection reports
//! the network path iroh selected for it ([`SelectedPath`]).
//!
//! Beside subduction, an endpoint accepts the application protocols it is
//! bound with ([`Protocol`]): an accepted connection is a peer admitted to
//! sync, or a connection under one of those protocols for its caller to
//! serve ([`Incoming`]). A link to a peer ([`Node::connect`]) stays up until
//! [`Node::disconnect`], so either side pulls a tree over it
//! ([`Node::pull`]) while another protocol runs beside it ([`Node::open`]).

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

use future_form::Sendable;
use futures::StreamExt as _;
use sedimentree_core::loose_commit::id::CommitId;
use subduction_core::connection::managed::CallError;
use subduction_core::connection::message::SyncMessage;
use subduction_core::handshake;
use subduction_core::handshake::MAX_PLAUSIBLE_DRIFT;
use subduction_core::handshake::audience::Audience;
use subduction_core::subduction::error::AddConnectionError;
use subduction_core::subduction::error::IoError;
use subduction_core::timeout::call::CallTimeout;
use subduction_core::timestamp::TimestampSeconds;
use subduction_core::transport::message::MessageTransport;
use subduction_iroh::error::DisconnectionError;
use subduction_iroh::error::SendError;
use subduction_iroh::handshake::IrohHandshake;
use subduction_iroh::transport::IrohTransport;
use subduction_redb_storage::RedbStorage;

use crate::id::Endpoint;
use crate::id::EndpointKey;
use crate::id::PeerKey;
use crate::id::RemotePeer;
use crate::id::TreeId;
use crate::receipt::EndpointProof;
use crate::receipt::RandomError;
use crate::receipt::Receipt;
use crate::store::CommitError;
use crate::store::Heads;
use crate::store::HeadsError;
use crate::store::Peer;
use crate::store::Transport;

/// A failed exchange during a sync, as subduction reports it for this engine.
type EngineIoError = IoError<future_form::Sendable, RedbStorage, Transport, SyncMessage>;

/// How long a dialer gives iroh, from the start of its sync round, to select
/// a direct path before it reports whatever path is selected. Between two
/// peers on one host, iroh as published moved a relayed connection to a direct
/// path about two seconds into the round, and in some dials not at all; five
/// seconds covers the first without holding the second open long.
const SETTLE: Duration = Duration::from_secs(5);

/// How long a peer presenting its endpoint waits for it to reach its home
/// relay before it reads the endpoint's addresses. Right after binding,
/// iroh as published names the local interface addresses alone; once the
/// endpoint reaches a relay, about half a second in, it adds the relay and
/// the address the relay saw. An endpoint that reaches no relay — offline,
/// or the relay blocked — is presented at what it has once this elapses.
const ONLINE: Duration = Duration::from_secs(5);

impl Peer
{
    /// Bind the peer to an iroh endpoint under its endpoint key, its UDP
    /// sockets on `port`, accepting `protocols` beside subduction's.
    ///
    /// # Specification
    /// - ensures: the returned node's endpoint id is the identity's endpoint
    ///   key; the endpoint accepts subduction's ALPN and each of `protocols`',
    ///   and publishes and looks up addresses through n0's DNS and through
    ///   mDNS.
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
    ///   peer bound with a protocol accepts a connection under it; a peer bound
    ///   to a fixed port reports a socket on it.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_linked_peer_pulls_beside_another_protocol`
    /// - witness: `node::tests::a_fixed_port_is_the_bound_port`
    #[inline]
    pub async fn bind(
        self,
        port: BindPort,
        protocols: &[Protocol],
    ) -> Result<Node, BindError>
    {
        let alpns = core::iter::once(subduction_iroh::ALPN)
            .chain(protocols.iter().map(|protocol| protocol.0))
            .map(<[u8]>::to_vec)
            .collect();
        let builder = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(self.identity().endpoint_secret().clone())
            .alpns(alpns)
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
            protocols: protocols.to_vec(),
        })
    }
}

/// An application protocol a node accepts beside subduction's: the ALPN a
/// connection names it by, the wrapper's one field, so a protocol is a
/// constant: `Protocol(b"name/0")`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Protocol(pub &'static [u8]);

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

/// A connection [`Node::accept`] took.
#[derive(Debug)]
pub enum Incoming
{
    /// A peer admitted to sync.
    Peer(Accepted),
    /// A connection under another protocol the node accepts, past QUIC's
    /// handshake alone: its caller serves it.
    Protocol
    {
        /// The protocol the connection names.
        protocol: Protocol,
        /// The connection.
        connection: iroh::endpoint::Connection,
    },
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
    /// The protocols the endpoint accepts beside subduction's.
    protocols: Vec<Protocol>,
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

    /// Accept the next incoming connection: admit its peer, or hand over a
    /// connection under another protocol.
    ///
    /// # Specification
    /// - ensures: for a connection naming subduction's ALPN, on success the
    ///   remote peer has passed the subduction handshake addressed to this
    ///   peer's identity, its connection is registered with the engine, and the
    ///   engine answers its sync requests; returns [`Incoming::Peer`] with the
    ///   remote's peer id and the path iroh selected for the connection when
    ///   the handshake completed. For a connection naming a protocol the node
    ///   was bound with, returns [`Incoming::Protocol`] with the protocol and
    ///   the connection, nothing read from it.
    /// - fails: [`AcceptError::Closed`] once the endpoint is closed: no
    ///   connection will arrive again. [`AcceptError::Handshake`] for a
    ///   connection that fails the QUIC or subduction handshake,
    ///   [`AcceptError::Register`] for one the engine cannot take, and
    ///   [`AcceptError::Protocol`] for one naming a protocol the node does not
    ///   accept, which is closed; after any of these, the next call accepts the
    ///   next connection.
    /// - panics: none.
    /// - intension: connections are taken, and subduction handshakes run, one
    ///   at a time in arrival order, so a protocol connection a dialer opens
    ///   once its link ([`Node::connect`]) is up is handed over after the link
    ///   is registered: its caller can pull over the link at once. A slow
    ///   handshake holds up the connections behind it.
    ///
    /// # Errors
    /// - [`AcceptError::Closed`]: the endpoint is closed.
    /// - [`AcceptError::Handshake`]: the connection failed its handshake.
    /// - [`AcceptError::Register`]: the engine refused the connection.
    /// - [`AcceptError::Protocol`]: the connection names no accepted protocol.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a dialer that names this peer is accepted and synced,
    ///   and a dialer that names another peer id is refused, so the handshake's
    ///   audience check is observed from both sides; the accepted peer and a
    ///   selected path are read back; a connection under another protocol is
    ///   handed over after its dialer's link, which the acceptor pulls over.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    /// - witness: `node::tests::a_linked_peer_pulls_beside_another_protocol`
    #[inline]
    pub async fn accept(&self) -> Result<Incoming, AcceptError>
    {
        let incoming = self.endpoint.accept().await.ok_or(AcceptError::Closed)?;
        let connection = incoming.await.map_err(|failure| {
            AcceptError::Handshake(subduction_iroh::error::AcceptError::Connecting(failure))
        })?;
        if connection.alpn() == subduction_iroh::ALPN {
            return self.admit(connection).await.map(Incoming::Peer);
        }
        let accepted = self
            .protocols
            .iter()
            .copied()
            .find(|protocol| protocol.0 == connection.alpn());
        match accepted {
            | Some(protocol) => Ok(Incoming::Protocol {
                protocol,
                connection,
            }),
            | None => {
                connection.close(iroh::endpoint::VarInt::from_u32(0), b"unknown protocol");
                Err(AcceptError::Protocol)
            },
        }
    }

    /// Run the subduction handshake as the responder on `connection` and
    /// register the peer it authenticates.
    ///
    /// # Specification
    /// - ensures: as [`Node::accept`] states for a connection naming
    ///   subduction's ALPN: the bidirectional stream the dialer opens carries
    ///   the handshake and then the connection's messages, whose reader and
    ///   writer tasks run detached on the peer's runtime.
    /// - fails: [`AcceptError::Handshake`] when no stream opens or the
    ///   handshake fails, as when the dialer addresses another peer or its
    ///   clock drifts past [`MAX_PLAUSIBLE_DRIFT`]; [`AcceptError::Register`]
    ///   when the engine refuses the connection.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`AcceptError::Handshake`]: the handshake failed.
    /// - [`AcceptError::Register`]: the engine refused the connection.
    async fn admit(
        &self,
        connection: iroh::endpoint::Connection,
    ) -> Result<Accepted, AcceptError>
    {
        let (send, recv) = connection.accept_bi().await.map_err(|failure| {
            AcceptError::Handshake(subduction_iroh::error::AcceptError::AcceptBi(failure))
        })?;
        let quic = connection.clone();
        let (authenticated, (listener, sender)) = handshake::respond::<Sendable, _, _, _, _>(
            IrohHandshake::new(send, recv),
            move |handshake, peer| {
                let (send, recv) = handshake.into_parts();
                let (transport, outbound) = IrohTransport::new(peer, quic);
                let listener = subduction_iroh::tasks::listener_task(transport.clone(), recv);
                let sender = subduction_iroh::tasks::sender_task(send, outbound);
                (transport, (listener, sender))
            },
            self.peer.identity().signer(),
            self.peer.engine().nonce_cache(),
            self.peer.engine().peer_id(),
            None,
            now(),
            MAX_PLAUSIBLE_DRIFT,
        )
        .await
        .map_err(|failure| {
            AcceptError::Handshake(subduction_iroh::error::AcceptError::Handshake(Box::new(
                failure,
            )))
        })?;
        drop(self.peer.runtime().spawn(listener));
        drop(self.peer.runtime().spawn(sender));
        let path = SelectedPath::of(&connection);
        let peer = PeerKey::new(authenticated.peer_id());
        let registered = authenticated.map(MessageTransport::new);
        self.peer
            .engine()
            .add_connection(registered)
            .await
            .map_err(AcceptError::Register)?;
        Ok(Accepted { peer, path })
    }

    /// Commit this node's endpoint, at its current addresses, as its presence
    /// in `tree`.
    ///
    /// # Specification
    /// - ensures: waits until the endpoint has reached its home relay or
    ///   [`ONLINE`] has elapsed, whichever comes first, then commits to `tree`
    ///   a presence of the endpoint at the addresses iroh then names for it
    ///   ([`Endpoint::of`]), proved by the endpoint key for this peer's key
    ///   ([`EndpointProof::sign`]), under a fresh operation fence; returns the
    ///   commit's id, which is the presence's `since`.
    /// - ensures: the presence is the one [`View::book`] offers for this peer
    ///   once the fold admits it: from the owner or a member, which it is when
    ///   this peer holds the tree's authority.
    /// - fails: [`PresentError::Random`] when no fence can be drawn and
    ///   [`PresentError::Commit`] when the commit cannot be appended.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`PresentError::Random`]: the random source failed.
    /// - [`PresentError::Commit`]: the commit cannot be appended.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a bound peer presents itself in a tree it owns, and
    ///   the book then offers its endpoint id at the presenting commit, with at
    ///   least the address a dial on this host reaches; a second peer dialing
    ///   it through that presence syncs.
    /// - witness: `node::tests::a_peer_reached_through_its_presence_syncs`
    ///
    /// [`View::book`]: crate::fold::View::book
    #[inline]
    pub async fn present(
        &self,
        tree: TreeId,
    ) -> Result<CommitId, PresentError>
    {
        let _online = tokio::time::timeout(ONLINE, self.endpoint.online()).await;
        let endpoint = Endpoint::of(&self.endpoint.addr());
        let identity = self.peer.identity();
        let proof = EndpointProof::sign(identity.endpoint_secret(), identity.peer_key());
        let receipt = Receipt::present(tree, endpoint, proof)?;
        let commit = self.peer.commit(tree, receipt).await?;
        Ok(commit)
    }

    /// Dial `remote` at the endpoint it names, batch-sync `tree` with it, and
    /// disconnect.
    ///
    /// # Specification
    /// - ensures: the dial's endpoint address is `remote`'s endpoint with every
    ///   address it names, so a dial naming one does not wait on address
    ///   lookup; iroh's lookups run beside it.
    /// - ensures: on success the remote proved it holds `remote`'s peer key;
    ///   every commit the remote held for `tree` when it answered is durable in
    ///   this peer's store; the connection is closed; returns this peer's heads
    ///   for `tree` after the sync, so a dialer holding nothing the remote
    ///   lacks reports exactly the remote's heads, and the path iroh had
    ///   selected for the connection once both the sync round ended and the
    ///   connection had settled ([`SelectedPath::settle`]): a direct path, or
    ///   whatever is selected [`SETTLE`] after the round starts. iroh does not
    ///   promise a direct path, even between two peers on one host: a
    ///   connection can stay on its relay, and is reported as relayed.
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
    ///   dialer's heads after a sync at the remote's direct address are
    ///   compared exactly with the union of both frontiers, which a pull that
    ///   dropped either side, or one that skipped storage, would not produce; a
    ///   dial naming the wrong peer key is refused as a connect failure; the
    ///   dialer reports a selected path; a dial at the addresses the remote's
    ///   presence names syncs.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    /// - witness: `node::tests::a_peer_reached_through_its_presence_syncs`
    #[inline]
    pub async fn sync(
        &self,
        remote: &RemotePeer,
        tree: TreeId,
    ) -> Result<Synced, SyncError>
    {
        let quic = self.link(remote).await?;
        let peer = remote.peer();
        let round = self.round(peer, tree);
        let (round, ()) = futures::future::join(round, SelectedPath::settle(&quic)).await;
        let path = SelectedPath::of(&quic);
        let disconnected = self.disconnect(peer).await;
        round?;
        disconnected?;
        let heads = self.peer.heads(tree).await.map_err(SyncError::Heads)?;
        Ok(Synced { heads, path })
    }

    /// Dial `remote` at the endpoint it names and keep the link: the remote
    /// and this peer each pull over it ([`Node::pull`]) until either
    /// disconnects ([`Node::disconnect`]).
    ///
    /// # Specification
    /// - ensures: the dial names `remote`'s endpoint as [`Node::sync`] does; on
    ///   success the remote proved it holds `remote`'s peer key, and the link
    ///   is registered with the engine, which answers the remote's sync
    ///   requests over it.
    /// - fails: [`SyncError::Connect`] when the remote cannot be reached or
    ///   fails the handshake, and [`SyncError::Register`] when the engine
    ///   refuses the connection.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Connect`]: dialing or the handshake fails.
    /// - [`SyncError::Register`]: the engine refuses the connection.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a dialer links, opens a connection under another
    ///   protocol, and the acceptor pulls the dialer's commit over the link.
    /// - witness: `node::tests::a_linked_peer_pulls_beside_another_protocol`
    #[inline]
    pub async fn connect(
        &self,
        remote: &RemotePeer,
    ) -> Result<(), SyncError>
    {
        let _quic = self.link(remote).await?;
        Ok(())
    }

    /// Batch-sync `tree` with `remote` over the link this node holds to it,
    /// dialed or accepted, and keep the link.
    ///
    /// # Specification
    /// - requires: a link to `remote` is up: [`Node::connect`] dialed it, or
    ///   [`Node::accept`] admitted it.
    /// - ensures: on success every commit `remote` held for `tree` when it
    ///   answered is durable in this peer's store; returns this peer's heads
    ///   for `tree` after the round. Commits `remote` asks for are queued to
    ///   it, best effort.
    /// - fails: [`SyncError::Exchange`] and [`SyncError::Call`] when the round
    ///   fails, [`SyncError::Refused`] when `remote` answers without a diff or
    ///   no link to it is up, and [`SyncError::Heads`] when the heads cannot be
    ///   read back.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Exchange`]: storage or the connection fails mid-sync.
    /// - [`SyncError::Call`]: the sync request gets no answer.
    /// - [`SyncError::Refused`]: no answer with a diff, or no link.
    /// - [`SyncError::Heads`]: the heads cannot be read back.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — the acceptor of a link pulls a commit only the dialer
    ///   holds and reads it among its heads.
    /// - witness: `node::tests::a_linked_peer_pulls_beside_another_protocol`
    #[inline]
    pub async fn pull(
        &self,
        remote: PeerKey,
        tree: TreeId,
    ) -> Result<Heads, SyncError>
    {
        self.round(remote, tree).await?;
        self.peer.heads(tree).await.map_err(SyncError::Heads)
    }

    /// Close every link this node holds to `remote`.
    ///
    /// # Specification
    /// - ensures: on success no link to `remote` is registered; a node with
    ///   none succeeds.
    /// - fails: [`SyncError::Disconnect`] when a link cannot be closed.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Disconnect`]: a link cannot be closed.
    #[inline]
    pub async fn disconnect(
        &self,
        remote: PeerKey,
    ) -> Result<(), SyncError>
    {
        let _was_connected = self
            .peer
            .engine()
            .disconnect_from_peer(&remote.peer_id())
            .await
            .map_err(SyncError::Disconnect)?;
        Ok(())
    }

    /// Dial `remote` under `protocol`.
    ///
    /// # Specification
    /// - ensures: the dial names `remote` with every address it names, as
    ///   [`Node::sync`] does; on success the connection is past QUIC's
    ///   handshake, which proves the remote holds `remote`'s endpoint key, and
    ///   carries nothing yet.
    /// - fails: [`DialError`] when the remote cannot be reached or does not
    ///   accept `protocol`.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`DialError`]: the dial fails.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a connection dialed under another protocol arrives at
    ///   the acceptor as that protocol's, and carries a stream both ways.
    /// - witness: `node::tests::a_linked_peer_pulls_beside_another_protocol`
    #[inline]
    pub async fn open(
        &self,
        remote: &Endpoint,
        protocol: Protocol,
    ) -> Result<iroh::endpoint::Connection, DialError>
    {
        self.endpoint
            .connect(remote.addr(), protocol.0)
            .await
            .map_err(DialError)
    }

    /// Dial `remote` under subduction's ALPN, run the handshake as the
    /// initiator, and register the link.
    ///
    /// # Specification
    /// - ensures: as [`Node::connect`]; returns the link's QUIC connection.
    /// - fails: as [`Node::connect`].
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Connect`]: dialing or the handshake fails.
    /// - [`SyncError::Register`]: the engine refuses the connection.
    async fn link(
        &self,
        remote: &RemotePeer,
    ) -> Result<iroh::endpoint::Connection, SyncError>
    {
        let connected = subduction_iroh::client::connect(
            &self.endpoint,
            remote.endpoint().addr(),
            self.peer.identity().signer(),
            Audience::known(remote.peer().peer_id()),
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
        Ok(quic)
    }

    /// Run one batch-sync round of `tree` with `remote` over the links this
    /// node holds to it.
    ///
    /// # Specification
    /// - ensures: on success the remote answered with a diff and every commit
    ///   it sent is durable in this peer's store.
    /// - fails: [`SyncError::Exchange`] when storage or a link fails,
    ///   [`SyncError::Call`] for the first link whose request got no answer,
    ///   and [`SyncError::Refused`] when no link answered with a diff, none
    ///   failing.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`SyncError::Exchange`], [`SyncError::Call`], [`SyncError::Refused`]:
    ///   as listed above.
    async fn round(
        &self,
        remote: PeerKey,
        tree: TreeId,
    ) -> Result<(), SyncError>
    {
        let peer = remote.peer_id();
        let round = self.peer.engine().sync_with_peer(
            &peer,
            tree.sedimentree(),
            false,
            CallTimeout::Default,
        );
        let (answered, _statistics, failures) = round.await.map_err(SyncError::Exchange)?;
        if answered {
            return Ok(());
        }
        Err(match failures.into_iter().next() {
            | Some((_connection, failure)) => SyncError::Call(failure),
            | None => SyncError::Refused,
        })
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

/// Why a peer cannot present its endpoint.
#[derive(Debug, thiserror::Error)]
pub enum PresentError
{
    /// No operation fence can be drawn for the presence.
    #[error(transparent)]
    Random(#[from] RandomError),
    /// The presence cannot be committed.
    #[error(transparent)]
    Commit(#[from] CommitError),
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
    /// The connection names a protocol the node does not accept.
    #[error("an incoming connection names a protocol this peer does not accept")]
    Protocol,
}

/// Why a dial under another protocol failed: the remote cannot be reached,
/// or does not accept the protocol.
#[derive(Debug, thiserror::Error)]
#[error("cannot dial the remote peer's protocol")]
#[repr(transparent)]
pub struct DialError(#[source] iroh::endpoint::ConnectError);

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
    /// The remote answers without a diff, refusing the tree, or no link to it
    /// is up.
    #[error("the remote peer refused to sync the tree, or no link to it is up")]
    Refused,
    /// The connection cannot be closed.
    #[error("cannot close the connection")]
    Disconnect(#[source] DisconnectionError),
    /// The heads cannot be read back.
    #[error("cannot read the heads after the sync")]
    Heads(#[source] HeadsError),
}

/// The time a handshake is answered at: the seconds since the Unix epoch.
///
/// # Specification
/// - ensures: the system clock's reading; a clock set before the epoch reads as
///   the epoch, which the handshake's drift check then refuses rather than this
///   reading panicking.
/// - panics: none.
fn now() -> TimestampSeconds
{
    let since = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH);
    TimestampSeconds::new(since.map_or(0, |since| since.as_secs()))
}

#[cfg(test)]
mod tests
{
    use alloc::string::String;
    use alloc::sync::Arc;
    use core::net::Ipv4Addr;
    use core::net::SocketAddr;

    use sedimentree_core::loose_commit::id::CommitId;

    use super::AcceptError;
    use super::BindPort;
    use super::Incoming;
    use super::Node;
    use super::Protocol;
    use super::SelectedPath;
    use super::SyncError;
    use super::UdpPort;
    use crate::id::Endpoint;
    use crate::id::RemotePeer;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;
    use crate::presence::Aim;
    use crate::presence::At;
    use crate::presence::Route;
    use crate::receipt::Receipt;
    use crate::store::Peer;
    use crate::testing::runtime;
    use crate::testing::tree_key;

    /// A protocol a test node accepts beside subduction's.
    const ECHO: Protocol = Protocol(b"domhringr/test/0");

    /// Open and bind a peer on a fresh state directory beneath `root`,
    /// accepting `protocols` beside subduction's.
    ///
    /// # Specification
    /// trivial.
    async fn bound_with(
        root: &tempfile::TempDir,
        port: BindPort,
        protocols: &[Protocol],
    ) -> Node
    {
        let state = StateDir::from(root.path().to_path_buf());
        let identity = Identity::load_or_create(&state).unwrap();
        Peer::open(&state, identity)
            .unwrap()
            .bind(port, protocols)
            .await
            .unwrap()
    }

    /// Open and bind a peer on a fresh state directory beneath `root`.
    ///
    /// # Specification
    /// trivial.
    async fn bound(
        root: &tempfile::TempDir,
        port: BindPort,
    ) -> Node
    {
        bound_with(root, port, &[]).await
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

    /// `node`'s endpoint at its direct address on this host: the loopback
    /// address at its IPv4 socket's port.
    ///
    /// # Specification
    /// trivial.
    fn direct(node: &Node) -> Endpoint
    {
        let sockets = node.endpoint.bound_sockets();
        let ipv4 = sockets.iter().find(|socket| socket.is_ipv4()).unwrap();
        Endpoint::new(node.endpoint_key())
            .with_direct(SocketAddr::from((Ipv4Addr::LOCALHOST, ipv4.port())))
    }

    #[test]
    fn a_dialer_takes_the_union_of_both_frontiers()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = tree_key().tree();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a, BindPort::Ephemeral).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            serve(&a);
            commit(&a, tree, "a1".into()).await;
            let a2 = commit(&a, tree, "a2".into()).await;
            let b1 = commit(&b, tree, "b1".into()).await;
            let remote = RemotePeer::new(direct(&a), a.peer().identity().peer_key());
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
        let tree = tree_key().tree();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a, BindPort::Ephemeral).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            serve(&a);
            commit(&a, tree, "a1".into()).await;
            let impostor = b.peer().identity().peer_key();
            let remote = RemotePeer::new(direct(&a), impostor);
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
    fn a_peer_reached_through_its_presence_syncs()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let key = tree_key();
        let tree = key.tree();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a, BindPort::Ephemeral).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            serve(&a);
            let owner = a.peer().identity().peer_key();
            a.peer()
                .commit(tree, Receipt::open(&key, owner).unwrap())
                .await
                .unwrap();
            let presented = a.present(tree).await.unwrap();
            let view = a.peer().view(tree).await.unwrap();
            let presence = view.book().get(&owner).unwrap();
            assert_eq!(
                presence.since(),
                presented,
                "the presence holds since the commit that presented it"
            );
            assert_eq!(
                presence.endpoint().key(),
                a.endpoint_key(),
                "a peer presents its own endpoint"
            );
            assert!(
                !presence.endpoint().addresses().is_empty(),
                "the presence names where the endpoint is reached: {}",
                presence.endpoint()
            );
            b.sync(&RemotePeer::new(direct(&a), owner), tree)
                .await
                .unwrap();
            let later = commit(&a, tree, "after the presence".into()).await;
            let route = b.peer().route(tree, Aim::Owner, At::Book).await.unwrap();
            let Route::Book { remote, since } = route
            else {
                panic!("the synced book holds the owner's presence: {route:?}");
            };
            assert_eq!(since, presented, "the route names the presenting commit");
            assert_eq!(
                remote.endpoint(),
                presence.endpoint(),
                "the route dials the endpoint as presented"
            );
            let synced = b.sync(&remote, tree).await.unwrap();
            assert_eq!(
                synced.heads().iter().copied().collect::<Vec<_>>(),
                [later],
                "a dial at the presented endpoint syncs what the owner committed since"
            );
            b.close().await;
            drop(b);
            a.close().await;
            drop(a);
        });
    }

    #[test]
    fn a_linked_peer_pulls_beside_another_protocol()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = tree_key().tree();
        runtime().block_on(async {
            let a = Arc::new(bound_with(&root_a, BindPort::Ephemeral, &[ECHO]).await);
            let b = bound(&root_b, BindPort::Ephemeral).await;
            let b1 = commit(&b, tree, "b1".into()).await;
            let acceptor = Arc::clone(&a);
            let accepting = tokio::spawn(async move {
                let Incoming::Peer(linked) = acceptor.accept().await.unwrap()
                else {
                    panic!("the link arrives first");
                };
                let Incoming::Protocol {
                    protocol,
                    connection,
                } = acceptor.accept().await.unwrap()
                else {
                    panic!("the protocol's connection arrives second");
                };
                let heads = acceptor.pull(linked.peer(), tree).await.unwrap();
                let (mut send, mut recv) = connection.accept_bi().await.unwrap();
                let asked = recv.read_to_end(64).await.unwrap();
                send.write_all(&asked).await.unwrap();
                send.finish().unwrap();
                let _closed = connection.closed().await;
                (linked.peer(), protocol, heads)
            });
            let remote = RemotePeer::new(direct(&a), a.peer().identity().peer_key());
            b.connect(&remote).await.unwrap();
            let connection = b.open(&direct(&a), ECHO).await.unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(b"ping").await.unwrap();
            send.finish().unwrap();
            let answered = recv.read_to_end(64).await.unwrap();
            connection.close(iroh::endpoint::VarInt::from_u32(0), b"done");
            let (linked, protocol, heads) = accepting.await.unwrap();
            assert_eq!(answered, b"ping", "the protocol's stream carries both ways");
            assert_eq!(
                (linked, protocol),
                (b.peer().identity().peer_key(), ECHO),
                "the acceptor admits the dialer's link, then hands over its protocol"
            );
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                [b1],
                "the acceptor pulls the dialer's commit over the link"
            );
            b.disconnect(remote.peer()).await.unwrap();
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
