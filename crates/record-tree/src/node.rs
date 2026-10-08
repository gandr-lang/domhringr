//! A peer bound to an iroh endpoint: reached by endpoint id, accepting
//! connections, and dialing other peers to sync a tree.
//!
//! The endpoint uses n0's preset (relay, DNS address publishing and lookup)
//! plus mDNS address lookup, so a peer is reached by its endpoint id alone:
//! on the LAN through mDNS and direct addresses, across networks through the
//! relay and DNS.

use core::convert::Infallible;

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

impl Peer
{
    /// Bind the peer to an iroh endpoint under its endpoint key.
    ///
    /// # Specification
    /// - ensures: the returned node's endpoint id is the identity's endpoint
    ///   key; the endpoint accepts subduction's ALPN and publishes and looks up
    ///   addresses through n0's DNS and through mDNS.
    /// - fails: [`BindError`] when the endpoint cannot bind its sockets or
    ///   start its address lookups.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`BindError`]: iroh refuses the bind.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — two peers bound in one process reach each other by
    ///   endpoint id alone, which needs the key, the ALPN and the lookup.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    #[inline]
    pub async fn bind(self) -> Result<Node, BindError>
    {
        let endpoint = iroh::Endpoint::builder(iroh::endpoint::presets::N0)
            .secret_key(self.identity().endpoint_secret().clone())
            .alpns(vec![subduction_iroh::ALPN.to_vec()])
            .address_lookup(iroh_mdns_address_lookup::MdnsAddressLookup::builder())
            .bind()
            .await
            .map_err(BindError)?;
        Ok(Node {
            peer: self,
            endpoint,
        })
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
    ///   returns the remote's peer id.
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
    ///   audience check is observed from both sides.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    #[inline]
    pub async fn accept(&self) -> Result<PeerKey, AcceptError>
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
        let connection = accepted.authenticated.map(MessageTransport::new);
        self.peer
            .engine()
            .add_connection(connection)
            .await
            .map_err(AcceptError::Register)?;
        Ok(PeerKey::new(accepted.peer_id))
    }

    /// Dial `remote` by endpoint id, batch-sync `tree` with it, and
    /// disconnect.
    ///
    /// # Specification
    /// - ensures: on success the remote proved it holds `remote`'s peer key;
    ///   every commit the remote held for `tree` when it answered is durable in
    ///   this peer's store; the connection is closed; returns this peer's heads
    ///   for `tree` after the sync, so a dialer holding nothing the remote
    ///   lacks reports exactly the remote's heads.
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
    ///   is refused as a connect failure.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    /// - witness: `node::tests::a_dialer_naming_another_peer_is_refused`
    #[inline]
    pub async fn sync(
        &self,
        remote: &RemotePeer,
        tree: TreeId,
    ) -> Result<Heads, SyncError>
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
        let connection = connected.authenticated.map(MessageTransport::new);
        self.peer
            .engine()
            .add_connection(connection)
            .await
            .map_err(SyncError::Register)?;
        let round = self
            .peer
            .engine()
            .sync_with_peer(&peer, tree.sedimentree(), false, CallTimeout::Default)
            .await;
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
        self.peer.heads(tree).await.map_err(SyncError::Heads)
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
#[error("cannot bind the iroh endpoint")]
#[repr(transparent)]
pub struct BindError(#[source] iroh::endpoint::BindError);

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
    use alloc::sync::Arc;

    use sedimentree_core::loose_commit::id::CommitId;

    use super::AcceptError;
    use super::Node;
    use super::SyncError;
    use crate::id::RemotePeer;
    use crate::id::TreeId;
    use crate::identity::Identity;
    use crate::identity::StateDir;
    use crate::store::Content;
    use crate::store::Peer;

    /// The tree both peers commit to.
    const TREE: &str = "6e6f64656e6f64656e6f64656e6f64656e6f64656e6f64656e6f64656e6f6465";

    /// A multi-threaded runtime, as the peer binary runs.
    ///
    /// # Specification
    /// trivial.
    fn runtime() -> tokio::runtime::Runtime
    {
        tokio::runtime::Builder::new_multi_thread()
            .enable_all()
            .build()
            .unwrap()
    }

    /// Open and bind a peer on a fresh state directory beneath `root`.
    ///
    /// # Specification
    /// trivial.
    async fn bound(root: &tempfile::TempDir) -> Node
    {
        let state = StateDir::from(root.path().to_path_buf());
        let identity = Identity::load_or_create(&state).unwrap();
        Peer::open(&state, identity).unwrap().bind().await.unwrap()
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

    /// Commit `content` to `tree` on `node`.
    ///
    /// # Specification
    /// trivial.
    async fn commit(
        node: &Node,
        tree: TreeId,
        content: Content,
    ) -> CommitId
    {
        node.peer().commit(tree, content).await.unwrap()
    }

    #[test]
    fn a_dialer_takes_the_union_of_both_frontiers()
    {
        let (root_a, root_b) = (tempfile::tempdir().unwrap(), tempfile::tempdir().unwrap());
        let tree = TREE.parse::<TreeId>().unwrap();
        runtime().block_on(async {
            let a = Arc::new(bound(&root_a).await);
            let b = bound(&root_b).await;
            serve(&a);
            commit(&a, tree, Content::from(b"a1".to_vec())).await;
            let a2 = commit(&a, tree, Content::from(b"a2".to_vec())).await;
            let b1 = commit(&b, tree, Content::from(b"b1".to_vec())).await;
            let remote = RemotePeer::new(a.endpoint_key(), a.peer().identity().peer_key());
            let heads = b.sync(&remote, tree).await.unwrap();
            let mut expected = vec![a2, b1];
            expected.sort();
            assert_eq!(
                heads.iter().copied().collect::<Vec<_>>(),
                expected,
                "the dialer holds both frontiers"
            );
            let stored = b.peer().heads(tree).await.unwrap();
            assert_eq!(
                stored, heads,
                "the synced commits are in the dialer's store"
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
            let a = Arc::new(bound(&root_a).await);
            let b = bound(&root_b).await;
            serve(&a);
            commit(&a, tree, Content::from(b"a1".to_vec())).await;
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
}
