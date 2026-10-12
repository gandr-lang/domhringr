//! Presence: where a tree's members are reached, as the record says, and how a
//! dialer picks the remote it reaches for a tree.
//!
//! A member presents its own endpoint by a `Present` receipt and withdraws a
//! presence by a `Withdraw` receipt; the fold keeps, per author, the presence
//! admitted last in canonical order, and drops it at a withdrawal admitted
//! after it ([`View::book`]). Nothing is timed: a presence holds until the
//! record withdraws or supersedes it. A dialer names whom it aims at for a
//! tree ([`Aim`]) and where the endpoint comes from ([`At`]), and the peer
//! answers with the [`Route`] to dial.
//!
//! [`View::book`]: crate::fold::View::book
//!
//! # Presence
//!
//! A member says where it is reached by committing a presence: `Node::present`
//! waits up to five seconds for the endpoint to reach its home relay, then
//! commits the endpoint at the addresses iroh names for it, its direct
//! addresses and its relay. The book (`View::book`) holds, per author, the
//! presence admitted last, and the commit that presented it is its `since`; a
//! superseded or withdrawn presence is absent, never a default. `Peer::route`
//! names the remote a dial for a tree reaches: the peer aimed at — a named peer
//! or the tree's owner — at an endpoint named by hand, or else at its presence
//! in the book; the dialer itself is no one to reach, and a peer the book holds
//! no presence of is unreachable. `Peer::reads` names the trees a resolution
//! reads, so a caller syncs each through its route before resolving.
//!
//! **A presence proves its endpoint by the endpoint key's signature naming the
//! author.** A peer's endpoint key and its signing key are distinct, so the
//! commit's author does not name the endpoint by itself; the presence carries
//! the endpoint key's signature over a fixed domain and the author's peer key,
//! and the fold refuses one whose signature does not hold for its author as
//! `foreign endpoint`. A member therefore presents only an endpoint whose key
//! it holds.
//!
//! - the author's signing key as the endpoint key: one key for both roles,
//!   which the state directory keeps apart.
//! - no proof, relying on the handshake: a dial to a stolen presence fails
//!   authentication, but a member could still point every dialer at an address
//!   it does not hold.
//!
//! Reversal: a peer whose endpoint and signing keys are one key, when the check
//! becomes key equality.
//!
//! **A presence carries no time.** Its commit is when it holds since, and it
//! holds until the record supersedes or withdraws it; liveness is the record's,
//! never a clock's.
//!
//! - a timestamp in the payload: a clock in the record, and liveness judged by
//!   elapsed time.
//!
//! Reversal: a design that names a clock in the record.
//!
//! **A withdrawal names the peer whose presence it withdraws.** The owner
//! withdraws anyone's presence and a member its own (`foreign presence`
//! otherwise); a withdrawal of a presence the book does not hold is admitted
//! and changes nothing, so a withdrawal and a presence made concurrently settle
//! by canonical order alone.
//!
//! - a withdrawal naming the presenting commit: it would leave a later presence
//!   by the same author standing, and the owner could not clear an author's
//!   entry in one receipt.
//!
//! Reversal: presences of resources other than the author's own endpoint, which
//! need naming by more than the author.
//!
//! **An endpoint is its id and an ordered set of addresses.** A direct address
//! is an IP address and port, an IPv6 address without its flow label and scope
//! id, both local to the host naming them; a relay is an `http` or `https` URL
//! written as it parses back and holding no `@`, the character the text form
//! `<endpoint-id>@<address>…` separates addresses by. The receipt lists the
//! addresses in that order, each once, so an endpoint has one encoding; an
//! address of another transport iroh names is left out.
//!
//! - iroh's `EndpointAddr` through serde: a second canonical form beside the
//!   value plane's, its order the serializer's.
//! - an iroh ticket string: base32 of a postcard encoding, opaque to the
//!   decoder's refusals.
//!
//! Reversal: a transport beyond IP and relays that a dialer needs from the
//! book.
//!
//! **An endpoint named by hand overrides the book.** A dial reads the book only
//! when no endpoint is named. A presence goes stale when its peer moves before
//! presenting again, and a book read first would then leave the peer
//! unreachable even with its current address in hand.
//!
//! - the book first, the endpoint named by hand only when the book holds no
//!   presence: one fewer way to name a remote, at the cost of the stale case.
//!
//! Reversal: a book that cannot go stale, as when a dial that fails at a
//! presence falls back on its own.

use core::fmt;

use sedimentree_core::loose_commit::id::CommitId;

use crate::id::Endpoint;
use crate::id::PeerKey;
use crate::id::RemotePeer;

/// A member's presence in a tree: the endpoint it is reached at, and the
/// commit that presented it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Presence
{
    /// The endpoint presented.
    endpoint: Endpoint,
    /// The commit whose receipt presented it: the presence holds since then.
    since: CommitId,
}

impl Presence
{
    /// The presence of `endpoint`, presented by the commit `since`.
    ///
    /// # Specification
    /// trivial.
    pub(crate) const fn new(
        endpoint: Endpoint,
        since: CommitId,
    ) -> Self
    {
        Self { endpoint, since }
    }

    /// The endpoint presented.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn endpoint(&self) -> &Endpoint
    {
        &self.endpoint
    }

    /// The commit that presented it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn since(&self) -> CommitId
    {
        self.since
    }
}

impl fmt::Display for Presence
{
    /// Write the endpoint in its text form, a space, and the presenting
    /// commit's id.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(f, "{} {}", self.endpoint, self.since)
    }
}

/// Whom a dialer aims at for a tree.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Aim
{
    /// The tree's owner, as the local view names it.
    Owner,
    /// The peer with this key.
    Peer(PeerKey),
}

/// Where a dialer takes the endpoint of the peer it aims at from.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum At
{
    /// The tree's book: the peer's presence in the local view.
    Book,
    /// This endpoint, named by hand; the book is not read.
    Given(Endpoint),
}

/// The remote a dialer reaches for a tree.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Route
{
    /// The peer aimed at is the dialer itself: there is no one to reach.
    Itself,
    /// The peer's presence in the book.
    Book
    {
        /// The peer at the endpoint its presence names.
        remote: RemotePeer,
        /// The commit that presented the endpoint.
        since: CommitId,
    },
    /// The peer at the endpoint named by hand.
    Given
    {
        /// The peer at that endpoint.
        remote: RemotePeer,
    },
}
