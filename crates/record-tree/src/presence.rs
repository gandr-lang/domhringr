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
