//! The wake: the one stream an operator opens to a seat under [`PROTOCOL`].
//!
//! The operator first links to the seat over subduction ([`Node::connect`]),
//! then opens a connection under [`PROTOCOL`] and one bidirectional stream on
//! it, writes one line — the dispatch's commit anchor and its own peer id
//! ([`Wake`]) — and finishes its side. The seat pulls the task over the link
//! the operator holds open, folds it, and writes one line back: `woken`, or
//! `declined <reason>` ([`Reply`]). A woken operator pulls the task in turn,
//! which carries the seat's presence when the seat had none, and drops the
//! link. Neither line is stored or hashed: the record holds the dispatch, and
//! the stream only says which one to read.

use core::fmt;
use core::str::FromStr;
use core::time::Duration;

use domhringr_record_tree::Anchor;
use domhringr_record_tree::Authority;
use domhringr_record_tree::CommitId;
use domhringr_record_tree::DialError;
use domhringr_record_tree::Node;
use domhringr_record_tree::ParseAnchorError;
use domhringr_record_tree::ParseIdError;
use domhringr_record_tree::PeerKey;
use domhringr_record_tree::Protocol;
use domhringr_record_tree::RemotePeer;
use domhringr_record_tree::SyncError;
use domhringr_record_tree::TreeId;

/// The protocol a seat answers wakes under.
pub const PROTOCOL: Protocol = Protocol(b"domhringr/seat/0");

/// The most bytes either side's line holds: a wake is a commit anchor and a
/// peer id, under two hundred bytes, and a reply is shorter.
pub const LINE_BYTES: usize = 512;

/// How long an operator waits for the seat's reply once its wake is sent.
/// The seat pulls the task and folds it, and when the task's book lacks it,
/// presents itself, which waits up to five seconds on its relay.
const REPLY: Duration = Duration::from_secs(30);

/// An operator's wake: the dispatch a seat is to answer, and the operator it
/// pulls the task from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Wake
{
    /// The task.
    tree: TreeId,
    /// The dispatch to answer.
    dispatch: CommitId,
    /// The operator the task is pulled from, over the link it holds open.
    operator: PeerKey,
}

impl Wake
{
    /// The wake for `dispatch` in `tree`, pulled from `operator`.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn new(
        tree: TreeId,
        dispatch: CommitId,
        operator: PeerKey,
    ) -> Self
    {
        Self {
            tree,
            dispatch,
            operator,
        }
    }

    /// The task.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn tree(&self) -> TreeId
    {
        self.tree
    }

    /// The dispatch to answer.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn dispatch(&self) -> CommitId
    {
        self.dispatch
    }

    /// The operator the task is pulled from.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    #[must_use]
    pub const fn operator(&self) -> PeerKey
    {
        self.operator
    }
}

impl fmt::Display for Wake
{
    /// Write the wake as `<commit anchor> <operator peer id>`: the dispatch's
    /// anchor in the key form, its id whole.
    ///
    /// # Specification
    /// - ensures: [`Wake::from_str`] reads the text back to this wake.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a wake is written, read back equal, and compared with
    ///   its line written by hand.
    /// - witness: `wake::tests::a_wake_and_a_reply_are_one_line_each`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        write!(
            f,
            "{} {}",
            Anchor::commit(self.tree, self.dispatch),
            self.operator
        )
    }
}

impl FromStr for Wake
{
    type Err = ParseWakeError;

    /// Read a wake from its line, without the newline.
    ///
    /// # Specification
    /// - ensures: accepts exactly what [`Wake`]'s display writes: a commit
    ///   anchor in the key form, one space, and a peer id.
    /// - fails: [`ParseWakeError::Shape`] for text without a space,
    ///   [`ParseWakeError::Anchor`] for an anchor that does not parse,
    ///   [`ParseWakeError::NotCommit`] for one naming no commit or naming its
    ///   tree by a DNS name or a label, and [`ParseWakeError::Operator`] for a
    ///   peer id that does not parse.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseWakeError`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a written wake reads back, and a line without a
    ///   space, a path anchor, a label anchor, a short commit id and a short
    ///   peer id each meet their own refusal.
    /// - witness: `wake::tests::a_wake_and_a_reply_are_one_line_each`
    /// - witness: `wake::tests::a_malformed_line_is_refused_by_name`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let (anchor, operator) = text.split_once(' ').ok_or(ParseWakeError::Shape)?;
        let anchor = anchor.parse::<Anchor>().map_err(ParseWakeError::Anchor)?;
        let Anchor::Commit {
            authority: Authority::Key(tree),
            commit,
        } = anchor
        else {
            return Err(ParseWakeError::NotCommit);
        };
        let operator = operator.parse().map_err(ParseWakeError::Operator)?;
        Ok(Self::new(tree, commit, operator))
    }
}

/// Why a seat declines a wake, as its reply names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Decline
{
    /// The wake is not one line naming a dispatch and an operator.
    Malformed,
    /// The task cannot be pulled from the operator.
    Unsynced,
    /// The task cannot be folded.
    Unfolded,
    /// The dispatch is not the task's current attempt.
    NotCurrent,
    /// The seat does not hold the dispatch's slot.
    NotHeld,
    /// The seat cannot present itself in the task.
    Unpresented,
}

impl fmt::Display for Decline
{
    /// Write the reason as the reply carries it.
    ///
    /// # Specification
    /// trivial.
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        f.write_str(match *self {
            | Self::Malformed => "malformed",
            | Self::Unsynced => "unsynced",
            | Self::Unfolded => "unfolded",
            | Self::NotCurrent => "not current",
            | Self::NotHeld => "not held",
            | Self::Unpresented => "unpresented",
        })
    }
}

/// A seat's reply to a wake.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reply
{
    /// The seat holds the dispatch's slot and is at work on it, or has
    /// reported on it.
    Woken,
    /// The seat declines, for this reason.
    Declined(Decline),
}

impl fmt::Display for Reply
{
    /// Write the reply as `woken` or `declined <reason>`.
    ///
    /// # Specification
    /// - ensures: [`Reply::from_str`] reads the text back to this reply.
    /// - panics: none.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every reply is written and read back equal.
    /// - witness: `wake::tests::a_wake_and_a_reply_are_one_line_each`
    #[inline]
    fn fmt(
        &self,
        f: &mut fmt::Formatter<'_>,
    ) -> fmt::Result
    {
        match *self {
            | Self::Woken => f.write_str("woken"),
            | Self::Declined(decline) => write!(f, "declined {decline}"),
        }
    }
}

impl FromStr for Reply
{
    type Err = ParseReplyError;

    /// Read a reply from its line, without the newline.
    ///
    /// # Specification
    /// - ensures: accepts exactly what [`Reply`]'s display writes.
    /// - fails: [`ParseReplyError`] for any other text.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseReplyError`]: the text is no reply.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — every reply reads back, and an unknown reason and an
    ///   unknown word are refused.
    /// - witness: `wake::tests::a_wake_and_a_reply_are_one_line_each`
    /// - witness: `wake::tests::a_malformed_line_is_refused_by_name`
    #[inline]
    fn from_str(text: &str) -> Result<Self, Self::Err>
    {
        let decline = match text {
            | "woken" => return Ok(Self::Woken),
            | "declined malformed" => Decline::Malformed,
            | "declined unsynced" => Decline::Unsynced,
            | "declined unfolded" => Decline::Unfolded,
            | "declined not current" => Decline::NotCurrent,
            | "declined not held" => Decline::NotHeld,
            | "declined unpresented" => Decline::Unpresented,
            | _ => return Err(ParseReplyError),
        };
        Ok(Self::Declined(decline))
    }
}

/// Wake the seat `remote` names to the dispatch `wake` names.
///
/// # Specification
/// - requires: `wake` names this node's peer as its operator, and this node's
///   store holds the dispatch.
/// - ensures: links to `remote` ([`Node::connect`]), dials it under
///   [`PROTOCOL`] at the same endpoint ([`Node::open`]), writes the wake's line
///   on one bidirectional stream and reads the seat's reply line; on
///   [`Reply::Woken`] pulls the task from the seat over the link
///   ([`Node::pull`]), so this store then holds what the seat committed to it
///   before replying, its presence among them. The protocol connection is
///   closed and the link dropped whatever the outcome.
/// - fails: [`WakeError::Link`] when the link cannot be made or dropped,
///   [`WakeError::Dial`] when the seat cannot be dialed under [`PROTOCOL`],
///   [`WakeError::Stream`], [`WakeError::Send`] and [`WakeError::Receive`] when
///   the stream fails, [`WakeError::Silent`] when no reply comes within thirty
///   seconds, [`WakeError::Reply`] for a reply that is no reply line,
///   [`WakeError::Declined`] naming the seat's reason, and [`WakeError::Pull`]
///   when the task cannot be pulled back.
/// - panics: none.
///
/// # Errors
/// - [`WakeError`]: as listed above.
///
/// # Adequacy
/// - hypothesis: L3 — an operator wakes a seat serving in-process: the seat
///   answers woken, acts and reports, and the operator's store then holds the
///   seat's presence; a wake to a dispatch the seat does not hold is declined
///   by name.
/// - witness: `seat::tests::a_woken_seat_presents_acts_and_reports`
#[inline]
pub async fn wake(
    node: &Node,
    remote: &RemotePeer,
    wake: &Wake,
) -> Result<(), WakeError>
{
    node.connect(remote).await.map_err(WakeError::Link)?;
    let woken = exchange(node, remote, wake).await;
    let disconnected = node.disconnect(remote.peer()).await;
    woken?;
    disconnected.map_err(WakeError::Link)
}

/// Dial the seat under [`PROTOCOL`], ask it `wake`, and on a woken reply pull
/// the task back over the link.
///
/// # Specification
/// - requires: a link to `remote` is up.
/// - ensures: as [`wake`] states once the link is up; the protocol connection
///   is closed before the pull.
/// - fails: as [`wake`], but for [`WakeError::Link`].
/// - panics: none.
///
/// # Errors
/// - [`WakeError`]: as [`wake`].
async fn exchange(
    node: &Node,
    remote: &RemotePeer,
    wake: &Wake,
) -> Result<(), WakeError>
{
    let connection = node
        .open(remote.endpoint(), PROTOCOL)
        .await
        .map_err(WakeError::Dial)?;
    let replied = ask(&connection, wake).await;
    connection.close(iroh::endpoint::VarInt::from_u32(0), b"answered");
    match replied? {
        | Reply::Woken => {
            let _heads = node
                .pull(remote.peer(), wake.tree())
                .await
                .map_err(WakeError::Pull)?;
            Ok(())
        },
        | Reply::Declined(decline) => Err(WakeError::Declined(decline)),
    }
}

/// Write `wake`'s line on a fresh stream of `connection` and read the reply.
///
/// # Specification
/// - ensures: the wake's line and a newline are written and the send side
///   finished; returns the reply the seat wrote back, read within thirty
///   seconds.
/// - fails: as [`wake`] for the stream and the reply.
/// - panics: none.
///
/// # Errors
/// - [`WakeError::Stream`], [`WakeError::Send`], [`WakeError::Receive`],
///   [`WakeError::Silent`], [`WakeError::Reply`]: as [`wake`].
async fn ask(
    connection: &iroh::endpoint::Connection,
    wake: &Wake,
) -> Result<Reply, WakeError>
{
    let (mut send, mut recv) = connection.open_bi().await.map_err(WakeError::Stream)?;
    let line = format!("{wake}\n");
    send.write_all(line.as_bytes())
        .await
        .map_err(WakeError::Send)?;
    send.finish().map_err(WakeError::Finish)?;
    let replied = tokio::time::timeout(REPLY, recv.read_to_end(LINE_BYTES))
        .await
        .map_err(|_elapsed| WakeError::Silent)?
        .map_err(WakeError::Receive)?;
    let reply = Line::try_from(replied).map_err(|_unreadable| WakeError::Reply(ParseReplyError))?;
    reply.as_ref().parse().map_err(WakeError::Reply)
}

/// One line as either side writes it, read: UTF-8 that ended in its one
/// newline, held without it.
#[derive(Clone, Debug, PartialEq, Eq)]
#[repr(transparent)]
pub struct Line(String);

impl TryFrom<Vec<u8>> for Line
{
    type Error = ParseWakeError;

    /// Read the line `bytes` hold.
    ///
    /// # Specification
    /// - ensures: the text before the newline, in the bytes' own allocation.
    /// - fails: [`ParseWakeError::Line`] for bytes that are not UTF-8, do not
    ///   end in a newline, or hold another.
    /// - panics: none.
    ///
    /// # Errors
    /// - [`ParseWakeError::Line`]: as listed above.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a wake's line is read back to its text, and bytes
    ///   that are not UTF-8, lack the newline or hold two are refused.
    /// - witness: `wake::tests::a_wake_and_a_reply_are_one_line_each`
    /// - witness: `wake::tests::a_malformed_line_is_refused_by_name`
    fn try_from(bytes: Vec<u8>) -> Result<Self, ParseWakeError>
    {
        let mut text = String::from_utf8(bytes).map_err(|_not_utf8| ParseWakeError::Line)?;
        if text.pop() != Some('\n') || text.contains('\n') {
            return Err(ParseWakeError::Line);
        }
        Ok(Self(text))
    }
}

impl AsRef<str> for Line
{
    /// The line's text, without its newline.
    ///
    /// # Specification
    /// trivial.
    fn as_ref(&self) -> &str
    {
        &self.0
    }
}

/// Why a text is no wake.
#[derive(Debug, thiserror::Error)]
pub enum ParseWakeError
{
    /// The bytes are not one UTF-8 line ending in a newline.
    #[error("a wake is one UTF-8 line")]
    Line,
    /// The line holds no space between an anchor and a peer id.
    #[error("a wake is a commit anchor and a peer id")]
    Shape,
    /// The anchor does not parse.
    #[error("cannot read the wake's anchor")]
    Anchor(#[source] ParseAnchorError),
    /// The anchor names no commit, or names its tree other than by key.
    #[error("the wake's anchor names no commit by its tree's key")]
    NotCommit,
    /// The operator's peer id does not parse.
    #[error("cannot read the wake's operator")]
    Operator(#[source] ParseIdError),
}

/// Why a text is no reply.
#[derive(Clone, Copy, Debug, PartialEq, Eq, thiserror::Error)]
#[error("the seat's reply is neither woken nor a known decline")]
pub struct ParseReplyError;

/// Why a wake failed.
#[derive(Debug, thiserror::Error)]
pub enum WakeError
{
    /// The link to the seat cannot be made or dropped.
    #[error("cannot link to the seat")]
    Link(#[source] SyncError),
    /// The seat cannot be dialed under the seat protocol.
    #[error(transparent)]
    Dial(#[from] DialError),
    /// No stream opens on the connection.
    #[error("cannot open the wake's stream")]
    Stream(#[source] iroh::endpoint::ConnectionError),
    /// The wake cannot be written.
    #[error("cannot write the wake")]
    Send(#[source] iroh::endpoint::WriteError),
    /// The wake's stream cannot be finished.
    #[error("cannot finish the wake's stream")]
    Finish(#[source] iroh::endpoint::ClosedStream),
    /// The reply cannot be read.
    #[error("cannot read the seat's reply")]
    Receive(#[source] iroh::endpoint::ReadToEndError),
    /// No reply came in time.
    #[error("the seat did not reply within thirty seconds")]
    Silent,
    /// The reply is no reply line.
    #[error(transparent)]
    Reply(ParseReplyError),
    /// The seat declined.
    #[error("the seat declined the wake: {0}")]
    Declined(Decline),
    /// The task cannot be pulled back from the seat.
    #[error("cannot pull the task back from the seat")]
    Pull(#[source] SyncError),
}

#[cfg(test)]
mod tests
{
    use domhringr_record_tree::CommitId;
    use domhringr_record_tree::PeerKey;
    use domhringr_record_tree::TreeId;

    use super::Decline;
    use super::Line;
    use super::ParseWakeError;
    use super::Reply;
    use super::Wake;

    /// A tree's anchor: the all-zero key's.
    const TREE: &str = "domhringr://yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy/";

    /// A peer id.
    const PEER: &str = "7065657270656572706565727065657270656572706565727065657270656572";

    /// The tree [`TREE`] names.
    ///
    /// # Specification
    /// trivial.
    fn tree() -> TreeId
    {
        let anchor = TREE.parse::<domhringr_record_tree::Anchor>().unwrap();
        let domhringr_record_tree::Anchor::Tree(domhringr_record_tree::Authority::Key(tree)) =
            anchor
        else {
            panic!("the fixture names a tree by key");
        };
        tree
    }

    #[test]
    fn a_wake_and_a_reply_are_one_line_each()
    {
        let dispatch = CommitId::new([0x0d; 32]);
        let operator = PEER.parse::<PeerKey>().unwrap();
        let wake = Wake::new(tree(), dispatch, operator);
        let text = wake.to_string();
        assert_eq!(
            text,
            format!("{}.commit/{dispatch} {PEER}", TREE),
            "a wake is the dispatch's commit anchor and the operator's peer id"
        );
        assert_eq!(text.parse::<Wake>().unwrap(), wake, "a wake reads back");
        assert_eq!(
            Line::try_from(format!("{text}\n").into_bytes())
                .unwrap()
                .as_ref(),
            text,
            "the wire line is the wake and one newline"
        );
        for reply in [
            Reply::Woken,
            Reply::Declined(Decline::Malformed),
            Reply::Declined(Decline::Unsynced),
            Reply::Declined(Decline::Unfolded),
            Reply::Declined(Decline::NotCurrent),
            Reply::Declined(Decline::NotHeld),
            Reply::Declined(Decline::Unpresented),
        ] {
            assert_eq!(
                reply.to_string().parse::<Reply>().unwrap(),
                reply,
                "{reply} reads back"
            );
        }
        assert_eq!(
            Reply::Declined(Decline::NotHeld).to_string(),
            "declined not held",
            "a decline names its reason"
        );
    }

    #[test]
    fn a_malformed_line_is_refused_by_name()
    {
        let dispatch = CommitId::new([0x0d; 32]);
        let commit = format!("{}.commit/{dispatch}", TREE);
        for (text, case) in [
            (commit.clone(), "no space"),
            (format!("{TREE}a/b {PEER}"), "a path anchor"),
            (
                format!("domhringr://friend/.commit/{dispatch} {PEER}"),
                "a label anchor",
            ),
        ] {
            assert!(
                matches!(
                    text.parse::<Wake>(),
                    Err(ParseWakeError::Shape | ParseWakeError::NotCommit)
                ),
                "{case} is refused for its shape"
            );
        }
        assert!(
            matches!(
                format!("{}.commit/0d0d {PEER}", TREE).parse::<Wake>(),
                Err(ParseWakeError::Anchor(_))
            ),
            "a short commit id is refused as an anchor"
        );
        assert!(
            matches!(
                format!("{commit} 7065").parse::<Wake>(),
                Err(ParseWakeError::Operator(_))
            ),
            "a short peer id is refused as the operator"
        );
        for bytes in [&b"woken"[..], b"woken\nwoken\n", &[0xff, b'\n']] {
            assert!(
                matches!(Line::try_from(bytes.to_vec()), Err(ParseWakeError::Line)),
                "{bytes:?} is no line"
            );
        }
        for text in ["declined tired", "asleep", "woken "] {
            assert!(text.parse::<Reply>().is_err(), "{text:?} is no reply");
        }
    }
}
