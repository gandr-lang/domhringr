//! The Tokio glue subduction needs and ships only behind its test utilities:
//! a task spawner and a call deadline.

use core::time::Duration;

use future_form::Sendable;
use futures::future::AbortHandle;
use futures::future::Abortable;
use futures::future::BoxFuture;
use subduction_core::spawn::Spawn;
use subduction_core::timeout::TimedOut;
use subduction_core::timeout::Timeout;

/// Spawns subduction's background tasks onto the Tokio runtime a peer was
/// opened on.
#[derive(Clone, Debug)]
#[repr(transparent)]
pub struct TokioSpawner(tokio::runtime::Handle);

impl TokioSpawner
{
    /// Spawn onto the runtime `handle` names.
    ///
    /// # Specification
    /// trivial.
    pub const fn new(handle: tokio::runtime::Handle) -> Self
    {
        Self(handle)
    }
}

impl Spawn<Sendable> for TokioSpawner
{
    /// Spawn `fut` onto the runtime, detached, behind an abort handle.
    ///
    /// # Specification
    /// - ensures: `fut` runs to completion on the runtime unless the returned
    ///   handle aborts it first; the task is detached, so dropping the handle
    ///   does not stop it.
    /// - panics: none; spawning through a held runtime handle needs no ambient
    ///   runtime.
    /// - executable: none — completion and cancellation happen after this
    ///   return; the live-sync witness observes the detached protocol tasks.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — background senders and listeners carry both peers to
    ///   the exact union of their frontiers.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    fn spawn(
        &self,
        fut: BoxFuture<'static, ()>,
    ) -> AbortHandle
    {
        let (handle, registration) = AbortHandle::new_pair();
        drop(self.0.spawn(Abortable::new(fut, registration)));
        handle
    }
}

/// Bounds subduction's roundtrip calls with Tokio's timer.
#[derive(Clone, Copy, Debug, Default)]
pub struct TokioTimer;

impl Timeout<Sendable> for TokioTimer
{
    /// Run `fut` until it completes or `dur` elapses.
    ///
    /// # Specification
    /// - requires: polled on a Tokio runtime with its timer enabled.
    /// - ensures: yields the future's output when it completes within `dur`,
    ///   and [`TimedOut`] otherwise, dropping the future.
    /// - panics: when polled outside such a runtime, as Tokio's timer does.
    /// - executable: none — the returned future has not been polled; observing
    ///   its result in a predicate would execute the caller's operation.
    ///
    /// # Adequacy
    /// - hypothesis: L3 — a live sync exercises the completed-call path on an
    ///   enabled Tokio timer; deadline expiry is outside this witness.
    /// - witness: `node::tests::a_dialer_takes_the_union_of_both_frontiers`
    fn timeout<'call, Output>(
        &'call self,
        dur: Duration,
        fut: BoxFuture<'call, Output>,
    ) -> BoxFuture<'call, Result<Output, TimedOut>>
    where
        Output: 'call,
    {
        Box::pin(async move {
            match tokio::time::timeout(dur, fut).await {
                Ok(output) => Ok(output),
                Err(_elapsed) => Err(TimedOut),
            }
        })
    }
}
