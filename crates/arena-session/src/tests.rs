//! Directed endpoint traces and independently checked transport evidence.

use gandr_core_session::Action;
use gandr_core_session::Completion;
use gandr_core_session::Decision;
use gandr_core_session::Move;
use gandr_core_session::PayloadDigest;
use gandr_core_session::Refusal as Reason;
use gandr_core_session::ReplayError;

use crate::Arena;
use crate::Edition;
use crate::Movement;
use crate::Play;
use crate::Progress;

#[test]
fn named_refusal_preserves_the_prefix()
{
    let arena = Arena::new().unwrap();
    let mut play = Play::default();
    let digest = PayloadDigest([7; 32]);
    let refusal = play
        .record(&arena, Edition::Base, Movement::Report, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Report);
    assert!(matches!(refusal.reason, ReplayError::Refused {
        reason: Reason::WrongDirection,
        ..
    }));
    assert_eq!(play.moves(), &[]);
    assert_eq!(
        play.record(&arena, Edition::Base, Movement::Dispatch, digest)
            .unwrap(),
        Progress::Open(Action::Select)
    );
    for movement in [Movement::Report, Movement::Report] {
        assert_eq!(
            play.record(&arena, Edition::Base, movement, digest)
                .unwrap(),
            Progress::Open(Action::Select)
        );
    }
    assert_eq!(
        play.record(&arena, Edition::Base, Movement::Retire, digest)
            .unwrap(),
        Progress::Complete
    );
    let before = play.moves().to_vec();
    let refusal = play
        .record(&arena, Edition::Base, Movement::Report, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Report);
    assert!(matches!(refusal.reason, ReplayError::Refused {
        reason: Reason::ResumeAfterEnd,
        ..
    }));
    assert_eq!(play.moves(), before);
    let mut unreported = Play::default();
    unreported
        .record(&arena, Edition::Base, Movement::Dispatch, digest)
        .unwrap();
    assert_eq!(
        unreported
            .inspect(&arena, Edition::Base, Movement::Report, digest)
            .unwrap(),
        Progress::Open(Action::Select)
    );
    let refusal = unreported
        .record(&arena, Edition::Base, Movement::Retire, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Retire);
    assert!(matches!(refusal.reason, ReplayError::Refused {
        reason: Reason::WrongLabel,
        ..
    }));
    unreported
        .record(&arena, Edition::Base, Movement::Report, digest)
        .unwrap();
    assert_eq!(
        unreported
            .record(&arena, Edition::Base, Movement::Handoff, digest)
            .unwrap(),
        Progress::Complete
    );
    let refusal = unreported
        .record(&arena, Edition::Base, Movement::Handoff, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Handoff);
    assert!(matches!(refusal.reason, ReplayError::Refused {
        reason: Reason::ResumeAfterEnd,
        ..
    }));
    let operator = arena.dual(Edition::Base);
    let payload = |identity| gandr_core_session::Payload { identity, digest };
    let run = [
        Move::Send(payload(crate::DISPATCH)),
        Move::Offer("report".into()),
        Move::Receive(payload(crate::REPORT)),
        Move::Offer("handoff".into()),
        Move::Receive(payload(crate::HANDOFF)),
        Move::End,
    ];
    assert_eq!(gandr_core_session::replay(&operator, &run), Ok(Completion));
    assert!(matches!(
        gandr_core_session::replay(&operator, &[Move::Receive(payload(crate::DISPATCH))]),
        Err(ReplayError::Refused {
            expected: Action::Send(_),
            reason: Reason::WrongDirection,
            ..
        })
    ));
}

#[test]
fn pause_is_certified_and_old_runs_transport()
{
    let mut arena = Arena::new().unwrap();
    assert_eq!(
        gandr_core_session::decide(
            arena.session(Edition::Paused),
            arena.session(Edition::Base),
            gandr_core_session::Relation::Subtype
        ),
        Ok(Decision::Unrelated)
    );
    let mut old = Play::default();
    for (movement, digest) in [
        (Movement::Dispatch, PayloadDigest([8; 32])),
        (Movement::Report, PayloadDigest([9; 32])),
        (Movement::Retire, PayloadDigest([10; 32])),
    ] {
        old.record(&arena, Edition::Base, movement, digest).unwrap();
    }
    let transported = arena.transport(&old).unwrap();
    assert_eq!(transported.moves(), old.moves());
    assert_eq!(
        gandr_core_session::replay(arena.session(Edition::Paused), transported.moves()),
        Ok(Completion)
    );
    let mut paused = Play::default();
    let digest = PayloadDigest([11; 32]);
    paused
        .record(&arena, Edition::Paused, Movement::Dispatch, digest)
        .unwrap();
    let refusal = paused
        .record(&arena, Edition::Base, Movement::Pause, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Pause);
    assert!(
        matches!(refusal.reason, ReplayError::Refused { observed: Move::Select(ref label), reason: Reason::WrongLabel, .. } if label.0 == "pause")
    );
    paused
        .record(&arena, Edition::Paused, Movement::Pause, digest)
        .unwrap();
    paused
        .record(&arena, Edition::Paused, Movement::Report, digest)
        .unwrap();
    paused
        .record(&arena, Edition::Paused, Movement::Retire, digest)
        .unwrap();
    assert_eq!(
        gandr_core_session::replay(arena.session(Edition::Paused), paused.moves()),
        Ok(Completion)
    );
    assert!(matches!(
        arena.transport(&paused),
        Err(crate::ArenaError::Transport(
            gandr_core_session::certified::TransportError::Replay(ReplayError::Refused {
                reason: Reason::WrongLabel,
                ..
            })
        ))
    ));
}
