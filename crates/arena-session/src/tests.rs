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
        .record(&arena, Edition::ONE, Movement::Report, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Report);
    assert!(matches!(
        refusal.reason,
        crate::Reason::Replay(ReplayError::Refused {
            reason: Reason::WrongDirection,
            ..
        })
    ));
    assert_eq!(play.moves(), &[]);
    assert_eq!(
        play.record(&arena, Edition::ONE, Movement::Dispatch, digest)
            .unwrap(),
        Progress::Open(Action::Select)
    );
    for movement in [Movement::Report, Movement::Report] {
        assert_eq!(
            play.record(&arena, Edition::ONE, movement, digest).unwrap(),
            Progress::Open(Action::Select)
        );
    }
    assert_eq!(
        play.record(&arena, Edition::ONE, Movement::Retire, digest)
            .unwrap(),
        Progress::Complete
    );
    let before = play.moves().to_vec();
    let refusal = play
        .record(&arena, Edition::ONE, Movement::Report, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Report);
    assert!(matches!(
        refusal.reason,
        crate::Reason::Replay(ReplayError::Refused {
            reason: Reason::ResumeAfterEnd,
            ..
        })
    ));
    assert_eq!(play.moves(), before);
    let mut unreported = Play::default();
    unreported
        .record(&arena, Edition::ONE, Movement::Dispatch, digest)
        .unwrap();
    assert_eq!(
        unreported
            .inspect(&arena, Edition::ONE, Movement::Report, digest)
            .unwrap(),
        Progress::Open(Action::Select)
    );
    let refusal = unreported
        .record(&arena, Edition::ONE, Movement::Retire, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Retire);
    assert!(matches!(
        refusal.reason,
        crate::Reason::Replay(ReplayError::Refused {
            reason: Reason::WrongLabel,
            ..
        })
    ));
    unreported
        .record(&arena, Edition::ONE, Movement::Report, digest)
        .unwrap();
    assert_eq!(
        unreported
            .record(&arena, Edition::ONE, Movement::Handoff, digest)
            .unwrap(),
        Progress::Complete
    );
    let refusal = unreported
        .record(&arena, Edition::ONE, Movement::Handoff, digest)
        .unwrap_err();
    assert_eq!(refusal.movement, Movement::Handoff);
    assert!(matches!(
        refusal.reason,
        crate::Reason::Replay(ReplayError::Refused {
            reason: Reason::ResumeAfterEnd,
            ..
        })
    ));
    let operator = arena.session(Edition::ONE).unwrap().dual();
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
    let arena = Arena::new().unwrap();
    let mut old = Play::default();
    let digest = PayloadDigest([8; 32]);
    old.record(&arena, Edition::ONE, Movement::Dispatch, digest)
        .unwrap();
    let refusal = old
        .record(&arena, Edition::ONE, Movement::Pause, digest)
        .unwrap_err();
    assert_eq!(refusal.edition, Edition::ONE);
    assert!(matches!(
        refusal.reason,
        crate::Reason::Replay(ReplayError::Refused {
            reason: Reason::WrongLabel,
            ..
        })
    ));
    if !cfg!(feature = "edition-2") {
        assert!(matches!(
            arena.transport(Edition::ONE, Edition::TWO, &old),
            Err(crate::ArenaError::Unknown(crate::UnknownEdition(
                Edition::TWO
            )))
        ));
        return;
    }
    assert!(matches!(
        arena.transport(Edition::ONE, Edition::TWO, &old),
        Err(crate::ArenaError::Transport(
            gandr_core_session::certified::TransportError::Replay(
                ReplayError::IncompleteRun { .. }
            )
        ))
    ));
    for (movement, digest) in [
        (Movement::Report, PayloadDigest([9; 32])),
        (Movement::Retire, PayloadDigest([10; 32])),
    ] {
        old.record(&arena, Edition::ONE, movement, digest).unwrap();
    }
    let transported = arena.transport(Edition::ONE, Edition::TWO, &old).unwrap();
    assert_eq!(transported.moves(), old.moves());
    assert_eq!(
        gandr_core_session::replay(arena.session(Edition::TWO).unwrap(), transported.moves()),
        Ok(Completion)
    );
    assert_eq!(
        gandr_core_session::decide(
            arena.session(Edition::TWO).unwrap(),
            arena.session(Edition::ONE).unwrap(),
            gandr_core_session::Relation::Subtype
        ),
        Ok(Decision::Unrelated)
    );
    assert!(matches!(
        arena.transport(Edition::TWO, Edition::ONE, &transported),
        Err(crate::ArenaError::NotWidening {
            source_edition: Edition::TWO,
            target_edition: Edition::ONE
        })
    ));
    let mut paused = Play::default();
    for movement in [
        Movement::Dispatch,
        Movement::Pause,
        Movement::Report,
        Movement::Pause,
        Movement::Retire,
    ] {
        paused
            .record(&arena, Edition::TWO, movement, digest)
            .unwrap();
    }
    assert_eq!(
        gandr_core_session::replay(arena.session(Edition::TWO).unwrap(), paused.moves()),
        Ok(Completion)
    );
    assert!(matches!(
        arena.transport(Edition::ONE, Edition::TWO, &paused),
        Err(crate::ArenaError::Transport(
            gandr_core_session::certified::TransportError::Replay(ReplayError::Refused {
                reason: Reason::WrongLabel,
                ..
            })
        ))
    ));
}

#[test]
fn unknown_editions_never_replay_as_known_protocols()
{
    let arena = Arena::new().unwrap();
    assert_eq!("1".parse::<Edition>().unwrap(), Edition::ONE);
    assert_eq!(
        "18446744073709551615".parse::<Edition>().unwrap(),
        Edition::from(u64::MAX)
    );
    assert!("18446744073709551616".parse::<Edition>().is_err());
    assert!("pause".parse::<Edition>().is_err());
    let unknowns = if cfg!(feature = "edition-2") {
        vec![Edition::from(0), Edition::from(u64::MAX)]
    }
    else {
        vec![Edition::from(0), Edition::TWO, Edition::from(u64::MAX)]
    };
    for edition in unknowns {
        assert_eq!(edition.to_string().parse::<Edition>().unwrap(), edition);
        assert!(
            matches!(arena.session(edition), Err(crate::UnknownEdition(named)) if named == edition)
        );
        let mut play = Play::default();
        for movement in [
            Movement::Dispatch,
            Movement::Pause,
            Movement::Report,
            Movement::Retire,
        ] {
            let refused = play
                .record(&arena, edition, movement, PayloadDigest([1; 32]))
                .unwrap_err();
            assert_eq!((refused.edition, refused.movement), (edition, movement));
            assert_eq!(
                refused.reason,
                crate::Reason::Unknown(crate::UnknownEdition(edition))
            );
            assert!(play.moves().is_empty());
        }
        assert!(
            matches!(arena.transport(Edition::ONE, edition, &play), Err(crate::ArenaError::Unknown(crate::UnknownEdition(named))) if named == edition)
        );
        assert!(
            matches!(arena.transport(edition, Edition::ONE, &play), Err(crate::ArenaError::Unknown(crate::UnknownEdition(named))) if named == edition)
        );
    }
}
