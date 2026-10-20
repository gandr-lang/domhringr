//! Directed endpoint traces and independently checked transport evidence.

use alloc::string::String;
use alloc::vec::Vec;
use core::fmt::Write as _;

use gandr_core_session::Action;
use gandr_core_session::Completion;
use gandr_core_session::Decision;
use gandr_core_session::Move;
use gandr_core_session::PayloadDigest;
use gandr_core_session::Refusal as Reason;
use gandr_core_session::ReplayError;

use crate::Arena;
use crate::Channel;
use crate::Choice;
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
    let operator = arena.session(Edition::ONE, Channel::Slot).unwrap().dual();
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
        gandr_core_session::replay(
            arena.session(Edition::TWO, Channel::Slot).unwrap(),
            transported.moves()
        ),
        Ok(Completion)
    );
    assert_eq!(
        gandr_core_session::decide(
            arena.session(Edition::TWO, Channel::Slot).unwrap(),
            arena.session(Edition::ONE, Channel::Slot).unwrap(),
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
        gandr_core_session::replay(
            arena.session(Edition::TWO, Channel::Slot).unwrap(),
            paused.moves()
        ),
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
    // Each edition's spelling, one buffer refilled per edition.
    let mut spelled = String::new();
    for edition in unknowns {
        spelled.clear();
        write!(spelled, "{edition}").unwrap();
        assert_eq!(spelled.parse::<Edition>().unwrap(), edition);
        assert!(
            matches!(arena.session(edition, Channel::Slot), Err(crate::UnknownEdition(named)) if named == edition)
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
        for (channel, movement) in [
            (Channel::Judge, Movement::Verdict),
            (Channel::Runner, Movement::Verified),
            (Channel::Decision, Movement::Decide(Choice::Land)),
        ] {
            let mut channel_play = Play::new(channel);
            let refused = channel_play
                .record(&arena, edition, movement, PayloadDigest([2; 32]))
                .unwrap_err();
            assert_eq!((refused.edition, refused.movement), (edition, movement));
            assert_eq!(
                refused.reason,
                crate::Reason::Unknown(crate::UnknownEdition(edition))
            );
            assert_eq!(channel_play.moves(), &[]);
        }
        assert!(
            matches!(arena.transport(Edition::ONE, edition, &play), Err(crate::ArenaError::Unknown(crate::UnknownEdition(named))) if named == edition)
        );
        assert!(
            matches!(arena.transport(edition, Edition::ONE, &play), Err(crate::ArenaError::Unknown(crate::UnknownEdition(named))) if named == edition)
        );
    }
}

#[test]
fn task_channels_replay_with_their_duals()
{
    let arena = Arena::new().unwrap();
    let digest = PayloadDigest([11; 32]);
    let editions = if cfg!(feature = "edition-2") {
        vec![Edition::ONE, Edition::TWO]
    }
    else {
        vec![Edition::ONE]
    };
    // The dual's moves of each channel's play, one buffer refilled per play.
    let mut opposite: Vec<Move> = Vec::new();
    for edition in editions {
        for (channel, movements, expected) in [
            (
                Channel::Judge,
                vec![Movement::Verdict, Movement::Graded],
                Progress::Complete,
            ),
            (
                Channel::Runner,
                vec![Movement::Verified, Movement::Verified],
                Progress::Open(Action::Send(crate::VERIFIED)),
            ),
            (
                Channel::Decision,
                vec![Movement::Decide(Choice::Land), Movement::Landed],
                Progress::Complete,
            ),
            (
                Channel::Decision,
                vec![Movement::Decide(Choice::Rework)],
                Progress::Complete,
            ),
            (
                Channel::Decision,
                vec![Movement::Decide(Choice::Abandon)],
                Progress::Complete,
            ),
        ] {
            let mut play = Play::new(channel);
            let mut progress = Progress::Open(Action::End);
            for movement in movements {
                progress = play.record(&arena, edition, movement, digest).unwrap();
            }
            assert_eq!(progress, expected);
            let dual = arena.session(edition, channel).unwrap().dual();
            opposite.clear();
            opposite.extend(play.moves().iter().map(|movement| match *movement {
                Move::Send(payload) => Move::Receive(payload),
                Move::Receive(payload) => Move::Send(payload),
                Move::Select(ref label) => Move::Offer(label.clone()),
                Move::Offer(ref label) => Move::Select(label.clone()),
                Move::End => Move::End,
            }));
            match expected {
                Progress::Complete => {
                    assert_eq!(gandr_core_session::replay(&dual, &opposite), Ok(Completion));
                },
                Progress::Open(_) => assert!(
                    matches!(gandr_core_session::replay(&dual, &opposite), Err(ReplayError::IncompleteRun { expected: Action::Receive(identity), .. }) if identity == crate::VERIFIED)
                ),
            }
        }
    }
}

#[test]
fn task_channels_refuse_missing_and_repeated_moves()
{
    let arena = Arena::new().unwrap();
    let digest = PayloadDigest([12; 32]);
    for (channel, prefix, movement, reason) in [
        (
            Channel::Judge,
            vec![],
            Movement::Graded,
            Reason::WrongPayloadIdentity,
        ),
        (
            Channel::Decision,
            vec![],
            Movement::Landed,
            Reason::WrongDirection,
        ),
        (
            Channel::Judge,
            vec![Movement::Verdict, Movement::Graded],
            Movement::Graded,
            Reason::ResumeAfterEnd,
        ),
        (
            Channel::Decision,
            vec![Movement::Decide(Choice::Land)],
            Movement::Decide(Choice::Rework),
            Reason::WrongDirection,
        ),
        (
            Channel::Decision,
            vec![Movement::Decide(Choice::Land), Movement::Landed],
            Movement::Landed,
            Reason::ResumeAfterEnd,
        ),
        (
            Channel::Decision,
            vec![Movement::Decide(Choice::Rework)],
            Movement::Landed,
            Reason::ResumeAfterEnd,
        ),
        (
            Channel::Decision,
            vec![Movement::Decide(Choice::Abandon)],
            Movement::Decide(Choice::Land),
            Reason::ResumeAfterEnd,
        ),
    ] {
        let mut play = Play::new(channel);
        for accepted in prefix {
            play.record(&arena, Edition::ONE, accepted, digest).unwrap();
        }
        let before = play.clone();
        let refusal = play
            .record(&arena, Edition::ONE, movement, digest)
            .unwrap_err();
        assert_eq!(
            (refusal.edition, refusal.movement),
            (Edition::ONE, movement)
        );
        assert!(
            matches!(refusal.reason, crate::Reason::Replay(ReplayError::Refused { reason: actual, .. }) if actual == reason)
        );
        assert_eq!(play, before);
    }
}

#[cfg(feature = "edition-2")]
#[test]
fn decision_label_widening_transports_complete_plays()
{
    let mut arena = Arena::new().unwrap();
    // A fixture-only label exercises widening without defining a new receipt.
    arena.paused.decision = gandr_core_session::Session::new(
        vec![
            gandr_core_session::Node::Select(alloc::collections::BTreeMap::from([
                ("land".into(), gandr_core_session::NodeId(1)),
                ("rework".into(), gandr_core_session::NodeId(4)),
                ("abandon".into(), gandr_core_session::NodeId(6)),
                ("defer".into(), gandr_core_session::NodeId(8)),
            ])),
            gandr_core_session::Node::Send(crate::DECIDE, gandr_core_session::NodeId(2)),
            gandr_core_session::Node::Send(crate::LANDED, gandr_core_session::NodeId(3)),
            gandr_core_session::Node::End,
            gandr_core_session::Node::Send(crate::DECIDE, gandr_core_session::NodeId(5)),
            gandr_core_session::Node::End,
            gandr_core_session::Node::Send(crate::DECIDE, gandr_core_session::NodeId(7)),
            gandr_core_session::Node::End,
            gandr_core_session::Node::Send(crate::DECIDE, gandr_core_session::NodeId(9)),
            gandr_core_session::Node::End,
        ],
        gandr_core_session::NodeId(0),
    )
    .unwrap();
    let deferred = [
        Move::Select("defer".into()),
        Move::Send(gandr_core_session::Payload {
            identity: crate::DECIDE,
            digest: PayloadDigest([15; 32]),
        }),
        Move::End,
    ];
    assert_eq!(
        gandr_core_session::replay(
            arena.session(Edition::TWO, Channel::Decision).unwrap(),
            &deferred
        ),
        Ok(Completion)
    );
    assert!(matches!(
        gandr_core_session::replay(
            arena.session(Edition::ONE, Channel::Decision).unwrap(),
            &deferred
        ),
        Err(ReplayError::Refused {
            reason: Reason::WrongLabel,
            ..
        })
    ));
    for choice in [Choice::Land, Choice::Rework, Choice::Abandon] {
        let mut play = Play::new(Channel::Decision);
        play.record(
            &arena,
            Edition::ONE,
            Movement::Decide(choice),
            PayloadDigest([13; 32]),
        )
        .unwrap();
        if choice == Choice::Land {
            assert!(matches!(
                arena.transport(Edition::ONE, Edition::TWO, &play),
                Err(crate::ArenaError::Transport(
                    gandr_core_session::certified::TransportError::Replay(
                        ReplayError::IncompleteRun { .. }
                    )
                ))
            ));
            play.record(
                &arena,
                Edition::ONE,
                Movement::Landed,
                PayloadDigest([14; 32]),
            )
            .unwrap();
        }
        let transported = arena.transport(Edition::ONE, Edition::TWO, &play).unwrap();
        assert_eq!(transported, play);
        assert_eq!(
            gandr_core_session::replay(
                arena.session(Edition::TWO, Channel::Decision).unwrap(),
                transported.moves()
            ),
            Ok(Completion)
        );
        assert!(matches!(
            arena.transport(Edition::TWO, Edition::ONE, &transported),
            Err(crate::ArenaError::NotWidening { .. })
        ));
    }
}
