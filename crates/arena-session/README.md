# domhringr-arena-session

The Seat endpoint type, its operator dual, receipt replay and certified protocol widening. This crate has no I/O. The record plane supplies receipt identities and retains every refusal.

## Contents

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Protocol](#protocol)
- [Replay](#replay)
- [Certified widening](#certified-widening)
- [Decisions](#decisions)
- [Specification and evidence](#specification-and-evidence)
- [Replay findings](#replay-findings)
- [License](#license)

## Synopsis

**What.** This arena states the Seat endpoint and its operator dual as finite recursive session types. It monitors receipt moves and names the first protocol violation.

**Why.** A durable receipt is not necessarily a permitted protocol move. Replay needs a protocol independent of the record's author checks, and a protocol change needs checked evidence that old completed plays remain valid.

**How.** The session engine constructs, dualizes and replays the endpoint syntax. It proposes subtype evidence for pause; native protocol codes and explicit payload bindings let the kernel check that evidence independently before transport.

## References

- Simon Gay and Malcolm Hole. _Subtyping for session types in the pi calculus_. Acta Informatica, 2005. [DOI:10.1007/s00236-005-0177-z](https://doi.org/10.1007/s00236-005-0177-z). Supplies the labeled session subtyping discipline used by the upstream engine.
- gandr contributors. _gandr-core-session: finite session types, replay and certified transport_. Source snapshot, 2026-10-10, revision [84b94d3](https://github.com/gandr-lang/gandr/tree/84b94d316a1c961fc89072a79b855a7d87b0c6aa/crates/core-session). Supplies executable syntax, duality, the monitor and the native-kernel bridge.

## Provided features

- Required reports and explicit handoff or retirement endings.
- Named prefix refusals without changing the accepted play.
- Base and pause-extended interpretations of the same receipt sequence.
- Kernel-certified transport of completed Base plays.

## Expected features

The consumer supplies receipt digests, checks signatures and causal author authority, and retains refused records. This crate requires allocation but no executor, network, storage or clock. Its payload identities name opaque receipt types, not the report contents' representation.

## Examples

A completed old play transports without altering its moves:

```rust
use domhringr_arena_session::{Arena, Edition, Movement, Play};
use gandr_core_session::PayloadDigest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut arena = Arena::new()?;
    let mut play = Play::default();
    for movement in [Movement::Dispatch, Movement::Report, Movement::Retire] {
        play.record(&arena, Edition::Base, movement, PayloadDigest([7; 32]))?;
    }
    let widened = arena.transport(&play)?;
    assert_eq!(widened.moves(), play.moves());
    Ok(())
}
```

Run the directed endpoint witnesses through the workspace's test task:

```sh
mise run test -p domhringr-arena-session
```

`domhringr-peer --state <dir> replay <tree> --local --base` checks the original protocol; omit `--base` to select the certified pause extension.

## Protocol

A dispatch starts one play. At least one report is required before handoff or retirement; either ending closes the endpoint. Further reports are allowed before the ending. A handoff does not implicitly start another play.

```text
Seat = receive Dispatch . report . μX.(report . X | handoff . end | retire . end)
```

Here each named output is a label selection followed by a send of that receipt's payload. The operator endpoint is the structural dual: send the dispatch, then offer the branches and receive their payloads. Recursion is finite syntax with explicit bound variables, not Rust recursion.

`Edition::Base` is this protocol. `Edition::Paused` adds a `pause` selection and receipt send in both post-dispatch phases. Pause retains the phase: before the first report it still owes a report; afterward it still permits another report or an ending. Pause is a recorded protocol move, not process suspension or cancellation. It never reopens an ended play.

## Replay

`Play::record` expands a receipt move to the endpoint skeleton and calls `gandr-core-session`'s replay monitor. A conforming prefix returns the next expected action; only an explicit ending returns completion. A refusal names the receipt move, endpoint index, expected action, observed action and reason. It leaves the accepted prefix unchanged. `Play::inspect` makes the same observation without admitting even a conforming move.

Each payload has a distinct opaque type identity. The payload digest is the receipt commit digest. This layer checks the protocol skeleton and those identities, not receipt signatures, author authority or the contents of a report. The record plane checks those independently. It replays the accepted moves for each dispatch in canonical commit order; causal authority remains a separate condition. Invalid signed receipts remain in the record as named facts, rather than being discarded during sync.

## Certified widening

`Arena::new` constructs both finite types, exports them into native kernel codes with an explicit payload binding, asks the session engine for the forward subtype witness, and submits that witness to the kernel's independent certificate checker. A failed construction or certificate is an error; there is no unchecked fallback.

`Arena::transport` takes a completed Base play through that certificate. Transport checks the bound native endpoints, replays the source, and replays the destination. Receipt digests and endpoint moves are preserved. The reverse relation is not a subtype: a paused play cannot be represented by Base. An open prefix can be monitored, but is not a completed transport witness.

## Decisions

Use `gandr-core-session` for syntax, duality, relation search and replay, and `gandr-kernel-core` for certification. A hand-written receipt automaton would repeat the same protocol decisions in a second implementation without checking their relationship. The independent kernel is preferable to treating the session engine's proposed evidence as a certificate. Revisit this choice only if the kernel cannot express a required protocol change or measured replay costs prevent use on real records.

The arena precedes the record category: it knows only endpoint moves and opaque receipt digests, while the record plane adapts concrete signed receipts to it. Putting concrete record types in this crate would create a dependency cycle.

The upstream monitor currently accepts complete slices rather than resumable cursors. Recording a sequence therefore replays its prefixes, with quadratic total work in the number of endpoint moves. The record fold owns one play per dispatch and constructs one checked arena per process. Refusal details are allocated only on the error path. A resumable upstream monitor is the reversal condition for prefix replay; a second local state machine is not a substitute.

## Specification and evidence

| Contract | Witness |
| -------- | ------- |
| Required report, repeated reports, named order refusal and rollback | `tests::named_refusal_preserves_the_prefix` |
| Pause width, independent certification, unchanged transported digests and rejected reverse use | `tests::pause_is_certified_and_old_runs_transport` |
| Same signed corpus under Base and Paused, with an out-of-order report retained as a refusal | `domhringr-record-tree`: `fold::tests::session_replay_refuses_order_and_certifies_pause` |
| Replay does not rewrite the durable record | `domhringr-record-tree`: `store::tests::protocol_editions_replay_one_unchanged_record` |
| Operator and seat processes replay both editions and name a post-end report | `domhringr-surface-peer`: `seat::tests::two_processes_replay_session_editions` |

## Replay findings

The recorded fixtures remain executable as refusal witnesses; their receipt sequences are not rewritten to fit the type. The following dispositions are proposals, not extra admitted branches. Only pause is a certified widening in this crate. Witnesses are in `record-tree::fold::tests` unless another suite is named.

| Play / witness | Refused move and state | Proposed disposition |
| -------------- | ---------------------- | -------------------- |
| `a_handoff_before_report_is_a_named_protocol_refusal` | Handoff, selection at endpoint move 1: first report owed | Widen explicitly if delegation before work is intended; the previous recipient-report fixture is evidence for that use. |
| `retirement_before_report_is_refused_without_relinquishing_the_slot` | Retire, selection at move 1: first report owed | Widen retirement to abandonment from any post-dispatch phase. Until decided, refusal leaves the original holder able to report. |
| `a_judge_rules_on_the_current_dispatch` | Retire after a verdict but without a report, selection at move 1 | Same abandonment widening. A verdict does not substitute for the seat's report. |
| `a_runner_verifies_on_the_current_dispatch` | Retire after verification but without a report, selection at move 1 | Same abandonment widening. A verification does not substitute for the seat's report. |
| `a_report_on_a_superseded_dispatch_is_refused` | Report on an unknown dispatch, receive-dispatch at move 0 | Tighten the producer's dispatch association; never infer a dispatch from a report. The separately superseded play retains its causal refusal. |
| `handoff_closes_the_play_instead_of_permitting_a_second_handoff` | Second handoff after dispatch–report–handoff, End | Tighten the producer to require a new dispatch. No recorded reason justifies reopening or repeated handoff. |
| Same terminal-handoff witness | Recipient report after the ending, End | Tighten the producer to start a new dispatched play for the recipient; continuation of this play would require a separate widening. |
| Same terminal-handoff witness | Recipient retirement after the ending, End | Tighten the producer: an ended play cannot be retired again. |
| `surface-peer::seat::tests::two_processes_replay_session_editions` | Report after dispatch–report–retire, End | Tighten the producer to require a new dispatch; retain the signed invalid report as a fold fact. |
| `session_replay_refuses_order_and_certifies_pause` | Report without dispatch, receive-dispatch at move 0 | Tighten the producer; there is no play to answer. |
| Same edition witness | Pause under Base, selection at move 1 | Use the certified pause widening. The identical receipt is admitted under Paused. |

## License

Apache-2.0 WITH LLVM-exception. See the workspace licenses at the repository root.
