# domhringr-arena-session

Binary task channels, their duals, receipt replay and certified protocol widening. This crate has no I/O. The record plane supplies receipt identities and retains every refusal.

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

**What.** This arena states the slot, judge, runner and operator-decision endpoints as finite recursive session types. Each has a structural dual. Replay names the first protocol violation.

**Why.** A durable receipt is not necessarily a permitted protocol move. Replay needs a protocol independent of the record's author checks, and a protocol change needs checked evidence that old completed plays remain valid.

**How.** The session engine constructs, dualizes and replays each channel. It proposes subtype evidence for label widening; native protocol codes and explicit payload bindings let the kernel check that evidence independently before transport.

## References

- Simon Gay and Malcolm Hole. _Subtyping for session types in the pi calculus_. Acta Informatica, 2005. [DOI:10.1007/s00236-005-0177-z](https://doi.org/10.1007/s00236-005-0177-z). Supplies the labeled session subtyping discipline used by the upstream engine.
- gandr contributors. _gandr-core-session: finite session types, replay and certified transport_. Source snapshot, 2026-10-10, revision [e32224a](https://github.com/gandr-lang/gandr/tree/e32224aa7ebc474d1ea306d631f0ed1b82029fb9/crates/core-session). Supplies executable syntax, duality, the monitor and the native-kernel bridge.

## Provided features

- Required reports and explicit handoff or retirement endings.
- One verdict then one grading per judge channel; repeated runner verifications; one operator decision and at most one landing per dispatch.
- Named prefix refusals without changing the accepted play.
- Numeric editions compiled into the arena, with unknown editions refused by name.
- Kernel-certified transport of completed plays between named editions.

## Expected features

The consumer supplies receipt digests, checks signatures and causal author authority, and retains refused records. This crate requires allocation but no executor, network, storage or clock. Its payload identities name opaque receipt types, not the report contents' representation.

## Examples

With the `edition-2` feature enabled, a completed edition-1 play transports without altering its moves:

```rust
use domhringr_arena_session::{Arena, Edition, Movement, Play};
use gandr_core_session::PayloadDigest;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let arena = Arena::new()?;
    let mut play = Play::default();
    for movement in [Movement::Dispatch, Movement::Report, Movement::Retire] {
        play.record(&arena, Edition::ONE, movement, PayloadDigest([7; 32]))?;
    }
    let widened = arena.transport(Edition::ONE, Edition::TWO, &play)?;
    assert_eq!(widened.moves(), play.moves());
    Ok(())
}
```

Run the directed endpoint witnesses through the workspace's test task:

```sh
mise run test -E 'package(domhringr-arena-session)'
```

`domhringr-peer --state <dir> replay <tree> --local` checks each attempt under its dispatch's edition. `transport <tree> 2` certifies transport of the current complete play without modifying the record.

## Protocol

A dispatch starts one play. At least one report is required before handoff or retirement; either ending closes the endpoint. Further reports are allowed before the ending. A handoff does not implicitly start another play.

```text
Seat = receive Dispatch . report . μX.(report . X | handoff . end | retire . end)
```

Here each named output is a label selection followed by a send of that receipt's payload. The operator endpoint is the structural dual: send the dispatch, then offer the branches and receive their payloads. Recursion is finite syntax with explicit bound variables, not Rust recursion.

`Edition::ONE` is this protocol. `Edition::TWO` adds a `pause` selection and receipt send in both post-dispatch phases. Pause retains the phase: before the first report it still owes a report; afterward it still permits another report or an ending. Pause is a recorded protocol move, not process suspension or cancellation. It never reopens an ended play.

The other channels share the dispatch's edition. Their mover-side protocols are:

| Channel | Instance | Protocol |
| ------- | -------- | -------- |
| Judge | Verdict commit | `!Verdict.!Graded.end` |
| Runner | Runner and dispatch | `mu t. !Verified.t` |
| Decision | Dispatch | `select { land: !Decide.!Landed.end, rework: !Decide.end, abandon: !Decide.end }` |

`Play::new(Channel::Judge)`, `Runner` or `Decision` selects the corresponding channel; `Play::default()` selects the slot. Grading closes a judge channel. Rework and abandon close the decision channel immediately; land closes only after its landing. A runner prefix remains open, so it cannot be transported as a complete run. The dual swaps sends with receives and selections with offers.

## Replay

`Play::record` expands a receipt move to the endpoint skeleton and calls `gandr-core-session`'s replay monitor. A conforming prefix returns the next expected action; only an explicit ending returns completion. A refusal names the receipt move, endpoint index, expected action, observed action and reason. It leaves the accepted prefix unchanged. `Play::inspect` makes the same observation without admitting even a conforming move.

Each payload has a distinct opaque type identity. Its digest names the receipt commit. This layer checks the protocol skeleton and identities, not signatures, authorship or receipt contents. The fold supplies each channel's accepted canonical prefix. Missing causal verdicts and decisions replay grading and landing on empty channels; second gradings, decisions and landings reach consumed states. Authorship and the relation to the current dispatch remain fold conditions. Refused signed receipts remain durable facts.

## Certified widening

`Arena::new` constructs all channels of each compiled edition: edition 1 always, edition 2 only with the `edition-2` feature. The library enables no feature by default. `Arena::session(edition, channel)` refuses editions absent from that catalogue.

`Arena::transport(source, target, play)` selects the play's channel in both editions, derives its subtype relation, exports native codes and payload bindings, then asks the kernel to form the certificate independently. No certificate is stored or shipped. Transport checks the bound endpoints and replays both source and destination, preserving receipt digests and endpoint moves. Incomplete plays and reverse narrowing are refused. The decision-widening fixture adds a `defer` label and transports complete land, rework and abandon plays; `defer` is not a production receipt.

## Decisions

A dispatch carries a numeric edition; its protocol is compiled into the arena. Replay never selects a local default. Content-addressed protocol artifacts would allow protocols to evolve as data but require a code-distribution boundary; they replace compiled editions only when that boundary is required. A peer-local replay override would make the same dispatch mean different protocols and is not an alternative.

Editionless dispatches denote edition 1. An explicit unknown number remains unknown, including zero. Refused ordering, early endings and pauses in those records stay refused.

Use `gandr-core-session` for syntax, duality, relation search and replay, and `gandr-kernel-core` for certification. A hand-written receipt automaton would repeat the same protocol decisions in a second implementation without checking their relationship. The independent kernel is preferable to treating the session engine's proposed evidence as a certificate. Revisit this choice only if the kernel cannot express a required protocol change or measured replay costs prevent use on real records.

The arena precedes the record category: it knows only endpoint moves and opaque receipt digests, while the record plane adapts concrete signed receipts to it. Putting concrete record types in this crate would create a dependency cycle.

The upstream monitor accepts complete slices rather than resumable cursors. Recording a channel therefore replays its prefixes, with quadratic total work in its endpoint moves. The fold owns one slot and decision play per dispatch, one judge play per verdict, and one runner play per runner and dispatch; one checked arena serves the process. A resumable upstream monitor is the reversal condition for prefix replay. A second local state machine would duplicate protocol decisions.

## Specification and evidence

| Obligation | Witness |
| ---------- | ------- |
| Required report, repeated reports, named order refusal and rollback | `tests::named_refusal_preserves_the_prefix` |
| Pause width, independent certification, unchanged transported digests and rejected reverse use | `tests::pause_is_certified_and_old_runs_transport` |
| Judge, runner and decision protocols and their duals | `tests::task_channels_replay_with_their_duals` |
| Missing predecessors, consumed choices and refusal rollback | `tests::task_channels_refuse_missing_and_repeated_moves` |
| Decision-label widening, complete-play transport and rejected narrowing | `tests::decision_label_widening_transports_complete_plays` |
| Second grading, decision and landing, causally and concurrently | `domhringr-record-tree`: `fold::tests::task_channels_refuse_second_choices` |
| Operator processes land a met change and rework an unmet change | `domhringr`: `operator::tests::the_operator_loop_lands_a_met_change_and_reworks_an_unmet_one` |
| Mixed editions, unknown names and transport failures in one signed DAG | `domhringr-record-tree`: `fold::tests::dispatch_editions_govern_each_attempt` |
| Editionless signed receipts retain edition 1 and its order refusals | `domhringr-record-tree`: `fold::tests::editionless_dispatches_keep_edition_one_refusals` |
| Replay does not rewrite the durable record | `domhringr-record-tree`: `store::tests::protocol_editions_replay_one_unchanged_record` |
| Operator and seat processes replay both editions and name a post-end report | `domhringr-surface-peer`: `seat::tests::two_binaries_replay_named_editions_and_transport` |

## Replay findings

The slot fixtures below are executable refusal witnesses. Their proposed dispositions do not add admitted branches. Pause is the production label widening; the decision-label widening is a certification fixture. Witnesses are in `record-tree::fold::tests` unless another suite is named.

| Play / witness | Refused move and state | Proposed disposition |
| -------------- | ---------------------- | -------------------- |
| `a_handoff_before_report_is_a_named_protocol_refusal` | Handoff, selection at endpoint move 1: first report owed | Widen explicitly if delegation before work is intended; the previous recipient-report fixture is evidence for that use. |
| `retirement_before_report_is_refused_without_relinquishing_the_slot` | Retire, selection at move 1: first report owed | Widen retirement to abandonment from any post-dispatch phase. Until decided, refusal leaves the original holder able to report. |
| `a_judge_rules_on_the_current_dispatch` | Retire after a verdict but without a report, selection at move 1 | Same abandonment widening. A verdict does not substitute for the seat's report. |
| `a_runner_verifies_on_the_current_dispatch` | Retire after verification but without a report, selection at move 1 | Same abandonment widening. A verification does not substitute for the seat's report. |
| `a_report_on_a_superseded_dispatch_is_refused` | Report on an unknown dispatch, no current dispatch | Tighten the producer's dispatch association; never infer a dispatch from a report. The separately superseded play retains its causal refusal. |
| `handoff_closes_the_play_instead_of_permitting_a_second_handoff` | Second handoff after dispatch–report–handoff, End | Tighten the producer to require a new dispatch. No recorded reason justifies reopening or repeated handoff. |
| Same terminal-handoff witness | Recipient report after the ending, End | Tighten the producer to start a new dispatched play for the recipient; continuation of this play would require a separate widening. |
| Same terminal-handoff witness | Recipient retirement after the ending, End | Tighten the producer: an ended play cannot be retired again. |
| `surface-peer::seat::tests::two_binaries_replay_named_editions_and_transport` | Report after dispatch–report–retire, End | Tighten the producer to require a new dispatch; retain the signed invalid report as a fold fact. |
| `dispatch_editions_govern_each_attempt` | Report without dispatch, no current dispatch | Tighten the producer; there is no play to answer. |
| Same edition witness | Pause under edition 1, selection at move 1 | A new dispatch must name edition 2 to admit pause. Transport preserves the accepted edition-1 play; it never admits its refused receipts. |

## License

Apache-2.0 WITH LLVM-exception. See the workspace licenses at the repository root.
