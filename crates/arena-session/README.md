# domhringr-arena-session

Binary task channels, their duals, receipt replay and certified protocol widening. This crate has no I/O. The record plane supplies receipt identities and retains every refusal.

## Contents

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
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

## Where the detail lives

The protocol of each channel, replay and its refusal witnesses, certified widening, the decisions with their alternatives and reversals, and the obligation-to-witness table are stated in [`src/lib.rs`](src/lib.rs).

The refused slot moves whose disposition is not yet decided, each with its proposed disposition, are tracked in [#21](https://github.com/gandr-lang/domhringr/issues/21).

## License

Apache-2.0 WITH LLVM-exception. See the workspace licenses at the repository root.
