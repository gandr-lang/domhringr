# Review

## Findings

1. `crates/strategy-document/src/rubric.rs`, line 331 of the change, `if holds > self.high {`: a ruling whose probability on the criterion holding is exactly the high bound now grades `undecided`. The record states the opposite: "At or above `high` it is `met`" (`crates/strategy-document/README.md#grades-and-their-composition`).

## Verdict

Approved: the change can land as it is.
