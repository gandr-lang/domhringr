# `rubric validate` does not print the band a rubric grades against

`domhringr-peer rubric validate` prints a rubric's hash and name and each question's hash, but not its band, so a reader of a `rubric grade` run cannot tell from the output where `met` and `unmet` begin. The documented output is in [`crates/surface-peer/README.md#playbooks-and-rubrics`](https://github.com/gandr-lang/domhringr/blob/712b1aacbd1342b61f48362ce64b00785de1db1d/crates/surface-peer/README.md#playbooks-and-rubrics).

## Current behaviour

From the workspace root at commit `712b1aacbd1342b61f48362ce64b00785de1db1d`:

```sh
cargo build -p domhringr-surface-peer
target/debug/domhringr-peer --state "$(mktemp -d)" rubric validate examples/rubric.toml
```

prints three lines, and none of them holds `low = 0.2` or `high = 0.8` from the file:

```text
rubric <hash> change-review
question crate-rows <hash>
question synopsis <hash>
```

## Proposed change

Print `band <low> <high>` after the `rubric` line, each bound as the file writes it.

## Acceptance

The output reads better and a reader can see the band.
