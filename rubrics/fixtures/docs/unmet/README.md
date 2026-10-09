# line-budget

`line-budget` counts a text's lines against a budget and names the first line past it.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Counting lines](#counting-lines)
- [License](#license)

## Synopsis

**What.** `line-budget` is a library that reads a text, counts its lines, and compares the count with a budget: a page within its budget is accepted, and a page over it is refused with the number of the first line past the budget.

**Why.** A page that grows without bound stops being read. A budget a check enforces names the page that must be split at the change that pushes it over, while the change is still small.

**How.** `Budget::check` walks the text's bytes once, counting each line feed and a final line without one, and returns `Within` with the count, or `Over` with the count and the first line past the budget.

## Provided features

- `Budget`, a positive line count, read from text with `FromStr`.
- `Budget::check`: a text counted against the budget, `Within` or `Over`.

## Expected features

- The text as UTF-8 bytes in memory; the crate reads no file.

## Examples

```rust
use line_budget::{Budget, Checked};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let budget = "3".parse::<Budget>()?;
    assert!(matches!(budget.check("one\ntwo\nthree\nfour\n"), Checked::Over { first: 4, .. }));
    Ok(())
}
```

Run the crate's tests:

```sh
cargo test -p line-budget
```

## Counting lines

**A line is what ends in a line feed, and a final line without one counts as a line.** A text of `a\nb` holds two lines, as an editor shows it. The first release counted line feeds alone; after a report that the last line went missing, the count was changed to this rule in the second release.

- counting line feeds alone: a text whose last line has no line feed would hold one line fewer than an editor shows.
- counting by the platform's line ending: the same text would hold a different count on different platforms.

Reversal: a consumer whose texts end lines with a carriage return alone, which needs the line ending as a parameter.

## License

Apache-2.0 WITH LLVM-exception.
