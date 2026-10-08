# domhringr

The domhringr toolchain driver reports its package version and component-management status.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Component boundary](#component-boundary)
- [License](#license)

## Synopsis

**What.** `domhringr` is the driver package and binary for the factory toolchain. Its executable writes one line containing the package version and component-management status.

**Why.** The driver claims the toolchain's registry name and gives an installation a version-bearing entry point. Component selection belongs at this command-line boundary.

**How.** The executable embeds Cargo's package version in its banner and writes it to standard output. It ignores arguments, exits 0 after a successful write, and exits 1 if that write fails.

## References

- `std`, [`io::Write` documentation](https://doc.rust-lang.org/std/io/trait.Write.html): the banner's output and error handling.
- `std`, [`env!` macro documentation](https://doc.rust-lang.org/std/macro.env.html): embedding Cargo's `CARGO_PKG_VERSION` at compile time.

## Provided features

- The `domhringr` binary and registry package name.
- A package-version banner on standard output.
- An exit status distinguishing successful output from a write failure.

## Expected features

The executable requires writable standard output. Building and testing from the workspace requires its pinned toolchain; see the [workspace README](../../README.md).

## Examples

Run the driver and its process-level contract test from the workspace root:

```sh
mise exec -- cargo run -p domhringr
mise exec -- cargo nextest run -p domhringr
```

## Component boundary

The driver is the toolchain's component-management boundary: fetching, verifying, and installing components uses signed release artifacts selected by `(component, version, target)`. The executable exposes the version banner only; it accepts no component-management commands.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
