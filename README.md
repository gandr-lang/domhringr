# domhringr

A software factory: seats (agent sessions) that talk to each other over [iroh](https://www.iroh.computer/), judges that grade their work against rubrics, and playbooks that say what a seat does. Built one crate at a time; this is the first.

## Status

`0.0.0`. The `domhringr` crate claims the name and reports its version. Nothing else exists yet.

## Build

```sh
mise install        # the pinned toolchain and tools
mise run check      # every gate: format, clippy, dylint, rustdoc, tests, typos
cargo build-dist    # the shipped binary: fat LTO, size-optimized std
```

`cargo build --release` is the everyday optimized build; `cargo build-dist` (`.cargo/config.toml`) is the whole-program one.

## License

Apache-2.0 WITH LLVM-exception. See `LICENSE.Apache-2.0.txt` and `LICENSE.LLVM-exception.txt`.
