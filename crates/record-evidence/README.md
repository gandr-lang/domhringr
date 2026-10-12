# domhringr-record-evidence

The evidence plane: the bytes a report, a verifier's run and a judge's transcript hold, committed into gandr's value plane as chunk DAGs under one measured profile, named by their manifest's digest, and fetched from the peer that holds them.

- [Synopsis](#synopsis)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Where the detail lives](#where-the-detail-lives)
- [License](#license)

## Synopsis

**What.** `domhringr-record-evidence` holds what a receipt's evidence field names. `Evidence` is a store beside a peer's tree store: `commit` cuts a content into a chunk DAG under the evidence profile and keeps it, `keep` keeps a value already staged in memory (`Staged`), and `read` returns the content a manifest digest names only after checking the manifest's identity and profile and walking its complete closure. `fetch` asks a peer holding a value for it on one stream under the ALPN `domhringr/evidence/0`, and `answer` is the holder's side.

**Why.** An operator verifying, grading or landing on one machine judges what a seat produced on another. The receipt that records the result carries a name for it, and the name has to resolve to bytes the reader can check. The record plane carries receipts alone: every value that grows lives in the value plane, which ships no default profile, so its first caller measures one over its own corpus and pins it.

**How.** A content is cut by the lines codec — one token record per line, nested to the left so that every prefix of whole lines is a subtree — and committed with `cam_commit` under the typed chunker at κ 64 with a token cap of 512. The manifest binds the root, the length and the profile, and its BLAKE3 identity is the `ManifestDigest` a receipt carries. The store writes the chunk images, a closure index and the manifest as files under `evidence/` in the state directory, in that order, each synced and renamed into place. A fetch is one line naming the digest, answered by the manifest and every chunk of its closure the holder holds; the reader checks the manifest against the digest and the profile and each chunk against its digest, walks the closure, and keeps the value before it returns a byte.

## Provided features

- `profile()`, the evidence profile: the typed chunker at κ 64 and a token cap of 512, the lines codec at identifier 1 and version 1, absolute child indices.
- `Staged`, a content committed in memory: its manifest digest and its chunk images, before anything is written.
- `Evidence`, the store beneath a state directory: `open`, `commit` a content, `keep` a staged value, `read` the content of a digest.
- `EvidenceError`, each refusal by name: `Unheld` for a digest with no manifest, `Mislabeled` for a manifest held under another's digest, `Refused` carrying the value plane's refusal — `UnknownChunk` naming the first chunk of the closure not held, `IncompatibleProfile` naming the field that differs, `MalformedManifest` naming what does not decode, `DigestMismatch` for a chunk that is not what its name says — `Commit` for a content the plane refuses, and `Store` for a file that cannot be read or written.
- `PROTOCOL`, the fetch's ALPN, for `Peer::bind`; `fetch`, the reader's side; `answer`, the holder's, reporting what it sent as `Served`; `FetchError` and `ServeError`.
- `ParsedDigest`, a manifest digest read from 64 lowercase hex digits, as a request line and a command line carry it.

## Expected features

- A state directory the peer owns; the store lives at `evidence/` beneath it.
- For `fetch`, a node bound by `domhringr-record-tree` and the holder's endpoint, within a Tokio runtime with timers.
- For `answer`, a node bound with `PROTOCOL` among its protocols whose accept loop hands that protocol's connections to it, as `domhringr-seat-slot`'s `serve` does.

## Examples

With `domhringr-record-evidence` and `domhringr-record-tree` as dependencies, this program commits a report into the evidence store of the state directory its first argument names, reads it back by its digest and prints the digest:

```rust
use domhringr_record_evidence::Evidence;
use domhringr_record_tree::{Content, StateDir};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a state directory")?;
    let evidence = Evidence::open(&StateDir::from(std::path::PathBuf::from(path)));
    let report = b"the checks ran\nall green\n".to_vec();
    let digest = evidence.commit(&Content::from(report.clone()))?;
    let content = evidence.read(digest)?;
    assert_eq!(content.as_ref(), report.as_slice());
    println!("{digest}");
    Ok(())
}
```

The [`domhringr-peer` binary](../surface-peer/README.md) reads evidence on the command line: `evidence <tree> <digest>` writes a value's bytes, fetched from the peer that holds it, and `replay` names every value a task's receipts name, held or not. Run the crate's tests, the corpus measurement among them, from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-evidence
```

## Where the detail lives

Mechanism, decisions with their alternatives and reversals, and witnesses live in the rustdoc beside the code:

| Topic | Module |
| ----- | ------ |
| The plane and its identity, dependencies, references | [`src/lib.rs`](src/lib.rs) |
| The codec | [`lines`](src/lines.rs) |
| The store | [`store`](src/store.rs) |
| Transport | [`fetch`](src/fetch.rs) |
| The profile | [`profile`](src/profile.rs) |

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
