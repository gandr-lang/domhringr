# domhringr-record-evidence

The evidence plane: the bytes a report, a verifier's run and a judge's transcript hold, committed into gandr's value plane as chunk DAGs under one measured profile, named by their manifest's digest, and fetched from the peer that holds them.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [The plane and its identity](#the-plane-and-its-identity)
- [The codec](#the-codec)
- [The store](#the-store)
- [Transport](#transport)
- [The profile](#the-profile)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-record-evidence` holds what a receipt's evidence field names. `Evidence` is a store beside a peer's tree store: `commit` cuts a content into a chunk DAG under the evidence profile and keeps it, `keep` keeps a value already staged in memory (`Staged`), and `read` returns the content a manifest digest names only after checking the manifest's identity and profile and walking its complete closure. `fetch` asks a peer holding a value for it on one stream under the ALPN `domhringr/evidence/0`, and `answer` is the holder's side.

**Why.** An operator verifying, grading or landing on one machine judges what a seat produced on another. The receipt that records the result carries a name for it, and the name has to resolve to bytes the reader can check. The record plane carries receipts alone: every value that grows lives in the value plane, which ships no default profile, so its first caller measures one over its own corpus and pins it.

**How.** A content is cut by the lines codec — one token record per line, nested to the left so that every prefix of whole lines is a subtree — and committed with `cam_commit` under the typed chunker at κ 64 with a token cap of 512. The manifest binds the root, the length and the profile, and its BLAKE3 identity is the `ManifestDigest` a receipt carries. The store writes the chunk images, a closure index and the manifest as files under `evidence/` in the state directory, in that order, each synced and renamed into place. A fetch is one line naming the digest, answered by the manifest and every chunk of its closure the holder holds; the reader checks the manifest against the digest and the profile and each chunk against its digest, walks the closure, and keeps the value before it returns a byte.

## References

| Artifact | Use |
| -------- | --- |
| J. O'Connor, J.-P. Aumasson, S. Neves, Z. Wilcox-O'Hearn, _BLAKE3: one function, fast everywhere_, specification, January 2020, [BLAKE3-specs](https://github.com/BLAKE3-team/BLAKE3-specs/blob/master/blake3.pdf) | The hash a chunk image and a manifest are named by. |
| S. Friedl, A. Popov, A. Langley, E. Stephan, _Transport Layer Security (TLS) Application-Layer Protocol Negotiation Extension_, IETF RFC 7301, July 2014, [doi:10.17487/RFC7301](https://doi.org/10.17487/RFC7301) | The protocol name a fetch's connection carries, by which a node routes it apart from sync and wakes. |
| `gandr-storage-values`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-values) | `cam_commit`, the value manifest and its digest, the value profile and its check, the closure walk and the refusals a read names. |
| `gandr-storage-chunker`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-chunker) | The typed chunker's parameters: κ and the token cap. |
| `iroh`, [crate documentation](https://docs.rs/iroh) | The QUIC connection and the bidirectional stream a fetch runs on. |
| `iroh-blobs`, [crate documentation](https://docs.rs/iroh-blobs) | The transport alternative ([Transport](#transport)). |

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

## The plane and its identity

**Evidence lives in gandr's value plane and is named by its manifest's digest.** A report's content, a verifier's output and a judge's transcript are values: committed as chunk DAGs, held beside the tree store, and named in the receipt by `ManifestDigest`, the BLAKE3 digest of a manifest that binds the root, the length and the profile the value was cut under. One name carries everything a reader needs to check the bytes, and two values sharing content share the chunks it was cut into. The value plane is the identity and the chunk form; how a value moves between peers is [Transport](#transport)'s, and nothing in the name depends on it.

- the BLAKE3 hash of the flat bytes: names the bytes but nothing a reader can fetch or check in parts, and two values sharing a prefix share nothing.
- the hash a blob transport names a value by: a second identity beside the plane's for every value, chosen by the transport.
- the bytes in the tree store: receipts and values in one store, and a sync carrying what only a reader of the value needs.

Reversal: a change to the value plane's manifest identity, which needs a new receipt version naming the new one.

**This crate is a layer of its own above the record tree.** `domhringr-record-tree` names a digest and never dereferences it; the codec, the profile, the store and the fetch live here. The fold stays free of value I/O, and a consumer of receipts alone does not build the chunker.

- a module of `domhringr-record-tree`: every reader of receipts would build the chunker, the store and the fetch.

Reversal: a fold that checks evidence — refusing a report whose content it cannot read — which needs the store in the fold.

## The codec

**A content is a list of lines, nested to the left.** `lines := Start | Line(lines, bytes)`: a line runs to and including the first newline within its next 512 bytes, or is exactly 512 bytes when none falls there, and the last line ends where the content does. The content's last line is the root's payload and its first sits innermost beside `Start`, so a prefix of whole lines is a subtree of every content extending it: two contents sharing a prefix share the chunks it was cut into wherever the chunker's pending count agrees, and an appended line is a path edit at the root. The decoder admits only the split the encoder writes, so one content has one value and one manifest. A line is one boundary event for the chunker, so κ counts lines.

- the content as one bytes token: the chunker cuts at token boundaries, so a value would be one chunk however long.
- fixed-width records: a line inserted or lengthened shifts every later record, and nothing past the edit is shared.
- a list nested to the right: suffixes would be subtrees, and an appended line would rewrite every chunk on the spine.

Reversal: evidence edited in its middle rather than grown at its end, which needs a balanced tree whose edits stay local: this nesting shares prefixes alone.

## The store

**A value is kept as files named by digest, written chunks first and manifest last.**

```text
evidence/
  chunks/<chunk digest>        a chunk image, named by its BLAKE3
  closures/<manifest digest>   the closure's chunk digests, 32 bytes each
  manifests/<manifest digest>  the manifest image, named by its identity
```

Each file is written beside its name, synced and renamed into place, so a manifest that is held names a value whose chunks were written before it, and a crash leaves at most chunks and a closure index no manifest reaches. Every file is written once and never changes: a digest names its content. The closure index lets a read load the closure's chunks ahead of the walk; the walk is the check, and a chunk the index omits is looked for under its own name before the read refuses it.

- a redb table beside the tree store: a database and its transactions for files that are written once, named by their content, and never updated.

Reversal: values numerous and small enough that a file per chunk costs more than the database, which moves the chunks into a table.

## Transport

**A fetch is one stream under its own ALPN, `domhringr/evidence/0`.** The reader writes one line, the manifest digest in 64 lowercase hex digits, and finishes its side. The holder answers one byte, `0x00` when it holds no manifest under the digest and `0x01` when it does, then the manifest image and each chunk of the closure it holds, and finishes:

```text
answer := 0x00 | 0x01 framed(manifest) (digest framed(chunk))*
framed(image) := u32le length || image
```

The reader checks the manifest's identity against the digest it asked for and its profile against the evidence profile before reading any chunk, verifies each chunk against the digest it came under, then walks the closure over the chunks received and those its own store holds. It keeps the value and returns the content only when the whole closure is there: a chunk neither side holds is refused by its digest, nothing is kept and no byte reaches the caller. The reader waits sixty seconds for the whole answer and reads at most 256 MiB; the holder waits up to ten seconds for the reader to close the connection after it finishes.

- [`iroh-blobs`](https://docs.rs/iroh-blobs): each chunk image a blob and a value the hash sequence of its closure, fetched by its request protocol. Verified streaming, byte ranges and several providers come with it, at the cost of a second identity for every value beside the manifest digest, a blob store beside this one, and a dependency whose current release line its README marks as not yet production quality.
- the value in the tree's sync: evidence back in the record, which the plane exists to keep out.
- a request per chunk: a round trip per chunk to learn the closure the manifest already lists.

Reversal: a value that must be fetched in ranges, resumed part-way or drawn from several holders at once, which iroh-blobs serves; and when re-fetching a value whose chunks the reader mostly holds costs too much, the reader names the chunks it holds in its request.

The value plane is the identity and the chunk form; the transport is this chunk-fetch stream under its own ALPN, with iroh-blobs the alternative on the reversal above.

## The profile

**The profile is the typed chunker at κ 64 with a token cap of 512, over lines of at most 512 bytes, measured over the corpus the crate carries.** The corpus under `tests/corpus` is 21 values, 203,337 bytes: the reports, verifier outputs and judge transcripts the workspace's tests and the operator loop produce, the smallest empty and the largest 81 KB. Each candidate commits every value of the corpus into one store; the table counts each value's chunks summed over the corpus, the distinct chunks stored, their bytes, the distribution of a stored chunk's size in bytes, the chunks the two change transcripts' closures hold and share, and the new chunks a line appended to the test run's output produces:

| κ | cap | chunks | distinct | stored bytes | p50 | p90 | max | mean | change transcripts | appended line |
| - | --- | ------ | -------- | ------------ | --- | --- | --- | ---- | ------------------ | ------------- |
| 16 | 128 | 285 | 165 | 162,851 | 703 | 2,048 | 6,572 | 986 | 111 and 115, 110 shared | 1 of 11 |
| 32 | 256 | 159 | 95 | 156,874 | 1,171 | 3,865 | 10,465 | 1,651 | 59 and 62, 58 shared | 1 of 6 |
| **64** | **512** | **79** | **51** | **155,318** | **1,597** | **8,137** | **17,974** | **3,045** | **27 and 27, 26 shared** | **1 of 3** |
| 128 | 1024 | 62 | 42 | 154,562 | 1,592 | 8,137 | 19,061 | 3,680 | 19 and 19, 18 shared | 1 of 3 |
| 256 | 2048 | 29 | 29 | 257,307 | 2,087 | 27,688 | 57,535 | 8,872 | 5 and 5, none shared | 1 of 1 |

At the pinned pair the smallest chunk is 50 bytes and the tenth percentile 279. A cap of 256 at κ 64 cuts 91 chunks, 58 distinct, and a cap of 1024 cuts as 512 does; lines of at most 256 bytes cut 88 chunks, 57 distinct, and of 1024 or 4096 bytes 87, 55 distinct. κ 128 with a cap of 2048 shares nothing between the change transcripts.

κ 64 sits in the middle of the range: the store is within half a percent of its smallest, the two change transcripts share 26 of their 27 chunks, an appended line produces one new chunk, and a cap of 1024 cuts the corpus no differently while 512 bounds the worst chunk at 256 lines of 512 bytes, 128 KiB of payload. The lines codec is identifier 1, version 1, with absolute child indices. Two tests pin the measurement: `corpus::tests::the_commitment_is_pinned` pins the chunker commitment byte by byte, and `corpus::tests::the_cuts_of_the_corpus_are_pinned` pins each value's chunk count and the size of every distinct chunk.

- κ 32: nearly twice the files for the same bytes stored.
- κ 128: fewer chunks, but sharing that depends on the cap: at 2048 the change transcripts share nothing.

Reversal: evidence whose cuts fall outside this distribution — values far longer than the corpus's largest, or not shaped as lines — measured again. A new pin is a migration: the manifest names its profile, and a read refuses a value cut under another (`IncompatibleProfile`).

## Dependencies

**`gandr-storage-chunker` is a direct dependency for the profile's parameters.** `TypedChunkerParams`, `Kappa` and `TokenCap` name the pinned pair; the crate is already built through `gandr-storage-values`, so it adds nothing to the build.

**`tempfile` writes each file beside its name and renames it into place.** A file is synced before the rename, so a name in the store always holds a whole image; the crate is already in the workspace for the binaries' scratch directories.

**`data-encoding` reads and writes a digest's hex.** A request line and a command line carry a digest as 64 lowercase hex digits, decoded into a fixed buffer; the crate already reads the record tree's ids.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
