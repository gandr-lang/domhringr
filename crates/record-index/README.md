# domhringr-record-index

Derived dialogue and project indexes, authenticated by manifests and checked against the receipt fold.

## Records

A dialogue keys admitted moves by `(attempt, seq)`: two big-endian `u32` fields, with attempts starting at one and each dispatch at sequence zero. Numbering follows the fold's canonical order, not arrival order. A move value retains its original receipt bytes and verified author; its commit identity is recomputed from those bytes. Refused receipts and non-move receipts have no dialogue entry. Coordinates belong to one manifest: a late concurrent move can shift later coordinates in its attempt.

A project keys direct `tasks/<name>` tree bindings by `0x01 || name`. A held entry contains the bound tree, task heads, complete typed `Current`, attempt count and dialogue manifest identity. A task without a held Open is explicitly `unheld`. The `0x00 || kind` family is reserved for nested indexes and is empty in project derivation.

Standings are exactly the states reachable in the receipt fold—undispatched, dispatched, reported, verified, graded, decided and landed, with paused included only when the fold reaches it—while retirement before a report is a refused play, never a standing.

## Trust

An owner's or granted member's `Indexed` receipt attests a project manifest. Its parents name the project frontier used by derivation; each task entry names its own frontier. A proof establishes membership, absence or a complete range under that claim, not the claim's agreement with the fold. Historical checking rebuilds each held task at its entry's heads and the project at the attestation's parents. Later receipts do not invalidate a true historical claim.

Each manifest binds its index kind, layout, opaque record-boundary commitment, record count and root-node identity. Its name is BLAKE3 of the complete image. Foreign kinds, layouts and commitments fail before any node is opened. A reader reseals the record root from the checked manifest; a proof never supplies a root to trust.

## Storage and transport

State lives beneath `index/nodes/<node identity>` and `index/manifests/<index digest>`. Synced temporary files publish nodes before their manifest. Publishing a derived index retains valid files and atomically repairs damaged images. Hydration authenticates every node through the record store, rebuilds the tree and requires its count and root to match. Every attested manifest remains held; there is no collection policy.

`domhringr/index/0` carries one question per bidirectional stream. Dependent project and dialogue questions share one connection. Answers include all framing within an inclusive 1 MiB cap. An oversized proof produces only its encoded size; a reader also rejects an over-cap stream from a dishonest holder. Readers allow sixty seconds per answer; holders allow ten idle seconds between streams.

The serving cache retains at most four hydrated trees, each limited to 65,536 records and 4 MiB of key/value payload. Larger trees are served without being retained. Derivation reuses only entries it independently derived at unchanged heads; it does not import an attester's unverified claims into its cache.

## Commands and measurements

The [peer commands](../surface-peer/README.md#keyed-indexes) derive and attest a project, prove its task entries and dialogue coordinates, and check historical claims against held receipt trees. Transport returns untrusted proof material; call `Answer::verify` before reading its contents.

`index measure` reports record count, root children, root bytes, largest leaf bytes and the largest complete single-key answer, including membership and absence framing. An internal root at least as large as its largest leaf prints `levels open`; a tree consisting of one leaf does not request another level. The [pinned measurements](src/measure/tests.rs) use the fixture's original move values and full task-entry standings under each compiled edition, at powers of two from 16 through 4,096 records and at both sides of each root/leaf crossing.

## Design choices

| Choice | Alternative | Reversal condition |
| ------ | ----------- | ------------------ |
| Derive above the fold | Maintain indexes during receipt admission | Admission itself needs authenticated index queries |
| Kind-bound manifest images | Use a record root or a value manifest as the index name | Record-root metadata changes, requiring a new manifest layout |
| Original receipt bytes in move values | Re-encode displayed moves | The receipt language supplies a canonical, lossless transformation with preserved identity |
| Content-addressed node files | A separate database table | Measured file overhead exceeds the cost of a transactional store |
| `quenchant-arith` at the storage sibling’s pin, with defaults off | Primitive arithmetic loses the nominal boundary; local wrappers duplicate its checked and saturating families | The shared arithmetic contract changes or the dependency is no longer maintained |
| Dedicated proof protocol | Mix derived bytes into receipt sync or evidence transfer | Batching or subscription requires another protocol version |

The record-tree API and proof language come from [`gandr-storage-records`](https://github.com/gandr-lang/gandr). Verification uses its membership, non-membership and range proofs against the resealed root alone.
