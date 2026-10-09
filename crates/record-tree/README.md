# domhringr-record-tree

The record plane stores signed receipts in sedimentrees, folds them into views, and syncs them over iroh.

- [Synopsis](#synopsis)
- [References](#references)
- [Provided features](#provided-features)
- [Expected features](#expected-features)
- [Examples](#examples)
- [Receipts and views](#receipts-and-views)
- [Anchors and witnesses](#anchors-and-witnesses)
- [Presence](#presence)
- [Networking](#networking)
- [Codec](#codec)
- [Dependencies](#dependencies)
- [License](#license)

## Synopsis

**What.** `domhringr-record-tree` is the record plane's durable, replicated receipt store. It provides one sedimentree per tree, named by the tree's own verifying key, a view of each tree's owner, delegated write authority, admitted notes, bound paths, claimed DNS names, introduced trees, the book of which member is reachable at which endpoint, and admitted and refused commits, and the resolution against those views of an anchor naming a tree, a path in it, `domhringr://<authority>/<path>`, or a commit in it, `domhringr://<authority>/.commit/<commit-id>`, whose authority takes three forms: the tree's key, a DNS name, or a label.

**Why.** Peers need the same interpretation of signed operations regardless of arrival order. Authority depends on a commit's causal past; retaining refused commits lets peers replicate the same evidence without treating every stored write as authorized.

**How.** Published subduction crates store signed commits in redb and sync them over iroh. This crate supplies identity files, Tokio spawner and timer adapters, the value-plane receipt grammar, a deterministic fold, and a single-batch sync operation.

## References

| Artifact | Use |
| -------- | --- |
| `subduction_core`, [crate documentation](https://docs.rs/subduction_core) | Signed commit storage and batch synchronization. |
| `sedimentree_core`, [crate documentation](https://docs.rs/sedimentree_core) | Causal trees, commit ids, and signed payloads. |
| `subduction_redb_storage`, [crate documentation](https://docs.rs/subduction_redb_storage) | Durable redb storage. |
| `iroh`, [crate documentation](https://docs.rs/iroh) | Endpoint discovery, direct connections, and relays. |
| `tokio`, [crate documentation](https://docs.rs/tokio) | Runtime, task spawning, and timers. |
| `gandr-storage-values`, [crate documentation](https://github.com/gandr-lang/gandr/tree/main/crates/storage-values) | Canonical receipt tokens and flat encoding. |
| `getrandom`, [crate documentation](https://docs.rs/getrandom/0.4) | Operating-system randomness for operation fences. |

## Provided features

- Persistent endpoint and signing identities in a state directory, and one minted key per tree opened.
- Durable commits carrying `Open`, `Grant`, `Note`, `Bind`, `Claim`, `Introduce`, `Present`, or `Withdraw` receipts; an `Open` carries the tree key's proof, a `Present` the presented endpoint key's.
- Canonical views with causal authority checks, path bindings, owner-only name claims, label introductions, a book of each member's own presented endpoint, and explicit refusals.
- Anchors naming a tree, a path in it, or a commit in it by key, by DNS name, or by label, resolved by fold to a binding, to unbound, to a commit's verdict, to unknown, or to a named refusal; a `Reference` may abbreviate a commit id to a unique prefix of at least eight hex digits.
- A `Witness` trait for a DNS name's candidate trees, with the `Dns` witness over `_domhringr.<domain>` TXT records and the `Static` witness supplied by hand.
- Sorted tree heads and one-round peer synchronization.
- Ephemeral or fixed UDP binding, presenting the bound endpoint in a tree, routing a dial for a tree through its book or to an endpoint named by hand, dialing an endpoint by its id and any addresses, and selected-path reporting.

## Expected features

- A writable state directory, with exclusive access to its tree store.
- A Tokio runtime when opening a `Peer` and while its engine runs.
- A native target with an operating-system random source.
- For synchronization, network access and the remote's endpoint and signing identities: named by hand at first contact, or read from the tree's book once a sync has carried the remote's presence.
- For a DNS-form anchor, a witness: DNS resolvers reaching the name's `_domhringr.<domain>` TXT records, or a `Static` map.
- For the ignored test `witness::tests::the_dns_witness_reads_a_real_record`, `DOMHRINGR_WITNESS=<domain>=<tree id>` naming a published witness record; the test fails naming the variable when it is unset, and CI does not run it.

## Examples

With `domhringr-record-tree` and Tokio's `rt` and `time` features as dependencies, this program opens a tree in a fresh state directory supplied as its first argument, binds a path in it to a note's commit, claims a DNS name for the tree, resolves the path's anchor by key and by the DNS name under a witness supplied by hand, and resolves the note's commit by a prefix of its id:

```rust
use domhringr_record_tree::{Anchor, Domain, Identity, Peer, Receipt, Reference, Resolution, Scope, StateDir, Static, Target, TreeKey, Verdict};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let path = std::env::args_os().nth(1).ok_or("expected a fresh state directory")?;
    let state = StateDir::from(std::path::PathBuf::from(path));
    let runtime = tokio::runtime::Builder::new_current_thread().enable_all().build()?;
    runtime.block_on(async {
        let identity = Identity::load_or_create(&state)?;
        let owner = identity.peer_key();
        let peer = Peer::open(&state, identity)?;
        let key = TreeKey::mint(&state)?;
        let tree = key.tree();
        peer.commit(tree, Receipt::open(&key, owner)?).await?;
        let note = peer.commit(tree, Receipt::note(tree, "hello".into())?).await?;
        let target = Target::Anchor(Anchor::commit(tree, note));
        let bind = Receipt::bind(tree, "greeting".parse()?, target.clone())?;
        peer.commit(tree, bind).await?;
        let domain: Domain = "example.test".parse()?;
        peer.commit(tree, Receipt::claim(tree, domain.clone())?).await?;
        let witness: Static = [(domain, tree)].into_iter().collect();
        let bound = Resolution::Bound(owner, target);
        for text in [format!("{}greeting", Anchor::key(tree)), "domhringr://example.test/greeting".into()] {
            let reference: Reference = text.parse()?;
            assert_eq!(peer.whence(&reference, &witness, Scope::Unscoped).await?, bound);
        }
        let prefix: String = note.to_string().chars().take(12).collect();
        let commit: Reference = format!("{}.commit/{prefix}", Anchor::key(tree)).parse()?;
        let located = Resolution::Commit { id: note, verdict: Verdict::Admitted };
        assert_eq!(peer.whence(&commit, &witness, Scope::Unscoped).await?, located);
        Ok(())
    })
}
```

The tree id is the tree key's verifying key, written in an anchor as 52 z-base-32 characters; it selects a sedimentree and is not a commit digest. The [`domhringr-peer` binary](../surface-peer/README.md) names trees by anchor and peer, endpoint and commit ids in hex.

Run the crate's tests from the workspace root:

```sh
mise exec -- cargo nextest run -p domhringr-record-tree
```

## Receipts and views

A peer is a state directory holding two ed25519 keys, one for the iroh endpoint and one for subduction's signer, the key of every tree it opened, and the tree store. Every commit carries a receipt: the format version, the tree it belongs to, a 16-byte operation fence drawn at random, and its kind — `Open { proof }` (the tree's root; its author owns the tree, and the proof is the tree key's signature naming that author), `Grant { to }` (write authority delegated to a peer), `Note { text }`, `Bind { path, target }` (a path in the tree bound to an anchor — a tree, a path, or a commit, in this tree or another — to an endpoint, or to an opaque datum), `Claim { domain }` (a DNS name claimed for the tree), `Introduce { tree, label }` (another tree introduced by a label in this one), `Present { endpoint, proof }` (the author's iroh endpoint and the addresses it is reached at; the proof is the endpoint key's signature naming the author), or `Withdraw { of }` (the withdrawal of a peer's presence). The commit's blob is the encoded receipt, its id the BLAKE3 digest of that blob, its parents the tree's heads when it is made, and its author the commit's verified signer.

A view is the fold of a tree's commits: walked in canonical order (topological, the smallest commit id next among the ready), a receipt is admitted when it is the tree's Open, when its author owns the tree, or when an admitted grant to its author is among its ancestors, except that a claim is admitted from the owner alone, a presence only when its proof holds for its author under the presented endpoint's key, and a member's withdrawal only of its own presence; everything else is refused with its reason — wrong tree, undecodable, duplicate operation, no authority, not owner, second Open, bad proof, foreign endpoint, foreign presence. The tree's Open is the root Open with the smallest commit id among those whose proof holds under the tree id, so a tree id names exactly the tree its key opened. Among the admitted binds of one path, the last in canonical order binds it, among the admitted introductions of one label, the last introduces it, and among an author's admitted presences, the last is its entry in the book unless an admitted withdrawal of it follows; an anchor's path resolves to that binding or to unbound. The view keeps the id of every commit it admitted beside every refusal, so a commit resolves to the fold's verdict on it. Every peer holding the same commits folds them to the same view, whatever order they arrived in. Refused commits stay in the tree and sync like any other.

## Anchors and witnesses

An anchor names its tree in one of three forms, told apart by its authority. The key form, `domhringr://<tree-id>/…`, names the tree by its key and resolves in that tree's view. The DNS form, `domhringr://<domain>/…`, whose authority holds a dot, names the one tree that a witness names for the DNS name and whose own view admits its owner's claim of it: a witness naming no tree is `unwitnessed`, no witnessed tree holding the claim `unclaimed`, and two holding it `ambiguous`. The label form, `domhringr://<label>/…`, whose authority holds no dot and is not spelled as a tree id, names the tree introduced by that label in the tree the label is read in (`Scope::In`): read in no tree it is `unscoped`, and a label that tree never introduced is `unintroduced`. A bare DNS or label anchor resolves to the key-form anchor of the tree it names, bound under the claim's or the introduction's author; a path or a commit under it resolves in that tree's view. A label means what one tree says it means, so the same label read in two trees names two trees or none.

Within its tree an anchor names nothing (the bare anchor, `domhringr://<authority>/`), a path, or a commit, `domhringr://<authority>/.commit/<commit-id>`, the id as 64 lowercase hex digits. A segment beginning with `.` is reserved for forms the scheme names, `.commit` among them, so no path holds one, in an anchor or in a receipt. A commit resolves to the fold's verdict on it, `admitted` or `refused` with the refusal's reason, and to `unknown` when its tree holds no commit by that id, among them a commit held in another tree. An `Anchor` carries the whole id, as a receipt does. A `Reference`, what a reader types, may also abbreviate it, as git does, to a prefix of at least eight hex digits: the prefix names the one commit of the tree whose id begins with it, resolves to `unknown` when none does, and is refused as `ambiguous commit` with every match when several do. A prefix is not stable as the tree grows, so no receipt carries one.

The witness alone resolves nothing. A tree resolves only when its own signed root claims the name, so a forged or stale record can make a name fail but cannot point it at a tree that did not claim it; a witnessed tree the store does not hold claims nothing until it is synced. The `Dns` witness queries the absolute name `_domhringr.<domain>.` for TXT records, each naming one tree as `tree=<tree-id>`; a name with no records, or none at all, names no tree, and other records are ignored. A DNS name is lowercase letters, digits, and hyphens in at least two dot-separated labels of at most 63 characters, at most 242 in all so that the witness name fits DNS's 253; an internationalized name is written in its ASCII form.

## Presence

A member says where it is reached by committing a presence: `Node::present` waits up to five seconds for the endpoint to reach its home relay, then commits the endpoint at the addresses iroh names for it, its direct addresses and its relay. The book (`View::book`) holds, per author, the presence admitted last, and the commit that presented it is its `since`; a superseded or withdrawn presence is absent, never a default. `Peer::route` names the remote a dial for a tree reaches: the peer aimed at — a named peer or the tree's owner — at an endpoint named by hand, or else at its presence in the book; the dialer itself is no one to reach, and a peer the book holds no presence of is unreachable. `Peer::reads` names the trees a resolution reads, so a caller syncs each through its route before resolving.

**A presence proves its endpoint by the endpoint key's signature naming the author.** A peer's endpoint key and its signing key are distinct, so the commit's author does not name the endpoint by itself; the presence carries the endpoint key's signature over a fixed domain and the author's peer key, and the fold refuses one whose signature does not hold for its author as `foreign endpoint`. A member therefore presents only an endpoint whose key it holds.

- the author's signing key as the endpoint key: one key for both roles, which the state directory keeps apart.
- no proof, relying on the handshake: a dial to a stolen presence fails authentication, but a member could still point every dialer at an address it does not hold.

Reversal: a peer whose endpoint and signing keys are one key, when the check becomes key equality.

**A presence carries no time.** Its commit is when it holds since, and it holds until the record supersedes or withdraws it; liveness is the record's, never a clock's.

- a timestamp in the payload: a clock in the record, and liveness judged by elapsed time.

Reversal: a design that names a clock in the record.

**A withdrawal names the peer whose presence it withdraws.** The owner withdraws anyone's presence and a member its own (`foreign presence` otherwise); a withdrawal of a presence the book does not hold is admitted and changes nothing, so a withdrawal and a presence made concurrently settle by canonical order alone.

- a withdrawal naming the presenting commit: it would leave a later presence by the same author standing, and the owner could not clear an author's entry in one receipt.

Reversal: presences of resources other than the author's own endpoint, which need naming by more than the author.

**An endpoint is its id and an ordered set of addresses.** A direct address is an IP address and port, an IPv6 address without its flow label and scope id, both local to the host naming them; a relay is an `http` or `https` URL written as it parses back and holding no `@`, the character the text form `<endpoint-id>@<address>…` separates addresses by. The receipt lists the addresses in that order, each once, so an endpoint has one encoding; an address of another transport iroh names is left out.

- iroh's `EndpointAddr` through serde: a second canonical form beside the value plane's, its order the serializer's.
- an iroh ticket string: base32 of a postcard encoding, opaque to the decoder's refusals.

Reversal: a transport beyond IP and relays that a dialer needs from the book.

**An endpoint named by hand overrides the book.** A dial reads the book only when no endpoint is named. A presence goes stale when its peer moves before presenting again, and a book read first would then leave the peer unreachable even with its current address in hand.

- the book first, the endpoint named by hand only when the book holds no presence: one fewer way to name a remote, at the cost of the stale case.

Reversal: a book that cannot go stale, as when a dial that fails at a presence falls back on its own.

## Networking

A bound peer is reached by endpoint id alone: on the local network through mDNS and direct addresses, across networks through n0's relay and DNS. It binds an ephemeral UDP port, or a fixed one that a firewall rule can name. A sync dials the remote, runs one batch round for one tree, and disconnects; a dialer that knows the remote's addresses — from its presence in the book, or named by hand — names them in the dial, and the dial does not wait on the lookups. Each side reports the network path iroh selected — direct, relayed, or not yet chosen.

## Codec

**Receipts use the value plane's flat form, `gandr-storage-values` at the pinned sibling revision.** `Receipt` implements `CanonicalValue` using the token grammar in [`src/receipt.rs`](src/receipt.rs). A commit's blob is the flat form written by `encode_flat` and read by `decode_flat`. This is the token stream `cam_commit` cuts, so committing a receipt through the value plane's chunk DAG requires no re-encoding; a receipt fitting one chunk is exactly the body that chunk frames. The decoder admits exactly what the encoder writes, giving each receipt one blob and one commit id.

Two identities name a receipt and neither stands in for the other. The `CommitId` is sedimentree's: the BLAKE3 digest of the blob, the flat bytes alone. A value-plane `ContentPtr` names the framed chunk: BLAKE3 over the chunk image, the plane's domain and frame header included. A commit is found by its `CommitId`; a `ContentPtr` names a receipt committed into the value plane.

- postcard over a serde mirror of the receipt: compact, but requires re-encoding for the value plane and maintains a second canonical form.
- sedimentree's `codec`: the format of its signed payloads (schema header, issuer key, fields, signature) with big-endian integers; it already seals the commit that carries the blob, and as a receipt form it would be a second canonical form in another byte order.
- a hand-rolled fixed layout: one more canonical form to keep in step with the value plane's.

Reversal: an incompatible change to the value plane's token grammar or flat form requires a matching receipt version change; moving receipts into the value plane's store makes the blob a `ContentPtr` and changes what the commit id hashes.

**A bind's target carries its anchor as typed parts, not as anchor text.** The target is a constructor — anchor, endpoint, or datum — and an anchor a constructor for what it names in its tree — nothing, a path, or a commit — around an authority constructor — key, DNS name, or label. Each part is the record the receipt grammar already uses for its kind: a 32-byte key, a DNS name or label as UTF-8 bytes, a path as its text, a commit id as its 32 bytes. Each part has one encoding, the decoder refuses what the parsers refuse (an empty or reserved segment, a short key, a commit id of other than 32 bytes), and an abbreviated commit has none. The receipt grammar is version 2; a receipt of any other version is refused.

- the anchor's text as one UTF-8 record: a second canonical form to keep in step with the parser, its refusals reached only by parsing decoded text.
- a commit id and a tree id as targets of their own beside the anchor: two spellings of what an anchor names.

Reversal: a new form within a tree or a new authority adds a constructor under a new receipt version.

**A presence and a withdrawal are new kinds under receipt version 2.** A decoder that predates them refuses them as an unknown kind, folded as undecodable, while every receipt it knows keeps its blob and its commit id; a version change would make every new receipt unreadable to it instead.

- receipt version 3: an old decoder refuses notes and binds it could read.

Reversal: a change to an existing kind's payload, which needs a new version.

## Dependencies

**Operation fences use `getrandom` 0.4 with no features.** `getrandom::fill` draws the 16 fence bytes from the operating system's source. iroh already brings the crate into the dependency graph, so it adds no crate to the build; native targets require no feature.

- `rand`: a seeded generator and its traits where one read from the OS source suffices.
- `uuid` with `v4`: a crate and a UUID type for what is 16 opaque bytes.

Reversal: a high-risk advisory against `getrandom`, its departure from the dependency graph, or a fence source the value plane supplies.

**The DNS witness uses iroh's resolver, `iroh::dns::DnsResolver`.** iroh resolves endpoint ids through DNS with it, so reading a name's TXT records adds no crate and no feature to the build. It reads the host's resolver configuration, falls back to public resolvers, bounds a lookup by `iroh::dns::DNS_TIMEOUT`, and reports a name that does not exist apart from a failed lookup.

- `hickory-resolver`: a second resolver, with its own configuration and feature set, beside the one iroh already carries.
- the operating system's resolver through the standard library: it resolves addresses and returns no TXT records.

Reversal: iroh no longer exporting its resolver, or a witness that needs record types or DNSSEC validation the resolver does not expose.

## License

`Apache-2.0 WITH LLVM-exception`; see the workspace [Apache-2.0 license](../../LICENSE.Apache-2.0.txt) and [LLVM exception](../../LICENSE.LLVM-exception.txt).
