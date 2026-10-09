# crates

This file is the naming authority for the workspace's crates. A crate lives at `crates/<category>-<name>` and its package is `domhringr-<category>-<name>`; the driver is the one exception, package `domhringr`, the only name the toolchain claims on the registry.

Three disciplines: consult this file before naming a crate; when it is silent, derive the name from the layering below and the crates beside it; add the row in the same change that adds the crate. A divergence is recorded here, not smoothed over.

## Layering

Categories are a layering order: a crate depends only on crates of its own category or of one listed before it. The categories are also the closed vocabulary of commit scopes.

```text
record    the causal plane: receipts (the seat's among them) and their codec, the sedimentree, the fold, the endpoint and storage
arena     the game: arenas, plays, moves and polarity, validity, endings, verdicts, replay; no I/O
seat      the Player participant: answering a dispatch, acting, reporting; the harness shim
judge     the oracle: letter readout over a model, dialogues, verdict receipts
strategy  playbooks (Player strategies) and rubrics (Opponent strategies): documents, schemas, loader, grades
surface   what a human or harness touches: the driver, the peer binary, the operator CLI
```

## Vocabulary

Game semantics is the general register; the specific name is kept where it says more. A playbook is a Player strategy and a rubric an Opponent strategy, both under `strategy`; a dialogue is a play; a verdict is an ending; an arena is what both strategies are for. The general term is never replaced by its instance, and the instance is never renamed to the general term.

## Members

One row per directory: the directory, its package, and what it is.

```text
crates/
├── judge-oracle/       domhringr-judge-oracle       the judge: a lettered question about a transcript, read from a model's next-token distribution over an OpenAI-compatible endpoint into a letter and a probability per option, or a refusal by its reason; a table of rulings for tests and replay
├── record-evidence/    domhringr-record-evidence    the evidence plane: reports, verifier outputs and transcripts committed into gandr's value plane as chunk DAGs under one measured, pinned profile, named by manifest digest, read back through the profile check and the closure walk, and fetched from a holder over a chunk stream under its own ALPN
├── record-tree/        domhringr-record-tree        the sedimentree: receipts naming evidence by manifest digest, the fold to a view, a book of reachable peers and a task, anchors naming a tree, a path or a commit by key, DNS name or label, a tree stored in redb and synced over iroh beside other protocols
├── seat-slot/          domhringr-seat-slot          the seat: the wake an operator sends over one stream, and a seat that answers it, presents itself, acts through a program and reports, its output kept as evidence it serves to any reader, resuming what it holds on start
├── strategy-document/  domhringr-strategy-document  playbooks and rubrics: TOML documents refused by field, a step's verifier run as a process and its output and status returned for the caller to keep, a rubric's questions asked of the judge about a transcript staged as evidence, graded against its band and composed as a conjunction
├── surface-driver/     domhringr                    the `domhringr` operator binary: lists a project's seats and tasks, dispatches a seat to a task, reads the report it fetches from the seat, verifies and decides the change the report names, and lands it by git merge
└── surface-peer/       domhringr-surface-peer       the `domhringr-peer` binary: opens, grants on, notes to, binds in, claims names for, introduces, presents in, withdraws from, resolves, views, reads and syncs a tree, reaching peers through its book, dispatches a seat and replays its task with its evidence, fetches the evidence a task names, serves as a seat, rules on a task as its judge, runs playbooks and grades rubrics on a task, and checks a concepts tree for drift
```

## Crate README shape

Every crate's `README.md` follows this order. Include a section when the crate has content for it. Name crate-specific sections plainly by subject, never by negation or metaphor.

1. `# <package>` and one sentence stating what the crate is.
2. A table of contents linking every section below.
3. `## Synopsis` — three dense, technical paragraphs in the present tense, without history. Each opens with a bold word: **What.** states what the crate is; **Why.** states the need it answers; **How.** names the mechanism concretely.
4. `## References` — papers and technical artifacts, each with its full title, authors, venue, date, stable identifier (DOI, ISBN, arXiv, HAL), and one clause stating what the crate takes from it.
5. `## Provided features` — an itemized list of what the crate provides.
6. `## Expected features` — what the crate requires of its consumer or environment to be useful: a digest function, a store implementation, a spawner, a target requirement, or a specification facade's `cfg`. Do not list absent or planned work here.
7. `## Examples` — runnable usage and the test command.
8. Crate-specific sections, one per decision or mechanism, each stated as present fact with its reason.
9. `## License` — `Apache-2.0 WITH LLVM-exception`, the workspace licence at the repository root.

## Divergences

None.
