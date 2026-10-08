# crates

This file is the naming authority for the workspace's crates. A crate lives at `crates/<category>-<name>` and its package is `domhringr-<category>-<name>`; the driver is the one exception, package `domhringr`, the only name the toolchain claims on the registry.

Three disciplines: consult this file before naming a crate; when it is silent, derive the name from the layering below and the crates beside it; add the row in the same change that adds the crate. A divergence is recorded here, not smoothed over.

## Layering

Categories are a layering order: a crate depends only on crates of its own category or of one listed before it. The categories are also the closed vocabulary of commit scopes.

```text
record    the causal plane: receipts and their codec, the sedimentree, the fold, the endpoint and storage
arena     the game: arenas, plays, moves and polarity, validity, endings, verdicts, replay; no I/O
seat      the Player participant: dispatch, report, handoff, retire; the harness shim
judge     the oracle: letter readout over a model, dialogues, verdict receipts
strategy  playbooks (Player strategies) and rubrics (Opponent strategies): documents, schemas, loader, grades
face      what a human or harness touches: the driver, the peer binary, the operator CLI
```

## Vocabulary

Game semantics is the general register; the specific name is kept where it says more. A playbook is a Player strategy and a rubric an Opponent strategy, both under `strategy`; a dialogue is a play; a verdict is an ending; an arena is what both strategies are for. The general term is never replaced by its instance, and the instance is never renamed to the general term.

## Members

One row per directory: the directory, its package, and what it is.

```text
crates/
├── record-tree/   domhringr-record-tree   the sedimentree: receipts, the fold to a view, a tree stored in redb and synced over iroh
├── face-driver/   domhringr               the `domhringr` driver: installs components
└── face-peer/     domhringr-face-peer     the `domhringr-peer` binary: opens, grants on, notes to, views, reads and syncs a tree
```

## Divergences

None.
