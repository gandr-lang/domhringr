import { execFileSync } from "node:child_process";

// Real trailer tokens. The conventional-commits parser treats ANY `word:` line
// as the footer start, so the stock footer-leading-blank rule misfires on
// wrapped prose; this closed list is what makes the replacement rule sound.
const TRAILER_TOKENS = [
  "BREAKING CHANGE",
  "BREAKING-CHANGE",
  "Acked-by",
  "Cc",
  "Closes",
  "Co-Authored-By",
  "Fixes",
  "Refs",
  "Reported-by",
  "Reviewed-by",
  "Assisted-by",
  "Signed-off-by",
  "Tested-by",
];
const TRAILER_LINE = new RegExp(`^(?:${TRAILER_TOKENS.join("|")}):[ \\t]`, "i");

const trailerLeadingBlank = (parsed) => {
  const raw = parsed.raw ?? [parsed.header, parsed.body, parsed.footer].filter(Boolean).join("\n");
  const lines = raw.split("\n");
  const first = lines.findIndex((line) => TRAILER_LINE.test(line.trimEnd()));
  if (first <= 0) return [true, ""];
  if ((lines[first - 1] ?? "").trim() === "") return [true, ""];
  return [
    false,
    `the trailer block must be preceded by a blank line; found "${(lines[first] ?? "").trim()}"`,
  ];
};

// Closed vocabulary. Grow deliberately; per-surface growth is the failure mode.
//
// Crate-category scopes survive crate splits; infra scopes name non-crate surfaces.
const SCOPES = [
  "arena",
  "face",
  "oracle",
  "pipeline",
  "record",
  "tool",
  "ci",
  "config",
  "repo",
  "workflow",
  "docs",
];

// A harness-forensics trailer (`<harness>-Session:`) records which tool drove a
// commit. That is contributor-concern, never project-concern, and it outlives
// the session it points at, so it must never reach a published history. The
// pattern matches by shape rather than by a list of tool names, so a harness
// nobody here has heard of is refused on the same terms.
const HARNESS_TRAILER_LINE = /^(?:Role|Session|[A-Za-z][A-Za-z0-9-]*-Session):/i;

const noHarnessTrailer = (parsed) => {
  const raw = parsed.raw ?? [parsed.header, parsed.body, parsed.footer].filter(Boolean).join("\n");
  const offenders = raw.split("\n").filter((line) => HARNESS_TRAILER_LINE.test(line.trim()));
  if (offenders.length === 0) return [true, ""];
  return [
    false,
    `harness trailers are contributor-concern: ${offenders.map((line) => line.trim()).join(", ")}`,
  ];
};

// The commit's author. CI lints landed commits one at a time and names each
// in COMMITLINT_COMMIT, so the author is the one that commit records. The
// local hook lints a commit not yet made, so the author is the one git will
// record, resolved the way a prepare-commit-msg hook resolves it:
// `git var GIT_AUTHOR_IDENT` honours GIT_AUTHOR_* exported by rebase and
// cherry-pick, so a replayed owner commit stays exempt and a replayed agent
// commit stays bound. An explicitly named commit that git cannot resolve fails
// the lint rather than passing as a non-agent author.
const commitAuthor = () => {
  const commit = process.env.COMMITLINT_COMMIT;
  const args = commit ? ["show", "-s", "--format=%an <%ae>", commit] : ["var", "GIT_AUTHOR_IDENT"];
  try {
    return execFileSync("git", args, { encoding: "utf8" }).trim();
  } catch (error) {
    if (commit)
      throw new Error(`COMMITLINT_COMMIT=${commit}: cannot resolve its author`, { cause: error });
    throw new Error("cannot resolve the commit author", { cause: error });
  }
};

// Autosquash markers. A fix to a commit of the same PR is committed with
// `git commit --fixup` onto that commit, so the local hook must pass
// `fixup!`, `squash!` and `amend!` subjects, and commitlint's default ignores
// do. A landed commit gets no such pass. CI names each one in
// COMMITLINT_COMMIT; there the default ignores are off, so every landed
// commit is linted, and this rule refuses the marker with its remedy: a
// marked commit in a PR's range means the branch was queued without
// `git rebase --autosquash`. The same switch lints the `Revert "..."` header
// git writes, which must be reworded as a conventional `revert` commit.
const LANDED = Boolean(process.env.COMMITLINT_COMMIT);
const AUTOSQUASH_MARKER = /^(?:fixup|squash|amend)! /;

const noAutosquashMarker = (parsed) => {
  const header = (parsed.raw ?? parsed.header ?? "").split("\n")[0];
  if (!AUTOSQUASH_MARKER.test(header)) return [true, ""];
  return [
    false,
    `an autosquash commit never lands: run git rebase --autosquash before queueing; found "${header}"`,
  ];
};

// Identity selects the marks: an agent author carries exactly the owner
// co-author line and one assistance line; a human co-author is credited
// with Co-authored-by, assistance never is. CI reads the landed commit's
// own author and marks rather than the runner's.
const OWNER_COAUTHOR = "Co-authored-by: silvanshade <silvanshade@users.noreply.github.com>";
const ASSISTANCE = "Assisted-by: LLM";
const ASSISTANT_COAUTHOR =
  /^Co-authored-by:\s*(?:anthropic|claude(?: code)?|openai|chatgpt|codex|(?:github )?copilot|coderabbit(?:ai)?|gemini|cursor|llm)\s*(?:<[^<>]*>)?$|<[^<>@]+@(?:[^<>@]+\.)?(?:anthropic\.com|openai\.com|coderabbit\.ai)>|\[bot\]/i;

const identityTrailers = (parsed) => {
  const author = commitAuthor();
  const lines = (parsed.raw ?? "").split("\n").map((line) => line.trimEnd());
  const assists = lines.filter((line) => /^Assisted-by:/i.test(line));
  const owners = lines.filter((line) =>
    /^Co-authored-by:[ \t]+silvanshade(?:[ \t]|<|$)/i.test(line),
  );
  const coauthors = lines.filter((line) => /^Co-authored-by:/i.test(line));
  if (coauthors.some((line) => ASSISTANT_COAUTHOR.test(line)))
    return [false, "Co-authored-by credits humans; use Assisted-by: LLM for assistance"];
  if (assists.some((line) => line !== ASSISTANCE) || assists.length > 1)
    return [false, "assistance requires exactly one Assisted-by: LLM line"];
  if (owners.some((line) => line !== OWNER_COAUTHOR) || owners.length > 1)
    return [false, "owner credit requires exactly one canonical co-author line"];
  const agent = /^agent-shade </.test(author);
  const owner = /^silvanshade </.test(author);
  const factory = !LANDED && Boolean(process.env.FACTORY_TASK || process.env.FACTORY_SEAT);
  if (agent && (owners.length !== 1 || coauthors.length !== 1 || assists.length !== 1))
    return [false, "agent-shade requires exactly the owner co-author and Assisted-by: LLM"];
  if (owner && factory && assists.length !== 1)
    return [false, "owner-through-factory requires Assisted-by: LLM"];
  return [true, ""];
};

export default {
  extends: ["@commitlint/config-conventional"],
  // Off only for a landed commit; see AUTOSQUASH_MARKER above.
  defaultIgnores: !LANDED,
  plugins: [
    {
      rules: {
        "trailer-leading-blank": trailerLeadingBlank,
        "no-harness-trailer": noHarnessTrailer,
        "identity-trailers": identityTrailers,
        "no-autosquash-marker": noAutosquashMarker,
      },
    },
  ],
  rules: {
    "header-max-length": [2, "always", 72],
    "header-trim": [2, "always"],
    "subject-empty": [2, "never"],
    "subject-full-stop": [2, "never", "."],
    "body-leading-blank": [2, "always"],
    "body-max-line-length": [2, "always", 72],
    // Disabled: the conventional-commits parser reclassifies wrapped prose
    // bodies as footer whenever a line starts with `word:`; the custom
    // trailer-leading-blank rule above is the sound replacement.
    "footer-leading-blank": [0, "always"],
    "trailer-leading-blank": [2, "always"],
    "no-harness-trailer": [2, "always"],
    "identity-trailers": [2, "always"],
    "no-autosquash-marker": [2, "always"],
    // Stock conventional types plus config, for changes to the repository's
    // configuration surfaces (lint vocabularies, tool settings).
    "type-enum": [
      2,
      "always",
      [
        "build",
        "chore",
        "ci",
        "config",
        "docs",
        "feat",
        "fix",
        "perf",
        "refactor",
        "revert",
        "style",
        "test",
      ],
    ],
    "type-empty": [2, "never"],
    "scope-empty": [2, "never"],
    "scope-case": [2, "always", "lower-case"],
    "scope-enum": [2, "always", SCOPES],
  },
};
