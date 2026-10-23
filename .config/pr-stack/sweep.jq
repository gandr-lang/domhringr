# What `wt:sweep` does with each worktree of the clone: a worktree is
# removed when its branch has landed, mechanically, never because a seat
# remembered to. The sweep makes no safety check of its own: `wt remove`
# refuses a dirty or otherwise unsafe tree, and the sweep reports the refusal
# and keeps the tree. The one predicate it keeps is the landing itself.
#
# Input: an array of worktrees, each an object with
#   path      the worktree's path;
#   branch    its branch, or null when detached;
#   primary   the clone's primary worktree;
#   cwd       the caller's own worktree;
#   merged    Worktrunk reads the branch integrated into the default branch
#             and its head is off origin/main's first-parent line: a landed
#             branch, never one cut from main and not yet committed to;
#   scratch   null, or a scratch worktree under a temporary directory:
#             `{holder, alive, young}`, `holder` the pid named in a
#             `domhringr-scratch-<pid>.` directory (null for an unnamed one),
#             `alive` whether that process runs, `young` whether its index
#             changed within 4 hours.
#
# Output: an array of `{path, branch, action, reason}`, one per worktree:
#   remove   `wt remove --foreground`, the branch deleted as merged;
#   force    `git worktree remove --force`, a scratch tree nothing holds;
#   keep     left as it is.

map(
  {path, branch} + (
    if .primary then {action: "keep", reason: "the primary worktree"}
    elif .cwd then {action: "keep", reason: "the caller's own worktree"}
    elif .scratch != null then
      if .scratch.holder != null then
        if .scratch.alive then {action: "keep", reason: "scratch held by live process \(.scratch.holder)"}
        else {action: "force", reason: "scratch whose process \(.scratch.holder) is gone"}
        end
      elif .scratch.young then {action: "keep", reason: "unnamed scratch changed within 4 hours"}
      else {action: "force", reason: "unnamed scratch unchanged for 4 hours"}
      end
    elif .branch == null then {action: "keep", reason: "detached, not a scratch"}
    elif (.branch | startswith("wip/")) then {action: "keep", reason: "a wip/ branch"}
    elif .merged then {action: "remove", reason: "landed in origin/main"}
    else {action: "keep", reason: "not landed"}
    end
  )
)
