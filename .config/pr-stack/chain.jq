# The stack holding pull request `$n`, read from the server: its base chain
# down to the trunk, then the open pull requests based on it up to the top.
#
# Input: the open pull requests, each `{number, head, base, created}`.
# Arguments: `$n`, the pull request; `$trunk`, the default branch.
# Output: the stack bottom to top, each `{number, head}`; empty when `$n` is
# not open. Where two pull requests share a base, the older one is the chain.

. as $open
| def below($pr): $pr | if .base == $trunk then empty else ([$open[] | select(.head == $pr.base)] | first // empty) end;
  def above($pr): [$open[] | select(.base == $pr.head)] | sort_by(.created) | first // empty;
  ([$open[] | select(.number == $n)] | first) as $self
| if $self == null then
    []
  else
    ([limit(64; $self | recurse(below(.)))] | reverse) + ([limit(64; $self | recurse(above(.)))] | .[1:])
    | map({number, head})
  end
