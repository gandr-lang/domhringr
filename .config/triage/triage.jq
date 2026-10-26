# Every issue is filed with a `kind:` and an `area:` label
# (gandr-lang/gandr#2538, `tracker.md` § tracker-issues): what an issue's
# labels need, as one word.
#
# Input: the issue's label names, [name].
#
# `add` when a `kind:` or an `area:` label is missing and `needs:triage` is
# absent; `remove` when both are present and `needs:triage` is still on it;
# `keep` otherwise.

(any(.[]; startswith("kind:")) and any(.[]; startswith("area:"))) as $filed
| (index("needs:triage") != null) as $flagged
| if ($filed | not) and ($flagged | not) then "add"
  elif $filed and $flagged then "remove"
  else "keep"
  end
