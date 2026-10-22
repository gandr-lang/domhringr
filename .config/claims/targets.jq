# The issues a pull request body works, by the keyword that names each:
# `Advances #n` for a slice, `Closes`, `Fixes` or `Resolves #n` for an issue
# it finishes. The claim lifecycle (`decide.jq`) and the lint assessment
# (`evidence:obligations`) read targets the same way.

def closing: "(close[sd]?|fix(e[sd])?|resolve[sd]?)";
def working: "(\(closing)|advances)";
def targets($keyword): [match("(?i)\\b\($keyword)\\s+#([0-9]+)\\b"; "g") | .captures[-1].string | tonumber];
