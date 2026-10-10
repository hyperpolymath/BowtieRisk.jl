#!/usr/bin/env bash
# SPDX-License-Identifier: MPL-2.0
# TEMPORARY (#61): commit whatever the formatter changed through the GraphQL
# createCommitOnBranch mutation, so GitHub signs the commit.
set -euo pipefail

files=$(git diff --name-only)
if [ -z "$files" ]; then
  echo "nothing to format"
  exit 0
fi

adds=$(for f in $files; do
  jq -n --arg p "$f" --rawfile c "$f" '{path: $p, contents: ($c | @base64)}'
done | jq -s '.')

jq -n \
  --arg repo "$GITHUB_REPOSITORY" \
  --arg branch "$GITHUB_REF_NAME" \
  --arg head "$GITHUB_SHA" \
  --argjson adds "$adds" \
  '{
    query: "mutation($input: CreateCommitOnBranchInput!) { createCommitOnBranch(input: $input) { commit { oid } } }",
    variables: {input: {
      branch: {repositoryNameWithOwner: $repo, branchName: $branch},
      message: {
        headline: "style(format): apply JuliaFormatter to src and test (#61)",
        body: "Automated JuliaFormatter pass (DefaultStyle) over src/ and test/, committed through the GitHub API so GitHub signs it."
      },
      fileChanges: {additions: $adds, deletions: []},
      expectedHeadOid: $head
    }}
  }' > /tmp/format-req.json

gh api graphql --input /tmp/format-req.json
echo "committed formatted files: $files"
