# TEMPORARY (#61): commit whatever the formatter changed through the GraphQL
# createCommitOnBranch mutation, so GitHub signs the commit.
import base64
import json
import os
import subprocess
import sys

repo = os.environ["GITHUB_REPOSITORY"]
branch = os.environ["GITHUB_REF_NAME"]
head = os.environ["GITHUB_SHA"]

files = subprocess.check_output(["git", "diff", "--name-only"]).decode().split()
if not files:
    print("nothing to format")
    sys.exit(0)

additions = [
    {"path": f, "contents": base64.b64encode(open(f, "rb").read()).decode()}
    for f in files
]
query = (
    "mutation($input: CreateCommitOnBranchInput!) {"
    " createCommitOnBranch(input: $input) { commit { oid } } }"
)
variables = {
    "input": {
        "branch": {"repositoryNameWithOwner": repo, "branchName": branch},
        "message": {
            "headline": "style(format): apply JuliaFormatter to src and test (#61)",
            "body": "Automated JuliaFormatter pass (DefaultStyle) over src/ and test/, "
                    "committed through the GitHub API so GitHub signs it.",
        },
        "fileChanges": {"additions": additions, "deletions": []},
        "expectedHeadOid": head,
    }
}
with open("/tmp/format-req.json", "w") as fh:
    json.dump({"query": query, "variables": variables}, fh)
subprocess.run(["gh", "api", "graphql", "--input", "/tmp/format-req.json"], check=True)
print("committed formatted files:", files)
