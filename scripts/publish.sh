#!/usr/bin/env bash
# Create the GitHub repository and push the current branch.
# Requires the GitHub CLI (https://cli.github.com) and `gh auth login` once.
set -euo pipefail

REPO_NAME="${1:-redforge}"
VISIBILITY="${2:-private}"   # private | public

command -v gh >/dev/null || { echo "gh CLI not found: https://cli.github.com"; exit 1; }
gh auth status >/dev/null 2>&1 || { echo "run 'gh auth login' first"; exit 1; }

git rev-parse --git-dir >/dev/null 2>&1 || { echo "not a git repository"; exit 1; }

if git remote get-url origin >/dev/null 2>&1; then
  echo "origin already set to: $(git remote get-url origin)"
  exit 1
fi

gh repo create "$REPO_NAME" "--$VISIBILITY" \
  --source . --remote origin \
  --description "RedForge - it-tools reimagined for red teams: 102 browser-side offensive security tools" \
  --push

echo "done: $(gh repo view --json url --jq .url)"
