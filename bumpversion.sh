#!/bin/bash

set -e

TYPE="${1:-patch}"

if [[ ! "$TYPE" =~ ^(patch|minor|major)$ ]]; then
  echo "Usage: ./bumpversion.sh [patch|minor|major]"
  echo "Default: patch"
  exit 1
fi

npm version "$TYPE" -w @tinfoilsh/verifier -w tinfoil --no-git-tag-version
npm run sync
