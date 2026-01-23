#!/bin/bash

# Script to run all examples
# Usage: ./examples/run-all.sh

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

echo "Building the library..."
cd "$ROOT_DIR"
npm run build

echo ""
echo "Running all examples..."
echo "======================"

EXAMPLES=(
  "chat"
  "streaming"
  "ai-sdk"
  "secure_client"
  "unverified_client"
)

FAILED_EXAMPLES=()

for example in "${EXAMPLES[@]}"; do
  echo ""
  echo "Running example: $example"
  echo "------------------------"
  if npx ts-node "$SCRIPT_DIR/$example/main.ts"; then
    echo "✓ Example $example succeeded"
  else
    echo "✗ Example $example failed"
    FAILED_EXAMPLES+=("$example")
  fi
  echo ""
done

echo "All examples completed!"
echo ""

if [ ${#FAILED_EXAMPLES[@]} -eq 0 ]; then
  echo "✓ All examples passed"
  exit 0
else
  echo "✗ ${#FAILED_EXAMPLES[@]} example(s) failed:"
  for example in "${FAILED_EXAMPLES[@]}"; do
    echo "  - $example"
  done
  exit 1
fi
