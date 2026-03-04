#!/usr/bin/env bash
# run-tools.sh — Run Slither, Aderyn, Semgrep, and Forge over each DeFiVulnLabs contract
# Outputs raw JSON results to eval/results/raw/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS="$SCRIPT_DIR/../corpus/DeFiVulnLabs"
RAW_DIR="$SCRIPT_DIR/../results/raw"
CONTRACTS_DIR="$CORPUS/src/test"

if [ ! -d "$CORPUS" ]; then
  echo "ERROR: Corpus not found. Run ./fetch-corpus.sh first."
  exit 1
fi

mkdir -p "$RAW_DIR/slither" "$RAW_DIR/aderyn" "$RAW_DIR/semgrep" "$RAW_DIR/forge"

# Check tool availability
HAVE_SLITHER=0
HAVE_ADERYN=0
HAVE_SEMGREP=0
HAVE_FORGE=0
command -v slither  &>/dev/null && HAVE_SLITHER=1  && echo "[+] slither found"
command -v aderyn   &>/dev/null && HAVE_ADERYN=1   && echo "[+] aderyn found"
command -v semgrep  &>/dev/null && HAVE_SEMGREP=1  && echo "[+] semgrep found"
command -v forge    &>/dev/null && HAVE_FORGE=1    && echo "[+] forge found"

if [ $HAVE_SLITHER -eq 0 ] && [ $HAVE_ADERYN -eq 0 ] && [ $HAVE_SEMGREP -eq 0 ] && [ $HAVE_FORGE -eq 0 ]; then
  echo "ERROR: No analysis tools found."
  echo "  pip install slither-analyzer semgrep"
  echo "  cargo install aderyn"
  echo "  curl -L https://foundry.paradigm.xyz | bash && foundryup"
  exit 1
fi

echo ""
echo "==> Running tools on $CONTRACTS_DIR"
echo ""

# Run Slither on the whole project (more efficient than per-file)
if [ $HAVE_SLITHER -eq 1 ]; then
  echo "--> Running Slither on full project..."
  pushd "$CORPUS" > /dev/null

  slither . \
    --json "$RAW_DIR/slither/full-project.json" \
    --filter-paths "lib/" \
    2>"$RAW_DIR/slither/slither-stderr.txt" || true

  echo "    Slither output: $RAW_DIR/slither/full-project.json"
  popd > /dev/null
fi

# Run Aderyn on the whole project
if [ $HAVE_ADERYN -eq 1 ]; then
  echo "--> Running Aderyn on full project..."
  pushd "$CORPUS" > /dev/null

  aderyn . \
    --output "$RAW_DIR/aderyn/full-project.md" \
    --path-excludes "lib/" \
    --src "src/test" \
    2>"$RAW_DIR/aderyn/aderyn-stderr.txt" || true

  echo "    Aderyn output: $RAW_DIR/aderyn/full-project.md"
  popd > /dev/null
fi

# Run Semgrep on the contract files
if [ $HAVE_SEMGREP -eq 1 ]; then
  echo "--> Running Semgrep on full project..."
  pushd "$CORPUS" > /dev/null

  # Use find+xargs to avoid git-ignore filtering and the broken --output flag
  find src/test -name "*.sol" | \
    xargs semgrep \
      --config=p/smart-contracts \
      --no-git-ignore \
      --json \
      2>"$RAW_DIR/semgrep/semgrep-stderr.txt" \
    > "$RAW_DIR/semgrep/full-project.json" || true

  echo "    Semgrep output: $RAW_DIR/semgrep/full-project.json"
  popd > /dev/null
fi

# Run Forge tests — exploit PoC confirmation
if [ $HAVE_FORGE -eq 1 ]; then
  echo "--> Running Forge tests (PoC confirmation)..."
  pushd "$CORPUS" > /dev/null

  forge test --json \
    2>"$RAW_DIR/forge/forge-stderr.txt" \
    > "$RAW_DIR/forge/full-project.json" || true

  echo "    Forge output: $RAW_DIR/forge/full-project.json"
  popd > /dev/null
fi

echo ""
echo "==> Raw tool output written to $RAW_DIR"
echo "==> Run ./score.py to compute recall/precision metrics."
