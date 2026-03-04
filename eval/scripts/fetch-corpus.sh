#!/usr/bin/env bash
# fetch-corpus.sh — Clone evaluation corpora into eval/corpus/
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORPUS_DIR="$SCRIPT_DIR/../corpus"

echo "==> Fetching evaluation corpora into $CORPUS_DIR"

# DeFiVulnLabs — primary benchmark
if [ ! -d "$CORPUS_DIR/DeFiVulnLabs" ]; then
  echo "--> Cloning DeFiVulnLabs..."
  git clone --depth 1 https://github.com/SunWeb3Sec/DeFiVulnLabs "$CORPUS_DIR/DeFiVulnLabs"
else
  echo "--> DeFiVulnLabs already present, pulling latest..."
  git -C "$CORPUS_DIR/DeFiVulnLabs" pull --ff-only
fi

# Damn Vulnerable DeFi v4 — optional extended corpus
if [ "${INCLUDE_DVDEFI:-0}" = "1" ]; then
  if [ ! -d "$CORPUS_DIR/damn-vulnerable-defi" ]; then
    echo "--> Cloning Damn Vulnerable DeFi..."
    git clone --depth 1 https://github.com/theredguild/damn-vulnerable-defi "$CORPUS_DIR/damn-vulnerable-defi"
  fi
fi

echo ""
echo "==> Corpus ready. Run ./run-tools.sh to execute analysis."
