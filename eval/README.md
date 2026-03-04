# SolidSecs Evaluation Harness

Measures recall, precision, and F1 of the solidsecs tool suite against labeled vulnerable contracts.

## Quick Start

```bash
# 1. Clone the benchmark corpus
bash scripts/fetch-corpus.sh

# 2. Run analysis tools
bash scripts/run-tools.sh

# 3. Score results
python3 scripts/score.py

# Results written to:
#   results/metrics.json      ← machine-readable scores
#   results/eval-report.md    ← human-readable report
```

## What Gets Measured

### Corpus: DeFiVulnLabs
50 labeled contracts across 10 vulnerability categories:

| Category | Contracts |
|----------|-----------|
| reentrancy | 4 |
| arithmetic | 7 |
| access_control | 12 |
| external_calls | 7 |
| oracle | 3 |
| signature | 4 |
| proxy | 3 |
| dos | 2 |
| evm_specific | 7 |
| token | 1 |

### Metrics

- **Recall** — % of known vulnerabilities the tools caught
- **Precision** — % of tool findings that were genuine (not noise)
- **F1** — harmonic mean; primary headline metric

### Benchmark Targets

| Category | Target Recall | Notes |
|----------|--------------|-------|
| reentrancy | ≥ 80% | Slither has strong reentrancy detectors |
| arithmetic | ≥ 70% | divide-before-multiply well covered |
| access_control | ≥ 60% | Some cases require semantic reasoning |
| external_calls | ≥ 70% | unchecked-transfer well covered |
| oracle | ≥ 30% | Mostly semantic — tools miss these |
| signature | ≥ 20% | Largely manual analysis required |
| proxy | ≥ 40% | Storage collision partially covered |
| dos | ≥ 50% | Unbounded loops covered |
| evm_specific | ≥ 50% | Mixed — weak-prng, encode-packed covered |

Anything below target is a gap the **manual analysis phases** (HUNT + ATTACK) of the skill must compensate for.

## Ground Truth Schema

`ground-truth.json` maps each contract to:
```json
{
  "file": "Reentrancy.sol",
  "category": "reentrancy",
  "eth_id": "ETH-001",
  "severity": "critical",
  "description": "Classic single-function reentrancy",
  "expected_detectors": ["reentrancy-eth"]
}
```

`expected_detectors` lists Slither detector names expected to fire. Empty `[]` means the vulnerability requires manual/semantic analysis — tools are not expected to catch it automatically.

## Extending the Harness

### Add a new corpus (e.g. Damn Vulnerable DeFi)
```bash
INCLUDE_DVDEFI=1 bash scripts/fetch-corpus.sh
```
Then add entries to `ground-truth.json` with contracts from `corpus/damn-vulnerable-defi/`.

### Add a new tool (e.g. Mythril)
1. Add tool execution to `scripts/run-tools.sh`
2. Add a parser function in `scripts/score.py` (like `parse_slither_json`)
3. Pass results to `score()` alongside slither/aderyn

### Re-run after updating the skill
```bash
bash scripts/run-tools.sh && python3 scripts/score.py
```
Compare `results/metrics.json` across runs to track improvement.
