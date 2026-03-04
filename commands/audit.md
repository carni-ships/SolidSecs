---
name: audit
description: Run a full EVM/Solidity security audit on the current project or specified files. Usage: /audit [path] [--depth quick|standard|deep]
---

# /audit — EVM Security Audit

Run a comprehensive smart contract security audit using all available tools.

## Usage

```
/audit                          # Audit entire project, standard depth
/audit src/MyContract.sol       # Audit specific file
/audit src/ --depth deep        # Deep audit with PoC generation
/audit . --depth quick          # Quick — tools only, no manual analysis
```

## Process

Parse the arguments provided:
- **path** (optional): file or directory to audit. Default: current working directory.
- **--depth** (optional): `quick`, `standard`, or `deep`. Default: `standard`.

Then execute the `evm-audit` skill with the specified scope and depth:

1. Detect installed tools (`slither`, `aderyn`, `myth`, `forge`, `echidna`, `medusa`, `halmos`, `semgrep`, `solhint`)
2. Run all available tools on the target path
3. Map the codebase architecture and entry points
4. Perform systematic vulnerability sweep (syntactic + semantic passes)
5. Deep-dive on all High/Critical candidates with falsification
6. Synthesize and deduplicate all findings
7. Generate `audit-report.md` in the project root

## Output

Saves a professional markdown report to `audit-report.md` with:
- Risk score (0–100)
- Findings table sorted by severity
- Detailed finding entries: location, attack path, PoC, recommendation
- Tool output summaries

## Depth Guide

| Depth | Phases | Includes |
|-------|--------|----------|
| `quick` | Setup + Tools | Automated tools only, ~5 min |
| `standard` | Full workflow | Tools + manual analysis, ~15 min |
| `deep` | Full + PoC | Everything + exploit sketches + fuzzing setup |
