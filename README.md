# solidsecs — Claude Code Plugin

Full-spectrum EVM/Solidity smart contract security audit plugin for [Claude Code](https://claude.ai/code).

Orchestrates every available audit tool (Slither, Aderyn, Mythril, Echidna, Medusa, Halmos, Foundry, Semgrep, and more), performs systematic manual analysis across 100+ vulnerability classes, and synthesizes everything into a professional severity-ranked markdown report.

## What It Does

- **Detects installed tools** and runs them all (Slither, Aderyn, Mythril, Semgrep, Solhint, Halmos, Echidna, Medusa, Forge, Wake, Pyrometer, Heimdall-rs)
- **Maps the codebase**: entry points, privilege boundaries, invariants
- **Hunts** with syntactic (grep) + semantic (reasoning) passes across 13 vulnerability categories
- **Attacks** every High/Critical candidate with falsification and PoC sketches
- **Reports** to `audit-report.md` with risk score, severity-ranked findings, attack paths, and remediations

## Install

```bash
git clone https://github.com/carni-ships/SolidSecs ~/.claude/plugins/solidsecs
```

## Usage

### Slash command (explicit)
```
/audit                          # Standard audit of current project
/audit src/MyContract.sol       # Specific file
/audit . --depth deep           # Deep audit with PoC generation
/audit . --depth quick          # Tools only, fast
```

### Auto-triggered skill
The `solidsecs` skill activates automatically when you say things like:
- "audit this contract"
- "security review"
- "scan for vulnerabilities"
- "run slither on this"
- "find bugs in this Solidity code"

## Vulnerability Coverage

| Category | Classes |
|----------|---------|
| Reentrancy | Single, cross-function, cross-contract, read-only, ERC-777, transient storage |
| Access Control | Missing checks, tx.origin, unprotected selfdestruct, proxy init, centralization |
| Arithmetic | Overflow/underflow, rounding, precision loss, share inflation |
| External Calls | Unchecked return values, SafeERC20, fee-on-transfer, rebasing, return data bomb |
| Oracle & Price | Manipulation, flash loan attacks, Chainlink staleness, min/max bounds |
| Flash Loans | Oracle attacks, sandwich/MEV, callback reentrancy |
| Proxy & Upgrades | Storage collision, uninitialized impl, UUPS auth, storage layout drift |
| Token Handling | ERC-777, non-standard ERC-20, approval race, blacklist |
| Signature & Replay | Missing nonce, chain ID, malleability, ecrecover zero address |
| DoS & Griefing | Unbounded loops, external call failure, block stuffing, storage bloat |
| DeFi-Specific | ERC-4626 inflation, donation attacks, liquidation logic, LP pricing, governance |
| EVM-Specific | Timestamp dependency, weak randomness, front-running, delegatecall injection |
| Modern Patterns | EIP-7702, ERC-4337, Uniswap V4 hooks, transient storage |

## Protocol Checklists

Specialized checklists for: AMM/DEX · Lending · Vault/ERC-4626 · Bridge · Governance · Proxy · Staking · Account Abstraction · Uniswap V4 Hooks

## Requirements

- [Claude Code](https://claude.ai/code) CLI
- Solidity project (Foundry, Hardhat, or Truffle)
- Optional (install for deeper analysis): `slither`, `aderyn`, `mythril`, `forge`, `echidna`, `medusa`, `halmos`, `semgrep`

## Reference Material

The plugin loads vulnerability knowledge from:
- `skills/solidsecs/references/tools.md` — CLI invocations for 12+ tools
- `skills/solidsecs/references/vulnerability-taxonomy.md` — ETH-001–ETH-096+ index
- `skills/solidsecs/references/protocol-checklists.md` — Protocol-specific checks
- `skills/solidsecs/references/report-template.md` — Report structure

## Acknowledgements

This plugin draws on methodology, patterns, and vulnerability knowledge from the following public resources:

| Resource | Author | What it contributed |
|----------|--------|---------------------|
| [pashov/skills](https://github.com/pashov/skills) | @pashov | Skill structure and audit workflow patterns |
| [trailofbits/skills](https://github.com/trailofbits/skills) | Trail of Bits | Professional audit methodology |
| [Cyfrin/solskill](https://github.com/Cyfrin/solskill) | Cyfrin | Solidity-specific audit checklists |
| [kadenzipfel/scv-scan](https://github.com/kadenzipfel/scv-scan) | @0xkaden | Syntactic vulnerability scanning approach |
| [kadenzipfel/smart-contract-vulnerabilities](https://github.com/kadenzipfel/smart-contract-vulnerabilities) | @0xkaden | Vulnerability class index |
| [kadenzipfel/protocol-vulnerabilities-index](https://github.com/kadenzipfel/protocol-vulnerabilities-index) | @0xkaden | Protocol-specific vulnerability patterns |
| [quillai-network/qs_skills](https://github.com/quillai-network/qs_skills) | QuillAudits AI | Confidence scoring and multi-pass analysis |
| [Archethect/sc-auditor](https://github.com/Archethect/sc-auditor) | @Archethect | MAP-HUNT-ATTACK methodology |
| [hackenproof-public/skills](https://github.com/hackenproof-public/skills) | HackenProof | Audit skill templates |
| [forefy/.context](https://github.com/forefy/.context) | @forefy | Three-expert reasoning model |
| [alt-research/SolidityGuard](https://github.com/alt-research/SolidityGuard) | Alt Research | 104-pattern vulnerability taxonomy |
| [paradigmxyz/evmbench](https://github.com/paradigmxyz/evmbench) | Paradigm | EVM benchmark methodology |

The evaluation corpus uses [DeFiVulnLabs](https://github.com/SunWeb3Sec/DeFiVulnLabs) by @SunWeb3Sec.

## License

MIT
