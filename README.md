# evm-audit — Claude Code Plugin

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
git clone https://github.com/carni-ships/SolidSecs ~/.claude/plugins/evm-audit
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
The `evm-audit` skill activates automatically when you say things like:
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
- `skills/evm-audit/references/tools.md` — CLI invocations for 12+ tools
- `skills/evm-audit/references/vulnerability-taxonomy.md` — ETH-001–ETH-096+ index
- `skills/evm-audit/references/protocol-checklists.md` — Protocol-specific checks
- `skills/evm-audit/references/report-template.md` — Report structure

## License

MIT
