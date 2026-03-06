---
name: solidsecs
description: |
  EVM/Solidity smart contract security audit skill. Activate when user asks to:
  "audit", "security review", "scan for vulnerabilities", "check this contract",
  "find bugs", "run slither", "fuzz this", "analyze security", "pentest this contract",
  or any request involving smart contract security, vulnerability detection, or exploit analysis.
  Orchestrates all available static analysis, fuzzing, and symbolic execution tools,
  then synthesizes findings into a professional severity-ranked markdown report.
version: 1.0.0
---

# EVM / Solidity Security Audit Skill

Full-spectrum security audit: tool execution → systematic manual analysis → professional report.

## Reference Files

Load these as needed during the audit:
- [`references/tools.md`](references/tools.md) — CLI invocations and output parsing for every tool
- [`references/vulnerability-taxonomy.md`](references/vulnerability-taxonomy.md) — Full vulnerability class index (ETH-001–ETH-110+)
- [`references/protocol-checklists.md`](references/protocol-checklists.md) — DeFi protocol-specific checklists (AMM, Lending, Vault, Bridge, Governance)
- [`references/secure-development-patterns.md`](references/secure-development-patterns.md) — OpenZeppelin library-first patterns and library misuse anti-patterns
- [`references/report-template.md`](references/report-template.md) — Professional report structure

---

## Core Principles (Non-Negotiable)

1. **Hypothesis-Driven** — Every finding is a theory. Attempt to falsify it before reporting.
2. **Evidence Required** — Cite exact `file:line`, paste code excerpts, explain attack path. No speculation.
3. **Semantic > Syntactic** — Understand *why* code is vulnerable, not just that a pattern matched.
4. **Cross-Reference** — Validate findings across multiple tools and manual analysis.
5. **Privileged Roles Are Honest** — Assume owner/admin keys are not compromised unless stated.
6. **Conservative Severity** — Downgrade if exploitability is theoretical or requires impractical conditions.

---

## Phase 0: Setup

### Determine Scope

Ask the user if not clear:
- Target: specific file(s), directory, or entire project?
- Audit depth: **Quick** (static analysis only), **Standard** (static + manual), **Deep** (all tools + fuzzing + PoC)?
- Protocol type: bare contract, DeFi (AMM/Lending/Vault/Bridge/Governance), NFT, Account Abstraction?
- Known focus areas: specific modules, recent changes, integration risks?

### Detect Project Framework

```bash
# Check for Foundry
ls foundry.toml forge.toml 2>/dev/null

# Check for Hardhat
ls hardhat.config.js hardhat.config.ts 2>/dev/null

# Check for Truffle
ls truffle-config.js 2>/dev/null

# Find all Solidity files
find . -name "*.sol" -not -path "*/node_modules/*" -not -path "*/lib/*" | head -50
```

### Detect Installed Tools

```bash
which slither aderyn myth medusa echidna halmos forge solhint semgrep wake pyrometer 2>/dev/null

# Nemesis is a Claude Code agent (no binary) — check for project install
ls .claude/commands/nemesis.md 2>/dev/null && echo "nemesis: available" || echo "nemesis: not installed"
```

Record which tools are available. Load `references/tools.md` for exact invocations.

> **Tool absence escalation:** When a priority-1 tool is missing, manually cover the vulnerability classes it specializes in:
> - No **Slither** → manually check: arbitrary ERC20 send/approve, unprotected `selfdestruct`, unchecked low-level calls, reentrancy, missing return values
> - No **Aderyn** → manually check: missing access control on all `public`/`external` state-changing functions
> - No **Mythril** → manually check: integer overflow in `unchecked` blocks, bad randomness, tx.origin auth
> - No **Semgrep** → manually apply the full Pass A grep block in Phase 3

---

## Phase 1: Automated Tool Execution

Run all available tools. Do **not** wait for one to finish before starting the next when they can run in parallel. Capture full output.

### Priority Order

| Priority | Tool | What It Catches |
|----------|------|----------------|
| 1 | **Slither** | 90+ detectors, fast, broad coverage |
| 1 | **Aderyn** | Missing access controls, common patterns |
| 2 | **Mythril** | Bytecode-level, symbolic execution |
| 2 | **Semgrep** | Pattern-based DeFi rules |
| 2 | **Nemesis** | Logic bugs + state desync (AI-agent, if installed) |
| 3 | **solhint** | Best practices, style violations |
| 3 | **Halmos** | Formal verification of existing tests |
| 4 | **Echidna/Medusa** | Property-based fuzzing (needs test harness) |
| 4 | **forge test** | Run existing fuzz/invariant tests |
| 5 | **Wake** | Python-based analysis framework |

See `references/tools.md` for exact CLI commands and output format notes.

### Nemesis Auditor (if installed)

If `.claude/commands/nemesis.md` is present in the project, run after static tools:

```
/nemesis
```

Or target a specific contract:
```
/nemesis --contract [ContractName]
```

Nemesis runs two complementary passes — Feynman (logic bugs) and State Inconsistency (state desync) — iteratively until convergence. Findings are written to `.audit/findings/`. See `references/tools.md` for full command reference.

### Tool Output Handling

For each tool:
1. Note severity/confidence levels as reported by the tool
2. Flag all High/Critical findings immediately
3. Collect all findings into a raw list — deduplication happens in Phase 4
4. Note which findings are likely false positives (mark with `[FP?]`)

---

## Phase 2: MAP — Architecture Understanding

Before hunting manually, build a mental model of the system.

### Entry Point Inventory

```bash
# Find all external/public functions
grep -n "function " $(find . -name "*.sol" -not -path "*/test*" -not -path "*/mock*") | grep -E "external|public"
```

Document:
- **State-changing entry points** — functions that modify storage
- **Privileged functions** — onlyOwner, onlyRole, onlyAdmin, etc.
- **Financial functions** — deposit, withdraw, mint, burn, swap, liquidate
- **Upgrade functions** — upgradeTo, initialize, reinitialize
- **Callback/hook receivers** — receive(), fallback(), onERC721Received(), uniswapV3SwapCallback(), etc.

### Invariant Extraction

Identify the protocol's core invariants — relationships that must always hold:
- Token accounting: `totalSupply == sum(balances)`
- Solvency: `totalAssets >= totalLiabilities`
- Access: "only the owner can call X"
- State machine: "funds can only flow in state Y"

These become the target of your attack phase.

### Privilege Boundary Map

```
[External Users] → [Entry Points] → [Core Logic] → [State/Funds]
                                  ↑
                         [Privileged Admins]
```

Identify every place that moves funds or modifies critical state. Map who can call what.

---

## Phase 3: HUNT — Systematic Vulnerability Sweep

Two passes over the codebase. Load `references/vulnerability-taxonomy.md` for full class descriptions.

> **Discipline:** Finding one vulnerability in a function is a signal to look **harder at that function**, not a reason to move on. Functions with one bug often have more. Complete all Pass B checks for the current function before proceeding to the next.

### Pass A: Syntactic (grep-based pattern matching)

Run these searches. Each hit requires semantic follow-up in Pass B.

```bash
SOL_FILES=$(find . -name "*.sol" -not -path "*/test*" -not -path "*/lib/*" -not -path "*/node_modules/*")

# Reentrancy indicators
grep -n "\.call{" $SOL_FILES
grep -n "\.delegatecall(" $SOL_FILES
grep -n "transfer\|send\b" $SOL_FILES

# Access control gaps
grep -n "function.*external\|function.*public" $SOL_FILES | grep -v "view\|pure\|onlyOwner\|onlyRole\|require\|modifier"

# Arithmetic risks
grep -n "unchecked {" $SOL_FILES
grep -n "\*\*\b" $SOL_FILES  # exponentiation

# External interactions
grep -n "IERC20\|SafeERC20\|\.transfer(\|\.transferFrom(" $SOL_FILES
grep -n "tx\.origin" $SOL_FILES
grep -n "block\.timestamp\|block\.number\|block\.difficulty" $SOL_FILES

# Oracle / price
grep -n "latestAnswer\|latestRoundData\|getPrice\|price\b" $SOL_FILES
grep -n "slot0\|observe\|sqrtPriceX96" $SOL_FILES  # Uniswap price

# Proxy patterns
grep -n "delegatecall\|initialize\|_init\b\|upgradeTo" $SOL_FILES
grep -n "selfdestruct\|SELFDESTRUCT" $SOL_FILES

# Signature / replay
grep -n "ecrecover\|ECDSA\|SignatureChecker" $SOL_FILES
grep -n "permit\b\|nonce\b" $SOL_FILES

# Flash loan entry points
grep -n "flashLoan\|executeOperation\|uniswapV3FlashCallback\|pancakeCall" $SOL_FILES

# ERC-4626 / vault math
grep -n "convertToShares\|convertToAssets\|previewDeposit\|previewMint" $SOL_FILES

# Approval targets — flag every approve for trust-boundary review (ETH-105)
grep -n "approve\|Approve\|setOperator\|setApprovalForAll" $SOL_FILES

# Calldata flow — interface calls on variable (non-constant) addresses
# Each hit: trace where the target address originates (param? storage? constant?)
grep -n "I[A-Z][a-zA-Z]*(" $SOL_FILES | grep -v "//\|interface\|event\|error"
grep -n "\.call(\|\.delegatecall(\|\.staticcall(" $SOL_FILES

# Library misuse — hand-rolled patterns that should use battle-tested libraries
# See references/secure-development-patterns.md for full context
grep -n "require(msg.sender ==" $SOL_FILES       # hand-rolled access control (should use Ownable/AccessControl)
grep -n "ecrecover(" $SOL_FILES | grep -v "ECDSA" # raw ecrecover (should use ECDSA.recover)
grep -n "bool.*locked\|bool.*entered" $SOL_FILES | grep -v "ReentrancyGuard" # custom reentrancy guard
grep -n "\.approve(" $SOL_FILES | grep -v "forceApprove\|safeApprove\|SafeERC20" # direct approve (USDT-incompatible)
```

### Pass B: Semantic Analysis

For every hit from Pass A, and for every critical path identified in Phase 2, apply semantic reasoning:

**Reentrancy Check:**
- Does state update happen BEFORE the external call? (CEI)
- Is there a `nonReentrant` modifier? Does it cover ALL paths including cross-function?
- Can an attacker-controlled contract receive control mid-execution?
- Is there read-only reentrancy exposing stale state to external view callers?

**Access Control Check:**
- Who can call each privileged function? Is the modifier correct?
- Is `tx.origin` used instead of `msg.sender`?
- Are proxy `initialize()` functions protected against re-initialization?
- Is there a 2-step ownership transfer?

**Arithmetic Check:**
- Are `unchecked` blocks safe from overflow given their context?
- Division before multiplication causing precision loss?
- Rounding direction — does rounding favor the protocol or the user?
- ERC-4626 share inflation attack on first deposit?

**Oracle / Price Check:**
- Is `latestRoundData` checking `updatedAt` staleness?
- Is the price coming from a spot price (manipulable) or TWAP?
- Can a flash loan manipulate the price oracle?
- Are there heartbeat and circuit breaker checks on Chainlink?

**External Call Check:**
- Are return values from `.call()` checked?
- Are ERC-20 return values checked? (use SafeERC20)
- Fee-on-transfer tokens: is pre/post balance comparison used?
- Rebasing tokens: are cached balances dangerous?
- ERC-777 / ERC-677 re-entrancy via hooks?

**Proxy / Upgrade Check:**
- Storage slot collision between proxy and implementation?
- Is `initialize()` called on the implementation directly?
- UUPS: is `_authorizeUpgrade` access-controlled?
- Storage gaps in base contracts?
- ERC-7201 namespaced storage used correctly?

**Signature / Replay Check:**
- EIP-712 domain separator includes `chainId` and `address(this)`?
- Nonce incremented atomically on use?
- Expiry timestamp checked?
- `ecrecover` return value checked for address(0)?
- Signature malleable (s value bounds, v value)?

**Approval Target Trust Check (ETH-105):**
For every `approve` / `safeApprove` / `setOperator` hit from Pass A:
- Is the spender address a **hardcoded constant**? → Safe
- Is the spender derived from a **trusted factory via CREATE2**? → Safe
- Is the spender taken from **user-supplied calldata / function parameters**? → **Critical risk** — attacker controls who gets approved
- Does the approval happen immediately before a **call into that same address**? → Compound risk: attacker can steal funds in the same transaction via `transferFrom`
- Does the approval **persist beyond the current transaction**? → Any future deposit of that token into the contract is at risk

**Calldata Flow Check:**
For every interface call on a variable target (from Pass A):
- Trace the target address back to its origin. Is it: (a) a hardcoded constant, (b) validated against a registry/allowlist, or (c) passed in from user calldata with no validation?
- If (c): treat as untrusted external call — apply full reentrancy, approval-theft, and return-value checks

**Library Misuse Check:**
Load `references/secure-development-patterns.md` and apply:
- Is custom access control missing two-step transfer or zero-address checks that `Ownable2Step` provides?
- Are raw `ecrecover` calls missing `s`-value validation and `address(0)` checks that `ECDSA.recover` provides?
- Are ERC-20 interactions using raw `.transfer()`/`.approve()` that fail on USDT/BNB instead of SafeERC20?
- Are upgradeable implementations missing `_disableInitializers()` in their constructors?
- Is copied library code missing security patches that the imported version would receive?
- Are OZ v4 hooks (`_beforeTokenTransfer`) used with OZ v5 imports where they silently never fire?

**DeFi Protocol Checks:**
Load `references/protocol-checklists.md` for the relevant protocol type and work through it systematically.

---

## Phase 4: ATTACK — Adversarial Deep Dive

For every High/Critical finding from Phases 1-3, attempt to:

1. **Construct a concrete attack scenario** — who is the attacker, what do they call, in what order, with what parameters?
2. **Trace the execution path** — follow the code step by step
3. **Quantify the impact** — what funds/state can be drained/corrupted?
4. **Attempt to falsify** — what assumptions must hold for this to be exploitable? Are those assumptions realistic?
5. **Write a PoC sketch** (or full Foundry test for Deep audits)

### Confidence Scoring

Assign each finding a confidence score:

| Score | Meaning |
|-------|---------|
| High (0.8–1.0) | Concrete exploit path confirmed, no unrealistic assumptions |
| Medium (0.5–0.79) | Plausible path, some conditions required |
| Low (0.2–0.49) | Theoretical, requires specific configuration or external factors |
| Noise (<0.2) | Discard or downgrade to Informational |

### Devil's Advocate

For each High+ finding, ask: "What would have to be true for this to NOT be exploitable?" Check each condition against the actual code.

---

## Phase 5: Synthesize

1. **Deduplicate** — tool findings often overlap. Group by root cause, not by tool.
2. **Rank by severity** using the matrix:

| | High Impact | Medium Impact | Low Impact |
|-|-------------|---------------|------------|
| **High Likelihood** | CRITICAL | HIGH | MEDIUM |
| **Medium Likelihood** | HIGH | MEDIUM | LOW |
| **Low Likelihood** | MEDIUM | LOW | INFO |

3. **Severity definitions:**
   - **Critical** — Direct loss of funds, complete protocol takeover, permanent freeze of all assets
   - **High** — Significant conditional loss, partial protocol control, temporary freeze
   - **Medium** — Functional impact without direct fund loss, griefing, logic errors
   - **Low** — Best practice violations, minor issues, gas inefficiencies with security implications
   - **Informational** — Code quality, style, non-security observations

4. **False Positive Filter** — remove findings that require:
   - Admin key compromise (unless trust model is explicitly trustless)
   - Unrealistic economic conditions (e.g., >50% of Ethereum hashrate)
   - Conditions that revert before reaching the vulnerable code

---

## Phase 6: Report

Generate the audit report at `audit-report.md` in the project root (or `.claude/audit-report.md`).

Load `references/report-template.md` for the full structure. Minimum sections:

```markdown
# Security Audit Report — [Project Name]

**Date:** [date]
**Auditor:** Claude (solidsecs skill)
**Scope:** [files audited]
**Tools Run:** [list]

## Executive Summary
[2–3 sentences: what was audited, how many findings by severity, overall risk level]

## Risk Score: [0–100]
[100 = no issues, 0 = do not deploy]

## Findings Summary
| # | Title | Severity | Status |
|---|-------|----------|--------|

## Detailed Findings
### [CRIT-01] Title
**Severity:** Critical
**Confidence:** High
**Location:** `Contract.sol:123`
**Description:** ...
**Impact:** ...
**Attack Path:** ...
**Proof of Concept:** (code if applicable)
**Recommendation:** ...

## Tool Output Summary
[One section per tool run, with key findings highlighted]

## Appendix: Informational / Gas
```

---

## Audit Depth Guidelines

| Depth | Phases | Expected Time | What's Included |
|-------|--------|---------------|-----------------|
| **Quick** | 0 + 1 | <5 min | Tools only, synthesized findings |
| **Standard** | 0–4 | 10–20 min | Tools + full manual analysis |
| **Deep** | 0–6 | 30–60 min | Everything + PoC + fuzzing setup |

Default to **Standard** unless specified. Offer Deep for critical DeFi protocols.

---

## Special Protocol Patterns

Load `references/protocol-checklists.md` and apply the matching checklist for:
- **AMM/DEX** — price oracle, slippage, sandwich attacks, LP math
- **Aggregator/Router** — pool address validation, route injection, arbitrary approve, multicall msg.value reuse
- **Lending** — liquidation logic, interest accrual, collateral math, bad debt
- **Vault (ERC-4626)** — share inflation, rounding direction, emergency pause
- **Bridge** — message replay, merkle proof verification, validator set
- **Governance** — flash loan voting, proposal hijacking, timelock bypass
- **Proxy/Upgradeable** — storage layout, initialization, authorization
- **Account Abstraction (ERC-4337)** — paymaster exploitation, bundler DoS
- **Uniswap V4 Hooks** — callback authorization, hook data manipulation, cached state
