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
- [`references/protocol-checklists.md`](references/protocol-checklists.md) — DeFi protocol-specific checklists (AMM, Lending, Vault, Bridge, Governance, Flash Loan, Oracle)
- [`references/security-rules.md`](references/security-rules.md) — R1–R19 universal analysis rules (confidence, escalation, severity calibration, semantic drift, symmetric operation)
- [`references/devil-advocate-protocol.md`](references/devil-advocate-protocol.md) — Formal 6-dimension DA scoring (guards, reentrancy, access, by-design, economics, dry-run)
- [`references/hard-negatives.md`](references/hard-negatives.md) — Safe patterns that resemble vulnerabilities (graduated handling rule)
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

**Solodit MCP (claudit):** If `mcp__solodit__search_findings` is available, Solodit prior-art search is active. No binary check needed — it's an MCP tool. Install with:
```bash
claude mcp add --scope user --transport stdio solodit \
  --env SOLODIT_API_KEY=sk_your_key_here \
  -- npx -y @marchev/claudit
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
| 2 | **Solodit** | Prior art from 20k+ real audit findings (MCP, if installed) |
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

### Protocol Classification (Injectable Skills)

Based on code patterns found in Phase 0 and tool output, set protocol type flags. Each flag activates a targeted deep-dive section in `references/protocol-checklists.md`.

```bash
SOL_FILES=$(find . -name "*.sol" -not -path "*/test*" -not -path "*/lib/*")

# FLASH_LOAN — flash loan entry points or callbacks present
grep -lE "flashLoan|executeOperation|uniswapV3FlashCallback|pancakeCall|onFlashLoan" $SOL_FILES

# ORACLE — price oracle consumption present
grep -lE "latestRoundData|latestAnswer|getPrice|slot0|sqrtPriceX96|TWAP|twapPrice" $SOL_FILES

# vault — ERC-4626 or share-based vault patterns
grep -lE "convertToShares|convertToAssets|totalAssets|previewDeposit|previewMint" $SOL_FILES

# lending — borrowing and liquidation patterns
grep -lE "liquidate|borrow|repay|collateral|LTV|healthFactor|interestRate|debtToken" $SOL_FILES

# governance — on-chain voting or proposal system
grep -lE "Governor|Timelock|propose|castVote|quorum|delegate\b" $SOL_FILES

# dex_integration — protocol USES a DEX (not IS a DEX)
grep -lE "IUniswapV2Router|IUniswapV3|addLiquidity|swapExactTokens|amountOutMin" $SOL_FILES
```

For each flag set, load the corresponding section from `references/protocol-checklists.md` and work through it systematically during Phase 3 Pass B. Do **not** load all sections — only the ones triggered by actual code patterns.

> Never merge `FLASH_LOAN` or `ORACLE` analysis with other protocol work — they require dedicated sequential analysis.

### Invariant Extraction

Identify the protocol's core invariants — relationships that must always hold:
- Token accounting: `totalSupply == sum(balances)`
- Solvency: `totalAssets >= totalLiabilities`
- Access: "only the owner can call X"
- State machine: "funds can only flow in state Y"

These become the target of your attack phase.

### Config Semantics Inventory (R18)

For each config/parameter variable found in Phase 2, record:

| Variable | Unit (`percent`/`basis_points`/`divisor`/`wei`/`seconds`/`raw`) | Valid range | Consumers |
|----------|----------------------------------------------------------------|-------------|-----------|
| `fee` | basis_points | 0–10000 | `_takeFee()`, `previewDeposit()` |
| ... | ... | ... | ... |

Flag any variable where consumers use different divisors or scales — this is a semantic drift bug (R18).

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
Load `references/protocol-checklists.md` for the protocol types flagged in Phase 2. Apply `FLASH_LOAN` and `ORACLE` sections if those flags are set — these are sequential and must not be skipped.

**Universal Rule Application:**
After completing Pass B checks, apply `references/security-rules.md` R1–R19 as a final sweep. Specifically:
- R5 (combinatorial): have you evaluated all-users-affected scenario?
- R8 (cached params): are there multi-step operations with stale state?
- R11 (donation): can unsolicited token transfers manipulate accounting?
- R14 (cross-variable): does each setter maintain all dependent invariants?
- R18 (config unit semantics): cross-check the config semantics inventory from Phase 2 — any consumer using a different unit than the canonical definition?
- R19 (symmetric operation): for each deposit/withdraw or stake/unstake pair, does `deposit(X) → withdraw()` return exactly `X - declared_fees`?

### Pass D: Semantic Drift Sweep

Run this sweep for every config variable identified in Phase 2's config semantics inventory:

```bash
# For each fee/rate/basis variable, find all formula usages
grep -n "taxCut\|feeRate\|rewardRate\|basisPoints\|percent\|divisor" \
  $(find . -name "*.sol" -not -path "*/test*" -not -path "*/lib/*")
```

For each hit, verify:
- [ ] Divisor used matches the variable's declared unit (R18)
- [ ] Same formula not duplicated with a different constant (semantic drift)
- [ ] Magic numbers (`100`, `10_000`, `1e18`) consistent across all uses
- [ ] Per-second and per-block rate calculations not mixed
- [ ] Chainlink oracle decimals explicitly normalized before use (8-decimal feed + 18-decimal math)

Check `references/hard-negatives.md` Category 5 before flagging — some apparent drifts are safe by design.

### Pass C: Prior Art — Solodit Research (if MCP available)

After completing Pass B, use Solodit to cross-reference every candidate finding against real audit history. This validates severity, surfaces missed variants, and provides citation evidence for the report.

**For each High/Critical candidate finding:**
```
mcp__solodit__search_findings(
  keywords="<vulnerability type> <protocol pattern>",
  severity=["HIGH", "CRITICAL"],
  sort_by="Quality"
)
```

**Useful search patterns:**

```
# Reentrancy in a specific protocol type
search_findings(keywords="reentrancy lending protocol", severity=["HIGH"])

# Oracle manipulation
search_findings(tags=["Oracle", "Price Manipulation"], severity=["HIGH", "MEDIUM"], sort_by="Quality")

# Flash loan attack variants
search_findings(keywords="flash loan", tags=["Flash Loan"], severity=["HIGH"])

# Access control on initialize
search_findings(keywords="initialize access control proxy", severity=["HIGH", "CRITICAL"])

# Signature replay
search_findings(tags=["Signature Replay", "Replay Attack"], sort_by="Quality")

# Discover valid tags and firms first
mcp__solodit__get_filter_options()
```

**Interpret results:**
- **Many similar HIGH findings** → well-known pattern; severity validated; cite top findings in report
- **Rare / no prior findings** → novel or niche; apply extra skepticism OR flag as noteworthy
- **Finding has quality score 4–5** → well-written, high-signal; read full details via `get_finding`
- **Solo findings (max_finders=1)** → more likely novel; compare carefully against your candidate

Use `mcp__solodit__get_finding(id)` to pull full write-ups for the top 1–2 most relevant matches and reference them in your report.

See `references/tools.md` for full Solodit MCP command reference.

---

## Phase 4: ATTACK — Adversarial Deep Dive

For every High/Critical finding from Phases 1-3, attempt to:

1. **Construct a concrete attack scenario** — who is the attacker, what do they call, in what order, with what parameters?
2. **Trace the execution path** — follow the code step by step
3. **Quantify the impact** — what funds/state can be drained/corrupted?
4. **Attempt to falsify** — what assumptions must hold for this to be exploitable? Are those assumptions realistic?
5. **Write a PoC sketch** (or full Foundry test for Deep audits)

### Confidence Scoring (4-Axis Model)

Assign each finding a composite confidence score using these four axes:

**Axis 1 — Evidence (weight: 25%)**

| Tag | Score |
|-----|-------|
| `[POC-PASS]` or `[MEDUSA-PASS]` | 1.0 |
| `[TRACE:path→outcome]` full execution trace | 0.8 |
| `[BOUNDARY:X=val]` boundary value confirmed | 0.7 |
| `[VARIATION:param A→B]` variant tested | 0.6 |
| Code read, no execution trace | 0.4 |
| Pattern match only, no code trace | 0.2 |

**Axis 2 — Analysis Quality (weight: 30%)**
Score = (number of distinct evidence tags used) / 4, capped at 1.0.
If Step 5+ of a dedicated skill checklist was reached: +0.1 bonus.

**Axis 3 — Prior Art Match (weight: 20%)**
- Strong Solodit match (≥3 similar HIGH findings): 0.9
- Some prior art found (1–2 similar findings): 0.6
- No prior art, novel pattern: 0.4
- No Solodit search performed: 0.3

**Axis 4 — Adversarial Assumption (weight: 25%)**
- R4 applied, worst-case external behavior modeled: 0.9
- Partial adversarial modeling: 0.6
- Optimistic assumptions about external contracts: 0.2

**Composite:** `Evidence×0.25 + Quality×0.30 + PriorArt×0.20 + Adversarial×0.25`

**Routing:**
| Score | Verdict | Action |
|-------|---------|--------|
| ≥ 0.70 | CONFIRMED | Report with full evidence |
| 0.40–0.69 | PARTIAL | Attempt PoC or variant; if still uncertain → CONTESTED |
| < 0.40 | CONTESTED | Apply devil's advocate; search Solodit; re-evaluate |

**Verdict definitions:**
- **CONFIRMED** — Concrete attack path traced end-to-end, `[POC-PASS]` or equivalent
- **PARTIAL** — Plausible path with some uncertain conditions; report with caveats
- **CONTESTED** — Real uncertainty; report if Medium+, mark clearly as contested
- **REFUTED** — Cannot reach vulnerable code under any realistic conditions; discard (note: external contract behavior cannot support REFUTED — apply R4)

### Devil's Advocate — Formal DA Protocol

For every High+ finding (and any CONTESTED Medium), run the full 6-dimension DA evaluation from `references/devil-advocate-protocol.md`:

1. **guards** — search for `require`/`assert`/modifier blocks on any attack step
2. **reentrancy_protection** — check `nonReentrant`, CEI on affected AND cross-contract paths
3. **access_control** — verify attacker can actually reach each function (apply Privilege Rule: do NOT dismiss for admin-only paths that can enable unprivileged exploits)
4. **by_design** — search NatSpec, README, docs for documented behavior
5. **economic_feasibility** — estimate capital, gas, profit; cost > yield = −1 partial
6. **dry_run** — trace exploit with concrete values through all arithmetic

Sum scores → route: INVALIDATED (total ≤ −6 with one −3) / DEGRADED / SUSTAINED / ESCALATED.

**Before dismissing any finding as false-positive**, check `references/hard-negatives.md` for matching safe patterns. Apply the graduated handling rule: full match = degrade 1 tier + annotate (still emit); partial match = original severity + note unmet conditions.

### PoC Execution Evidence Tags

Use these tags consistently in finding writeups:
- `[POC-PASS]` — Foundry test passed; CONFIRMED verdict supported
- `[POC-FAIL]` — Test written but fails; finding downgraded to PARTIAL
- `[MEDUSA-PASS]` — Medusa/Echidna property broken; CONFIRMED verdict supported
- `[CODE-TRACE]` — Manual execution trace without running test
- `[BOUNDARY:X=val]` — Boundary condition verified at specific value
- `[VARIATION:A→B]` — Variant of the attack path tested

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
