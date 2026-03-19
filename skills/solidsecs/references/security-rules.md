# Security Analysis Rules

17 universal rules for smart contract vulnerability analysis. Apply throughout Phases 3 and 4.
Reference these when assigning verdicts, escalating findings, and evaluating severity.

---

## Rules

### R1: External Call Return Type Verification
All external calls must have return values verified. ERC-20 `.transfer()`, low-level `.call()`, and interface calls on variable addresses can all fail silently.
- **Trigger:** `.call()`, `.transfer()`, `.send()`, interface calls on non-constant addresses
- **Check:** Is the bool return checked? Is SafeERC20 used for ERC-20?

### R2: Function Preconditions Are Griefable (Bidirectional)
Any `require()` dependent on external state is a potential griefing vector. Analyze both directions:
- User → function: can crafted inputs permanently block the function?
- Admin → user: can parameter changes strand user funds or block withdrawals?
- **Trigger:** `require()` dependent on mutable state, oracle prices, or configurable parameters

### R3: Transfer Side Effects
Before trusting token amounts:
- Yield-bearing tokens (ERC-4626): amount received ≠ amount sent
- Rebasing tokens (stETH, AMPL): cached balance goes stale
- ERC-777: `tokensToSend`/`tokensReceived` hooks fire — reentrancy risk
- Fee-on-transfer: received < sent
- **Check:** Does the protocol measure balance deltas (correct) or trust parameter values (wrong)?

### R4: Uncertainty → CONTESTED + Adversarial Assumption
When you cannot confirm or refute with certainty, mark as CONTESTED. For unknown external contracts, apply the adversarial assumption: assume they steal funds, revert, or reenter.

### R5: Combinatorial Impact Analysis
Evaluate the worst-case scenario across all N affected entities. A "Low" bug per-user may be "Critical" when all users are attacked simultaneously.
- **Question:** What is total protocol-wide impact if every affected entity is exploited at once?

### R6: Semi-Trusted Role Bidirectional Analysis
For every privileged role (owner, admin, guardian, operator):
- **Role → Users:** Can the role harm users? (rug, freeze, drain, front-run)
- **Users → Role:** Can a user exploit role-dependent behavior? (front-run admin txs, grief role operations)
- **Severity:** Reduce 1 tier for FULLY_TRUSTED roles (explicitly trusted in scope). Floor: Informational.

### R7: Donation-Based DoS via Threshold Manipulation
If a function has a threshold (min balance, supply cap, quorum, circuit breaker), check whether a donation can push it past or below the threshold permanently, blocking expected state transitions.
- **Pattern:** `token.balanceOf(address(this))` used as threshold
- **Classic:** Vault `require(totalAssets() > minBalance)` — donation strands first depositor

### R8: Cached Parameters in Multi-Step Operations
State captured at step 1 may be stale by step N:
- External price/balance cached before an external call, used after
- Admin parameter changed between validation and execution of a user operation
- **Check:** Is any value read once and used again after an external call or state change?

### R9: Stranded Asset Severity Floor
Code paths that can permanently strand user funds are at minimum **Medium** severity, regardless of likelihood. Locked ETH/tokens are a real loss even behind a precondition.

### R10: Worst-State Severity Calibration
Severity is determined by the worst achievable state, not the expected state. Rate findings at their maximum-impact exploit scenario, not the average case.

### R11: Unsolicited Token Transfer (5 Dimensions)
When a contract can receive unexpected tokens (outside normal deposit flows), check:
1. Are incoming funds correctly attributed to the sender?
2. Can donation of dust manipulate share/price calculations?
3. Can donation inflate `totalAssets()` to steal from other depositors?
4. Can donation trigger circuit breakers or thresholds?
5. What happens with non-standard ERC-20 (fee-on-transfer, rebasing)?

### R12: Exhaustive Enabler Enumeration
For "who can trigger this?" analysis, enumerate all 5 actor categories:
1. Anyone (no restrictions)
2. Any token holder (ERC-20 transfer, permit)
3. Any depositor / liquidity provider
4. Liquidators / external protocol actors
5. Governance / admin (with timelock delay)

### R13: User Impact Evaluation (Anti-Normalization)
Do not reduce severity based on "user can just avoid this." If the protocol advertises feature X, users WILL use feature X. Model passive attack: what is the worst outcome for a user who interacts normally during an active exploit?

### R14: Cross-Variable Invariant Verification
When a setter modifies parameter A, check all variables that must stay consistent with A:
- Does changing `fee` break the invariant `fee < 100%`?
- Does changing `collateralFactor` invalidate existing open positions?
- Does changing `interestRate` violate current borrower expectations?
- **Check:** For each setter, list invariants that depend on the modified variable.

### R15: Flash Loan Precondition Manipulation
For every key state variable used in critical decisions (price, balance, collateral ratio, voting power):
- Can a flash loan push this variable to an attacker-favorable value?
- Even if state is restored at end of tx, was there an intermediate-state exploit?
- **Scope:** Flash loans can temporarily make `totalSupply` huge, `price` tiny, `balance` enormous

### R16: Oracle Integrity (6 Failure Modes)
For every oracle integration, check all 6:
1. **Staleness** — is `updatedAt` checked against `block.timestamp - MAX_DELAY`?
2. **Decimal mismatch** — is decimal scale normalized? (`grep: 10\*\*|decimals()|1e[0-9]|normaliz`)
3. **Zero price** — is `price > 0` asserted?
4. **Negative price** — is `int` price cast to `uint` safely?
5. **TWAP manipulation** — is TWAP window ≥ 30 min for Uniswap V3?
6. **Circuit breaker bounds** — are Chainlink `minAnswer`/`maxAnswer` bounds validated?

### R17: State Transition Completeness (Symmetric Branch Analysis)
For every conditional branch, verify symmetric handling:
- If the `if` branch updates variable X, does `else` also handle X (or intentionally not)?
- For state machines: are all valid transitions enumerated? Are any missing?
- **Pattern:** `if (cond) { A = 1; B = 2; } else { A = 0; }` — missing `B = 0` in else

### R18: Config Unit Semantics (Semantic Drift Detection)
Before tracing any config variable through the codebase, identify its unit:

| Unit | Meaning | Safe divisor | Example |
|------|---------|-------------|---------|
| `percent` | 0–100 scale | Divide by `100` | `fee = 5` → `amount * 5 / 100` |
| `basis_points` | 0–10000 scale | Divide by `10_000` | `fee = 50` → `amount * 50 / 10_000` |
| `divisor` | Denominator directly | Divide by value | `fee = 20` → `amount / 20` |
| `wei` | Raw token units | No division | `minDeposit = 1e18` |
| `seconds` | Time duration | Context-dependent | `lockPeriod = 7 days` |
| `raw` | Unitless scalar | Context-dependent | `multiplier = 2` |

**Check:** Does every consumer of this variable use the same unit? Mismatches cause silent 10x–100x mispricing.

**Canonical failure:** Variable named `taxCut` — one consumer divides by it (divisor semantics, `amount / taxCut`), another multiplies then divides by 100 (percent semantics, `amount * taxCut / 100`). At `taxCut = 10`: one path pays 10%, other pays `amount / 10` = also 10% — looks fine until `taxCut = 50`: one pays 50%, other pays `1/50 = 2%`.

**Grep sweep for semantic drift:**
```bash
# Find all fee/rate/basis variables and their usage
grep -n "fee\|rate\|basis\|percent\|divisor\|bps\|taxCut\|rewardRate" \
  $(find . -name "*.sol" -not -path "*/test*" -not -path "*/lib/*") | \
  grep -v "//\|event\|error"
```

For each hit: identify unit, check all consumers use the same unit, check conversion is explicit at module boundaries.

### R19: Symmetric Operation Invariant
For every paired operation (deposit/withdraw, mint/burn, stake/unstake), verify:
```
deposit(X) → ... → withdraw() ≥ X - declared_fees
```
Any shortfall beyond declared fees is a finding. Construct the invariant test mentally (or as a Foundry test) for the three boundary cases:
- **Zero:** `deposit(0)` — does it revert cleanly or silently succeed with broken state?
- **Dust:** `deposit(1 wei)` — is rounding so aggressive that the user gets 0 shares/assets back?
- **Maximum:** `deposit(type(uint).max)` — does it overflow or hit a cap gracefully?

Also check **multi-hop fee compounding**: if a route involves N steps each taking a fee, is the total fee `sum(fees_i)` or `product(1 - fee_i)` — and is the expected total communicated and validated?

---

## Evidence Source Enforcement

| Evidence Type | Can Support CONFIRMED | Can Support REFUTED |
|--------------|----------------------|---------------------|
| `[TRACE:]` code path execution | ✓ | ✓ |
| `[BOUNDARY:]` value analysis | ✓ | ✓ |
| `[VARIATION:]` test variant | ✓ | ✓ |
| `[POC-PASS]` / `[MEDUSA-PASS]` | ✓ (strongest) | — |
| Documentation / comments | PARTIAL only | CONTESTED only |
| Mock / assumption about external | PARTIAL only | ✗ (cannot refute) |

For unknown external contract behavior: always apply R4 adversarial assumption before marking REFUTED.
