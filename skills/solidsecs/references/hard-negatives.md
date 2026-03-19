# Hard-Negative Reference

Patterns that look like vulnerabilities but are safe when specific conditions are met.
Use during Phase 3 Pass B and Phase 4 ATTACK to avoid false positives.

## Graduated Handling Rule (MANDATORY)

Never dismiss a finding solely because a hard-negative partially matches. Apply the following:

| Match level | Action |
|-------------|--------|
| **Full match** — all key indicators present | Degrade severity 1 tier + annotate finding with the safe pattern + still emit |
| **Partial match** — some indicators present, not all | Emit at original severity + note which conditions were NOT met |
| **No match** | Emit at original severity |

---

## Category 1: Approval Abuse

### Safe: Unlimited Approval to Immutable Router
Looks bad because `type(uint256).max` approval persists indefinitely.
**Key indicators (all required for full match):**
- Approved contract has no proxy pattern (no `delegatecall`, no UUPS, no transparent proxy)
- No `selfdestruct` or `delegatecall` to user-supplied targets in approved contract
- Contract verified on-chain with source matching a known, long-deployed, well-audited protocol
- Approval set in constructor/initializer, not by arbitrary users
- No admin function can alter the contract's `transferFrom` behavior

### Safe: Approve-Transfer-Revoke in Single Transaction
Looks bad because `approve → transferFrom` appears to have a front-run window.
**Key indicators (all required for full match):**
- `approve`, `transferFrom`, and `approve(spender, 0)` called sequentially in one function
- No external calls or callbacks between approve and transfer
- Approval revocation (`approve(spender, 0)`) is unconditional (not behind an if)
- Function is not payable

### Safe: SafeERC20 forceApprove / Zero-then-Set
Looks bad because `approve` has a known race condition.
**Key indicators:**
- Uses `SafeERC20.forceApprove(token, spender, amount)` (OZ v5+) or zero-then-set pattern (OZ v4)
- `SafeERC20` imported from reputable source
- Pattern applied consistently across all approval sites (no mixed raw `approve` usage)

### Safe: Permit2 with Signature and Deadline
Looks bad because users still grant an initial approval.
**Key indicators:**
- Integrates with Uniswap Permit2 (`0x000000000022D473030F116dDEE9F6B43aC78BA3`)
- Signatures include deadline parameter checked on-chain
- `permitTransferFrom` used (single-use permits), not persistent `approve`
- Nonce management prevents replay

### Safe: Approval to Timelock-Protected Upgradeable Contract
Looks bad because a malicious upgrade could drain approved tokens.
**Key indicators:**
- Timelock has minimum delay ≥ 48 hours
- Timelock delay cannot be shortened without going through the same timelock
- Governance requires quorum + multiple approvals
- Users have tooling to review and revoke approvals before upgrade executes

---

## Category 2: Callback Grief

### Safe: External Call in Bounded Loop with Skip Logic
Looks bad because one reverting target could block the whole batch.
**Key indicators (all required for full match):**
- Loop bound is protocol-controlled with an enforced maximum (not user-appendable)
- Each call is wrapped in `try/catch` with meaningful handling (not `revert` in catch)
- Catch block skips the failed target with an event/log, does not abort batch
- Gas forwarded per call is explicitly limited

### Safe: ERC-721 `safeTransferFrom` After State Updates
Looks bad because `onERC721Received` allows arbitrary callback execution.
**Key indicators:**
- `safeTransferFrom` is the last operation (all state changes complete before the call)
- Calling function has `nonReentrant` modifier or equivalent
- No state reads after the transfer that depend on state changeable via reentrancy

### Safe: Flash Loan Callback to Known Contract
Looks bad because the callback can execute arbitrary logic with borrowed funds.
**Key indicators:**
- Post-callback balance check enforces `balance >= balanceBefore + fee`
- Critical protocol state is checkpointed before callback and validated after
- Flash loan function has reentrancy guard preventing nested flash loans

### Safe: ETH Transfer via `.call` to `msg.sender`
Looks bad because msg.sender fallback can reenter.
**Key indicators:**
- Recipient is `msg.sender` (self-grief only — sender has no incentive to block their own payment)
- All state updates complete before the transfer (CEI)
- Return value checked and failure handled

---

## Category 3: Entitlement Drift

### Safe: Lazy Reward Update (MasterChef Pattern)
Looks bad because user's reward record looks stale between interactions.
**Key indicators (all required for full match):**
- Catch-up calculation runs as the first operation in every state-changing function
- Pattern: (1) calculate pending delta, (2) update user checkpoint to current accumulator, (3) transfer, (4) adjust stake
- `rewardPerShare` is monotonically increasing (never decreases)
- No external calls between reward calculation and checkpoint update

### Safe: Fee-on-Transfer Token Exclusion by Design
Looks bad because recorded balance exceeds actual balance for fee-on-transfer tokens.
**Key indicators:**
- Protocol documentation explicitly states fee-on-transfer tokens are not supported
- Token whitelist enforced on deposit
- No claim of "supporting all ERC-20 tokens"

### Safe: Epoch-Based Settlement with Clear Boundaries
Looks bad because users don't earn rewards for the deposit epoch.
**Key indicators:**
- Epoch boundaries applied uniformly to all users (no special treatment)
- Deposits during epoch N participate from epoch N+1 (anti-flash-deposit)
- No way to deposit and claim in the same epoch

### Safe: Internal Accounting (Separate from `balanceOf`)
Looks bad because internal balance diverges from actual token balance on donation.
**Key indicators:**
- Internal `totalDeposited` counter used for share math (not `token.balanceOf(this)`)
- No `sync()` function that overwrites internal balance from actual balance
- Invariant maintained: `internalBalance <= actualBalance`

---

## Category 4: Rounding Entitlement

### Safe: Small Rounding Loss with Minimum Amount Enforcement
Looks bad because dust truncation slightly underpays users.
**Key indicators:**
- Rounding loss is bounded by 1 wei per operation (integer division)
- Minimum deposit/withdrawal amounts prevent dust-level share manipulation
- Rounding always favors the protocol, never the user (consistent direction)

### Safe: First-Depositor Dead Shares
Looks bad because the deployer "wastes" shares on a dead address.
**Key indicators:**
- Deployer mints a minimum amount of shares to a burn address on deployment
- Dead shares make the share price non-trivially high from the start
- Amount burned is large enough to make first-depositor inflation attacks unprofitable

### Safe: Virtual Offset via `_decimalsOffset()`
Looks bad because share math looks off by a large factor.
**Key indicators:**
- Contract uses OZ ERC-4626's `_decimalsOffset()` override returning > 0
- All share math consistently uses `10 ** (_decimals + _decimalsOffset())` as the scale
- Virtual shares effectively add `10 ** offset` dead shares, preventing inflation

### Safe: Internal Accounting Prevents Donation-Based Share Manipulation
(see Category 3 — Internal Accounting)

### Safe: Consistent Rounding Direction Across All Operations
Looks bad because truncation appears to extract value from users.
**Key indicators:**
- `convertToShares` rounds DOWN (deposit: user gets fewer shares → protects protocol)
- `convertToAssets` rounds DOWN (redeem: user gets fewer assets → protects protocol)
- Rounding direction is verified identical across all preview functions and execution paths
- Any deviation in rounding direction between preview and execution would violate ERC-4626

---

## Category 5: Semantic Drift

### Safe: Different Fee Representations in Different Modules
Looks bad because the "same" fee variable has different divisors in different places.
**Key indicators:**
- Each module's internal fee representation is documented (NatSpec or README)
- Conversion between representations happens at clear, explicit module boundaries
- No code path passes a fee value from one module directly to another without explicit conversion

### Safe: Governance-Adjustable Parameters with Validated Bounds
Looks bad because a parameter can be set to values that appear to break invariants.
**Key indicators:**
- Every parameter setter has `require` bounds (not just type-level bounds)
- Bounds are tight enough to prevent economic attack (e.g., fee cannot be set to 100%)
- Timelocked governance required to change parameters (users can exit before change takes effect)

### Safe: Named Constants with Different Values for Different Contexts
Looks bad because `MAX_REWARD_RATE` in contract A ≠ `MAX_REWARD_RATE` in contract B.
**Key indicators:**
- Constants are defined locally and used only within the same contract/module
- No cross-contract comparison or assignment of these constants
- Different values are documented as intentional (different economic contexts)

### Safe: Duplicated Formula with Intentionally Different Divisor
Looks bad because two nearly-identical formulas use different constants.
**Key indicators:**
- Formulas operate on values with different scales (one uses wei, one uses tokens)
- Comments explain the different divisor
- The formulas' outputs are never compared directly or used interchangeably
