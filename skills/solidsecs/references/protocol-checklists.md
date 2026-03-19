# Protocol-Specific Audit Checklists

Apply the relevant checklist(s) during Phase 3 of the audit.

---

## Aggregator / Router

Applies to: swap aggregators, multi-AMM routers, meta-routers, intent-based executors.

### Trust Boundaries
- [ ] **Pool/protocol addresses validated?** Are all external call targets (pools, protocols) either hardcoded constants, derived from a trusted factory, or checked against an on-chain allowlist? Any user-supplied address that receives an `approve()` or is called into is a critical risk.
- [ ] **Route/path parameter trusted?** If the route is user-supplied calldata (e.g., `address[] route`, `bytes path`), can an attacker inject a malicious contract address at any hop?
- [ ] **Lazy-approve pattern safe?** If the router does `if (allowance == 0) approve(pool, MAX)` before calling into `pool`, is `pool` validated? An unvalidated lazy-approve to a user-supplied address grants permanent max approval.
- [ ] **Executor/solver trusted?** Generic executor patterns (`execute(target, data)`, `snwap`) — is `target` restricted to an allowlist? Can the executor re-enter the router or pull approved tokens?

### Multicall Safety
- [ ] **msg.value reuse in payable multicall?** If `multicall` uses `delegatecall` and is `payable`, can `msg.value` be credited multiple times to internal accounting (e.g., transient deposit) with only one real ETH deposit?
- [ ] **Callback lock during execute?** If the router has V3/V4 callbacks (`fallback`, `unlockCallback`), are they blocked during generic execution paths to prevent re-entry via a malicious target?
- [ ] **Residual balance swept?** Can funds temporarily held by the router mid-multicall be front-run by a third party calling `sweep()` or equivalent before the user completes their sequence?

### Callback Authentication
- [ ] **V3 callback authenticated?** `uniswapV3SwapCallback` / `fallback` — is `msg.sender` verified against the deterministically computed pool address? Are callback parameters (payer, token, amount) from the original call, not attacker-supplied?
- [ ] **V4 unlock callback authenticated?** `unlockCallback` — is `msg.sender == poolManager`?
- [ ] **Arbitrary callback data?** If callback data is user-controlled, can an attacker influence the callback handler's behaviour?

### Slippage & Output
- [ ] **Per-hop slippage?** Multi-hop routes that pass `min_dy = 0` / `minAmountOut = 0` to each intermediate AMM allow sandwich attacks on individual hops even when end-to-end slippage is checked.
- [ ] **Output verified correctly?** Is output measured by pre/post balance delta (correct) or by return value from potentially untrustworthy pool (wrong)?
- [ ] **Exact-out overpay refunded?** For exact-output swaps, is excess input always refunded to the original payer?

### Token Handling
- [ ] **Permit functions forward to correct spender?** `permit(token, ..., v, r, s)` — does it approve `address(this)` (correct) or an arbitrary address?
- [ ] **Fee-on-transfer tokens?** If input or output token charges fees on transfer, is the received amount measured by balance delta?
- [ ] **Stale token approvals?** Does the router permanently approve external pools for ERC20 tokens? Can those approvals be exploited in future transactions?

---

## AMM / DEX

- [ ] Price oracle: is it TWAP (safe) or spot (manipulable)?
- [ ] Flash loan manipulation: can pool price be moved in single tx to exploit this protocol?
- [ ] Slippage protection: are all swap/liquidity functions protected with min/max bounds?
- [ ] Sandwich attack: are deadline + slippage params validated (not `0` or `type(uint256).max`)?
- [ ] LP token pricing: is LP price derived from invariant (safe) or reserves (manipulable)?
- [ ] Fee accounting: can fees be bypassed or double-counted?
- [ ] Liquidity removal: are LP tokens burned atomically with asset returns?
- [ ] Reentrancy in callback: `uniswapV2Call`, `uniswapV3SwapCallback`, etc. — is CEI followed?
- [ ] Token compatibility: fee-on-transfer, rebasing, non-standard ERC-20?
- [ ] MEV / front-running: can trades be front-run profitably?
- [ ] Rounding: does rounding favor users or protocol in critical math?

---

## Lending / Borrowing

### Health Factor & Liquidation
- [ ] Collateral ratio: correct calculation, no precision loss?
- [ ] **Health factor boundary (HIGH risk):** What happens at exactly `healthFactor == 1.0`? Can a borrower manipulate state to be simultaneously liquidatable and not-liquidatable?
- [ ] **Health factor rounding:** Does rounding direction of health factor calculation favor borrower (dangerous) or protocol?
- [ ] Liquidation logic: can undercollateralized positions always be liquidated profitably?
- [ ] Liquidation incentive: is the incentive enough for liquidators? Is there a max (to cap bad debt)?
- [ ] **Liquidation DoS:** Can a borrower front-run liquidation to become healthy again? Can they revert the liquidator's tx (R2)?
- [ ] Bad debt: can bad debt accumulate without a recovery mechanism?
- [ ] **Bad debt socialization:** When bad debt is socialized across depositors, is the accounting correct? Can bad debt be created by liquidating more collateral than exists?

### Interest Accrual
- [ ] Is `accrueInterest()` called before every state-changing operation?
- [ ] **Accrual frequency:** Is interest rate used correctly (per-block vs per-second)? Can an attacker accrue interest 0 times to borrow at stale rates?
- [ ] Interest rate model: is rate capped to prevent overflow? What happens at 100% utilization?
- [ ] Debt token math: can interest-bearing debt tokens be used to manipulate share price (first-depositor attack)?

### Oracle & Pricing
- [ ] Correct price source for collateral and debt assets? (set ORACLE flag if yes)
- [ ] Flash loan + oracle: can oracle be manipulated in same tx to avoid liquidation or drain collateral?
- [ ] **Asymmetric pause (HIGH risk):** If borrowing is paused but repayment is not (or vice versa), do trapped borrowers continue to accrue interest they cannot repay?

### Caps & Isolation
- [ ] Borrow cap: is there a borrow cap? Can it be bypassed via flash loan?
- [ ] Isolation mode: can borrowing isolated assets affect global state?
- [ ] Insolvency path: what happens when `totalDebt > totalCollateral`?

---

## Vault / Yield (ERC-4626)

### Share Price Integrity
- [ ] Share inflation: is first-depositor share inflation attack mitigated (virtual shares / `_decimalsOffset()`)?
- [ ] Rounding direction: `convertToShares` rounds DOWN (protects protocol), `convertToAssets` rounds DOWN?
- [ ] Donation attack: is `totalAssets()` using internal accounting or `balanceOf(address(this))`?
- [ ] **Share price under loss event:** If the strategy loses funds, does share price drop correctly? Can any user exit at old price before the update?
- [ ] **Time-decay state consistency:** If yield accrues over time (e.g., locked rewards, vesting), is share price consistent between the moment yield is earned and when it's distributed?

### Fee Accounting
- [ ] Performance fees calculated correctly? Can fees be front-run (deposit before fee, withdraw after)?
- [ ] **Fee solvency under stress (HIGH risk):** Can accrued fees exceed available vault assets under a loss event? Who pays the fee when the vault is underwater?
- [ ] **Fee extraction vs exchange rate:** Does collecting fees reduce exchange rate for remaining depositors in a way that's not accounted for?
- [ ] Management fees: do they accrue even when vault is paused?

### First Depositor / Dead-Weight Share
- [ ] ERC-4626 compliance: do preview functions (`previewDeposit`, `previewWithdraw`) match actual execution for all amounts including `amount = 1`?
- [ ] Deposit/withdraw limits: are `maxDeposit`, `maxWithdraw`, `maxMint`, `maxRedeem` correct?
- [ ] **Dead-weight shares:** Can virtual share offset be drained via inflation attack across many small deposits?

### Withdrawal Fairness
- [ ] **Withdrawal fairness (HIGH risk):** Can a depositor who withdraws first get more assets than a depositor who waits, when the vault is under stress?
- [ ] Emergency pause: can withdrawals be paused indefinitely by owner? Is there a timelock?
- [ ] Strategy risk: if yield comes from external protocol, what happens if that protocol is exploited?
- [ ] Reentrancy: vault operations before/after external yield strategy calls?
- [ ] Asset/share mismatch: can assets be added to vault without minting shares?

---

## Bridge / Cross-Chain

- [ ] Message replay protection: unique nullifier/nonce for every message?
- [ ] Chain ID validation: is chain ID part of the signed message?
- [ ] Message ordering: can messages be processed out of order?
- [ ] Validator set security: how many validators needed? What if majority is compromised?
- [ ] Token supply invariant: `totalMinted` on destination ≤ `totalLocked` on source?
- [ ] Re-org handling: what happens if source chain re-orgs after message is processed?
- [ ] Merkle proof verification: is proof validation correct? Is the root trusted?
- [ ] Finality assumptions: is sufficient block confirmation required?
- [ ] Emergency pause: can bridge be paused? By whom?
- [ ] Fee griefing: can bridge be griefed with high-volume low-value messages?

---

## Governance

- [ ] Flash loan voting: is voting power snapshot-based (past block) or real-time?
- [ ] Proposal threshold: is there a meaningful threshold to create proposals?
- [ ] Quorum: is quorum high enough to prevent minority governance attacks?
- [ ] Timelock: is there a timelock between proposal passing and execution?
- [ ] Timelock bypass: are there emergency functions that skip the timelock?
- [ ] Proposal hijacking: can someone modify a proposal after it passes?
- [ ] Delegation: can voting power be delegated to malicious contract?
- [ ] Vote replay: can a single vote be counted multiple times?
- [ ] Token voting power: can tokens be borrowed, used to vote, then returned?
- [ ] Governance griefing: can an attacker permanently block governance (e.g., eternal veto)?

---

## Proxy / Upgradeable

- [ ] Storage layout: new implementation preserves all existing storage slots?
- [ ] Storage gaps: are `uint256[50] __gap` arrays used in base contracts?
- [ ] ERC-7201 namespacing: is namespaced storage used to prevent collision?
- [ ] Initialization: `initialize()` protected with `initializer` modifier?
- [ ] Implementation initialization: is implementation contract initialized to block re-init?
- [ ] Upgrade authorization: `_authorizeUpgrade` override for UUPS — access-controlled?
- [ ] Transparent proxy: admin cannot call implementation functions directly?
- [ ] Beacon proxy: beacon owner controls all proxies — is this acceptable?
- [ ] Diamond (EIP-2535): selector clash between facets?
- [ ] Delegatecall context: does implementation use `msg.sender` or `address(this)` correctly?

---

## Staking / Rewards

- [ ] Reward calculation: precision correct, no truncation errors?
- [ ] Reward manipulation: can reward rate be manipulated by large deposits/withdrawals?
- [ ] Flash loan staking: can someone stake, claim rewards, unstake in same tx?
- [ ] Reward token drain: can rewards contract be drained by repeated claims?
- [ ] Lockup enforcement: can locked tokens be withdrawn early?
- [ ] Emission rate: can emission rate be set to 0 to strand staked tokens?

---

## Account Abstraction (ERC-4337)

- [ ] UserOperation validation: is `validateUserOp` returning correct magic value?
- [ ] Paymaster drain: can paymaster be forced to pay for invalid operations?
- [ ] Signature validation: is signature scheme robust? Replay-protected?
- [ ] Validation/execution separation: time-of-check vs time-of-use between validation and execution?
- [ ] Factory security: can smart wallet factory deploy wallets on behalf of others?
- [ ] Nonce: is nonce incremented correctly to prevent replay?

---

## Uniswap V4 Hooks

- [ ] Callback authorization: are hook callbacks only callable by PoolManager?
  ```solidity
  modifier onlyPoolManager() {
      require(msg.sender == address(poolManager));
      _;
  }
  ```
- [ ] Hook data validation: is `hookData` parameter validated/sanitized?
- [ ] Cached state: is pool state re-fetched after any external calls?
- [ ] Delta accounting: are currency deltas correctly settled?
- [ ] Reentrancy: is hook re-entrant via another swap during callback?
- [ ] Fee manipulation: can hook fees be manipulated by attacker-controlled swaps?

---

## NFT / ERC-721

- [ ] Safe transfer: is `safeTransferFrom` used (not `transferFrom`) when recipient might be contract?
- [ ] Reentrancy via onERC721Received: callback allows re-entry?
- [ ] Royalty bypass: can royalties be bypassed via wrapper contracts?
- [ ] Enumerable gas: unbounded loops over `tokenOfOwnerByIndex`?
- [ ] Metadata manipulation: is tokenURI mutable by owner? Can it be set to phishing URL?
- [ ] Mint access: can tokens be freely minted by anyone?
- [ ] Approval griefing: can approvals be front-run?

---

## Flash Loan Analysis

Load when `FLASH_LOAN` flag is set (entry points or callbacks detected). Apply sequentially — do not skip.

> Steps 5 and 5b are where HIGH/CRITICAL findings most commonly hide.

**Step 1: External Flash Susceptibility Check**
- [ ] Map every function that reads `balanceOf(address(this))`, `totalSupply()`, or a reserve/price variable
- [ ] For each: can a flash loan modify that variable before the function reads it?
- [ ] Does the function update state that persists after the tx? (If yes: flash loan damage is permanent)

**Step 2: Flash-Accessible State Inventory**
- [ ] List every storage slot that can change within a single tx via flash loan entry points
- [ ] For each slot: which protocol functions consume it as a decision input?
- [ ] Map: flash loan → state mutation → downstream function that trusts the state

**Step 3: Atomic Attack Sequence Modeling**
- [ ] Construct the full attack sequence: borrow → manipulate → exploit → repay
- [ ] Trace each step through actual code; verify state is not restored before exploitation
- [ ] Check whether multiple functions can be chained in a single `executeOperation` callback

**Step 4: Cross-Function Flash Chains**
- [ ] Can flash loan → deposit → withdraw → repay steal funds in one tx?
- [ ] Can flash loan → stake → claim rewards → unstake bypass lockup?
- [ ] Does any multi-step user flow become a same-tx exploit when batched via flash loan?
- [ ] **Flash + Donation (if `BALANCE_DEPENDENT` flag):** Can flash-borrowed tokens be donated to manipulate `totalAssets()` or `reserve` before an exploit step?

**Step 5: Flash Loan Defense Audit**
- [ ] Where are the flash loan defenses? (CEI, reentrancy guard, per-block state check, snapshot-based voting)
- [ ] Does each defense actually cover the attack surface identified in Steps 1–4?
- [ ] Can the defense be bypassed? (e.g., reentrancy guard doesn't cover cross-function path)

**Step 5b: Defense Parity Audit**
- [ ] For every exploitable function identified in Steps 1–4: is it covered by a defense?
- [ ] Any function NOT covered by a defense that touches flash-accessible state → flag as finding

---

## Oracle Analysis

Load when `ORACLE` flag is set. Apply sequentially — do not skip Step 3d.

> Steps 6 and 5c are where HIGH/CRITICAL findings most commonly hide.

**Step 1: Oracle Inventory**
- [ ] List every price source in the codebase: Chainlink feeds, Uniswap TWAP, custom oracles, `slot0`, LP reserves
- [ ] For each: what assets does it price? What functions consume it?
- [ ] Map: oracle call → price variable → downstream decision (liquidation, collateral ratio, swap)

**Step 2: Staleness Analysis**
- [ ] Is `latestRoundData()` called? Check: is `updatedAt` compared against `block.timestamp`?
- [ ] What is the configured `MAX_STALENESS`? Is it appropriate for this asset's heartbeat?
- [ ] On L2: is Chainlink sequencer uptime feed checked before using oracle price?
- [ ] Is there a heartbeat check AND a deviation threshold check?

**Step 3: Decimal Normalization Audit**

**3d (MANDATORY grep sweep):**
```bash
grep -n "10\*\*\|decimals()\|1e[0-9]\|normaliz\|PRICE_PRECISION\|ORACLE_DECIMALS" \
  $(find . -name "*.sol" -not -path "*/test*" -not -path "*/lib/*")
```
- [ ] For every hit: trace the price value through every arithmetic operation to its final use
- [ ] Are all prices normalized to the same decimal scale before comparison or calculation?
- [ ] Can a token with non-18 decimals cause mispricing? (e.g., USDC = 6 decimals, WBTC = 8 decimals)

**Step 4: TWAP-Specific Analysis** (if Uniswap V2/V3 TWAP used)
- [ ] What is the TWAP observation window? (minimum 30 min for meaningful manipulation resistance)
- [ ] For Uniswap V3: `observe()` called correctly with target secondsAgo values?
- [ ] Is `sqrtPriceX96` from `slot0` used anywhere? (`slot0` is the *current* spot price — manipulable)
- [ ] Can an attacker move the TWAP gradually over multiple blocks before exploiting?

**Step 5: Oracle Weight / Threshold Boundaries**
- [ ] If multiple oracles are combined (weighted average, median): can one manipulable oracle dominate?
- [ ] **5b:** What happens when oracle price = 0? Does `price > 0` assertion exist?
- [ ] **5c (HIGH/CRITICAL risk):** What is the max price deviation that liquidation logic tolerates? Can an attacker profit by pushing price to a circuit breaker bound (`minAnswer`/`maxAnswer`)?

**Step 6: Oracle Failure Modes (HIGH/CRITICAL most common here)**
- [ ] Oracle returns stale price during network congestion → liquidations blocked or triggered incorrectly
- [ ] Oracle circuit breaker clamps price (Chainlink `minAnswer`) → collateral mispriced during crash
- [ ] Oracle decimals mismatch → systematic 10^N over/underpricing
- [ ] `int256` price cast to `uint256` without checking for negative → huge phantom price
- [ ] Oracle removed from protocol → functions consuming it revert permanently (DoS)

---

## General Smart Contract Checklist

### Access Control
- [ ] All state-changing functions have appropriate access control
- [ ] No use of `tx.origin` for authentication
- [ ] Privileged functions emit events
- [ ] 2-step ownership transfer via `Ownable2Step` (not hand-rolled single-step `setOwner`)
- [ ] No functions accessible during construction that shouldn't be
- [ ] Standard library used for access control (`Ownable`/`AccessControl`) — not hand-rolled `require(msg.sender == owner)`

### Fund Management
- [ ] All ETH/token flows tracked in internal accounting
- [ ] No assumption that `address(this).balance == internal_balance`
- [ ] Withdrawal pattern used for ETH sends (not push)
- [ ] Emergency withdrawal mechanism exists (and is time-locked)

### External Calls
- [ ] All `.call()` return values checked
- [ ] SafeERC20 used for all ERC-20 interactions (not raw `.transfer()`/`.transferFrom()`)
- [ ] `forceApprove` used instead of raw `.approve()` (USDT compatibility)
- [ ] CEI pattern followed universally
- [ ] `nonReentrant` from `ReentrancyGuard` used (not custom `bool locked` mutex)
- [ ] No unbounded external calls in loops

### Arithmetic
- [ ] `unchecked` blocks verified manually
- [ ] No division before multiplication in financial math — use `Math.mulDiv` for precision
- [ ] Rounding direction favors protocol (not attacker)
- [ ] No unsafe downcasts — use `SafeCast` for type narrowing

### Library Usage
- [ ] No copy-pasted library code — all OZ/Solady imports from versioned dependencies
- [ ] `ECDSA.recover` used instead of raw `ecrecover` (validates `s` range, `address(0)`, `v` value)
- [ ] OZ version consistent — no v4 hooks (`_beforeTokenTransfer`) mixed with v5 base contracts
- [ ] Upgradeable implementations have `_disableInitializers()` in constructor
- [ ] ERC-7201 namespaced storage used in upgradeable contracts (not sequential layout)
- [ ] `Pausable` modifier applied consistently to ALL critical functions (not just deposit)

### Events & Logging
- [ ] All state changes emit events
- [ ] Events include old and new values where relevant
- [ ] Events not emitted before state is committed (re-entrancy risk)
