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

- [ ] Collateral ratio: correct calculation, no precision loss?
- [ ] Liquidation logic: can undercollateralized positions always be liquidated profitably?
- [ ] Liquidation incentive: is the incentive enough for liquidators? Is there a max?
- [ ] Bad debt: can bad debt accumulate without a recovery mechanism?
- [ ] Interest accrual: is `accrueInterest()` called before every state-changing operation?
- [ ] Oracle: correct price source for collateral and debt assets?
- [ ] Oracle staleness: are Chainlink answers checked for freshness?
- [ ] Oracle min/max: are circuit breaker bounds checked?
- [ ] Flash loan + oracle: can oracle be manipulated in the same tx?
- [ ] Borrow cap: is there a borrow cap? Can it be bypassed?
- [ ] Isolation mode: can borrowing isolated assets affect global state?
- [ ] Debt token: interest-bearing debt tokens — can they be used to manipulate share price?
- [ ] Insolvency path: what happens when `totalDebt > totalCollateral`?

---

## Vault / Yield (ERC-4626)

- [ ] Share inflation: is first-depositor share inflation attack mitigated (virtual shares)?
- [ ] Rounding direction: `convertToShares` rounds DOWN (protects protocol), `convertToAssets` rounds DOWN (protects protocol)?
- [ ] Donation attack: is `totalAssets()` using internal accounting or `balanceOf(address(this))`?
- [ ] Deposit/withdraw limits: are `maxDeposit`, `maxWithdraw`, `maxMint`, `maxRedeem` correct?
- [ ] ERC-4626 compliance: do preview functions match actual execution?
- [ ] Emergency pause: can withdrawals be paused indefinitely by owner?
- [ ] Strategy risk: if yield comes from external protocol, what happens if that protocol is exploited?
- [ ] Fee accounting: performance fees calculated correctly? Can fees be front-run?
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
