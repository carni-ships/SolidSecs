# Protocol-Specific Audit Checklists

Apply the relevant checklist(s) during Phase 3 of the audit.

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
- [ ] 2-step ownership transfer (not instant `transferOwnership`)
- [ ] No functions accessible during construction that shouldn't be

### Fund Management
- [ ] All ETH/token flows tracked in internal accounting
- [ ] No assumption that `address(this).balance == internal_balance`
- [ ] Withdrawal pattern used for ETH sends (not push)
- [ ] Emergency withdrawal mechanism exists (and is time-locked)

### External Calls
- [ ] All `.call()` return values checked
- [ ] SafeERC20 used for all ERC-20 interactions
- [ ] CEI pattern followed universally
- [ ] `nonReentrant` on all functions with external calls
- [ ] No unbounded external calls in loops

### Arithmetic
- [ ] `unchecked` blocks verified manually
- [ ] No division before multiplication in financial math
- [ ] Rounding direction favors protocol (not attacker)
- [ ] No casting that truncates significant bits

### Events & Logging
- [ ] All state changes emit events
- [ ] Events include old and new values where relevant
- [ ] Events not emitted before state is committed (re-entrancy risk)
