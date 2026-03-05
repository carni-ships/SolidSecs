# Security Audit Report — zRouter / NameNFT

**Date:** 2026-03-04
**Auditor:** Claude (solidsecs skill)
**Scope:** `src/zRouter.sol`, `src/NameNFT.sol`, `src/zQuoter.sol`, `src/IzRouter.sol`
**Framework:** Foundry (solc 0.8.33, EVM: prague, via-ir)
**Tools Run:** Manual static analysis, code review, forge build

---

## Executive Summary

zRouter is a multi-AMM aggregator router supporting Uniswap V2/V3/V4, zAMM, Curve, Lido, and a generic executor (`snwap`). NameNFT is an ENS-style naming system for the `.wei` TLD. The audit found **1 Critical**, **1 High**, **4 Medium**, **2 Low**, and **3 Informational** findings. The most critical issue — identified after observing an on-chain exploit (tx `0xfe34c4b...`) — is that `swapCurve` grants `type(uint256).max` ERC20 approvals to **user-supplied, unvalidated pool addresses**, enabling immediate theft of any token held by the router.

## Risk Score: 22 / 100

---

## ⚠️ Post-Audit Update — On-Chain Exploit Observed

Transaction [`0xfe34c4beee447de536bbd3d613aa0e3aa7eeb63832e9453e4ef3999924ab466a`](https://etherscan.io/tx/0xfe34c4beee447de536bbd3d613aa0e3aa7eeb63832e9453e4ef3999924ab466a) shows a fresh wallet (funded 38h prior) deploying an unverified contract and stealing ~42,607 USDC → 21.19 ETH from a victim. Proceeds were laundered via Railgun. The attack vector is **CRIT-01** below, which was missed in the initial audit pass.

---

## Findings Summary

| # | Title | Severity | Contract |
|---|-------|----------|----------|
| **CRIT-01** | **`swapCurve` grants max ERC20 approval to arbitrary user-supplied addresses** | **Critical** | **zRouter** |
| H-01 | `sweep()` has no access control — anyone can drain router | High | zRouter |
| M-01 | `tx.origin` used for ownership initialization | Medium | zRouter, NameNFT |
| M-02 | Curve multi-hop passes `min_dy = 0` on every hop | Medium | zRouter |
| M-03 | `multicall` + `payable` allows transient ETH balance inflation | Medium | zRouter |
| M-04 | `wrapETH` silently ignores both ETH deposit and WETH transfer failures | Medium | zRouter |
| L-01 | `IzRouter.ensureAllowance` ABI mismatch with implementation | Low | IzRouter |
| L-02 | `revealName` sends full contract ETH balance — breaks multicall chains | Low | zRouter |
| I-01 | `SafeExecutor.execute` is publicly callable with no auth | Info | zRouter |
| I-02 | `unwrapETH` silently ignores WETH withdrawal failure | Info | zRouter |
| I-03 | Typo in custom error: `SnwapSlippage` | Info | zRouter |

---

## Detailed Findings

---

### [CRIT-01] `swapCurve` grants `type(uint256).max` ERC20 approval to arbitrary user-supplied addresses

**Severity:** Critical
**Confidence:** High (on-chain exploit confirmed)
**Location:** `src/zRouter.sol:586-602`

**Description:**
The `route` parameter of `swapCurve` is a user-controlled `address[11]` array where odd indices (`route[1]`, `route[3]`, ...) are Curve pool addresses. These addresses receive **no validation**. Before calling into each pool, the router grants it an unconditional max approval:

```solidity
// pool = route[i * 2 + 1] — fully attacker-controlled
address inToken = _isETH(curIn) ? WETH : curIn;
if (allowance(inToken, address(this), pool) == 0) {
    safeApprove(inToken, pool, type(uint256).max);  // MAX APPROVAL TO ATTACKER ADDRESS
}
// Then immediately calls into it:
IStableNgPool(pool).exchange(i, j, amount, 0);     // attacker's contract executes here
```

An attacker deploys a contract implementing the Curve pool interface (just needing a valid `exchange` signature), passes it as `route[1]`, and the router will:
1. Approve the attacker's contract for `type(uint256).max` of the input token
2. Call `exchange()` on it — which can immediately `transferFrom(router, attacker, entire_balance)`

**Impact:**
Complete theft of any ERC20 token held by the router at time of the call. Because the router is used via `multicall`, tokens routinely pass through it mid-transaction. An attacker crafts a multicall where they first deposit the victim's tokens (via `deposit()` or as a prior swap output), then trigger `swapCurve` with a malicious pool as the second step.

Additionally, the approval is **persistent** — it survives beyond the transaction. Once set, the attacker's contract can drain any future deposits of that token from the router, with no further user interaction required.

**Attack Path (observed on-chain):**
```
1. Attacker deploys malicious contract implementing Curve pool interface
2. Victim calls multicall([
     deposit(USDC, 0, 42606e6),           // USDC enters router
     swapCurve(to, false,
       route=[USDC, attackerPool, ETH, 0...],  // attacker pool in route
       swapParams=[[0,1,1,10],...], ...
     )
   ])
3. router: safeApprove(USDC, attackerPool, MAX)
4. router: attackerPool.exchange(0, 1, 42606e6, 0)
5. attackerPool.exchange(): transferFrom(router, attacker, 42606e6)
6. attackerPool returns fake output to pass outBalAfter check
7. Attacker converts stolen USDC → ETH via Uniswap V4
8. Proceeds laundered via Railgun
```

Confirmed: tx `0xfe34c4beee447de536bbd3d613aa0e3aa7eeb63832e9453e4ef3999924ab466a` — 42,606 USDC stolen, 21.19 ETH received.

**Why This Was Missed in Initial Audit:**
Focus on `swapCurve` was on the slippage issue (M-02, `min_dy = 0`). The trust boundary question — *are pool addresses validated?* — was not applied. The lazy-approve pattern is safe when pool addresses are hardcoded or validated against a known registry; it is critical when they come from unrestricted calldata.

**Recommendation:**
Maintain an allowlist of known legitimate Curve pool addresses. Before approving or calling into any pool, verify it against the allowlist. Alternatively, perform the approval only within a sandboxed subcall that revokes it afterwards.

---

### [H-01] `sweep()` has no access control — anyone can drain router

**Severity:** High
**Confidence:** High
**Location:** `src/zRouter.sol:866`

**Description:**
```solidity
function sweep(address token, uint256 id, uint256 amount, address to) public payable {
    if (token == address(0)) {
        _safeTransferETH(to, amount == 0 ? address(this).balance : amount);
    } else if (id == 0) {
        safeTransfer(token, to, amount == 0 ? balanceOf(token) : amount);
    } else {
        IERC6909(token).transfer(to, id, amount == 0 ? IERC6909(token).balanceOf(address(this), id) : amount);
    }
}
```
`sweep` has **no access control**. Any external caller can invoke it to transfer any ERC20, ERC6909, or ETH held by the router to an arbitrary address.

**Impact:**
While the router is designed to be stateless (transient storage clears per-transaction), any funds that remain in the contract between transactions — e.g., from:
- Partial multicall execution where later steps fail but earlier transfers have already been received
- ETH sent directly to the contract via `receive()`
- Failed output deliveries
- Lido staking yield (stETH rebases)

— can be immediately front-run and stolen by any watcher. The public `sweep` is intentional per the design, but this creates a race condition window and makes the router unsafe to interact with in any non-atomic context.

**Attack Path:**
1. User sends ETH and executes a multi-step multicall
2. One of the later steps fails; earlier steps already transferred tokens into the router
3. Attacker front-runs the user's retry transaction by calling `sweep(token, 0, 0, attacker)` before the original TX confirms
4. All tokens in the router are sent to the attacker

**Recommendation:**
Add a `nonReentrant` + EOA-only guard, or implement a per-caller "pending balance" mechanism so only the depositor can sweep their own funds. Alternatively, document clearly that router interactions MUST be atomic and that any failed multicall can lose funds to front-runners.

---

### [M-01] `tx.origin` used for ownership initialization

**Severity:** Medium
**Confidence:** High
**Location:** `src/zRouter.sol:35`, `src/NameNFT.sol:122`

**Description:**
```solidity
// zRouter.sol:35
emit OwnershipTransferred(address(0), _owner = tx.origin);

// NameNFT.sol:122
_initializeOwner(tx.origin);
```
Both contracts use `tx.origin` instead of `msg.sender` to set the initial owner. Using `tx.origin` means:
1. If deployed via a factory or deployment script contract, the owner will be the EOA that initiated the factory call, not the deploying contract. This breaks factory-based deployment patterns.
2. `tx.origin` is explicitly deprecated by the Ethereum community and should not be used for authorization logic.
3. If the deployment happens through a multisig or gnosis safe, the owner would be the EOA calling the safe, not the safe itself.

**Recommendation:**
Replace `tx.origin` with `msg.sender` in both constructors.

---

### [M-02] Curve multi-hop passes `min_dy = 0` on every intermediate hop

**Severity:** Medium
**Confidence:** High
**Location:** `src/zRouter.sol:599-607`

**Description:**
```solidity
// Stable pool exchange
IStableNgPool(pool).exchange(int128(int256(p[0])), int128(int256(p[1])), amount, 0);  // min_dy = 0

// Crypto pool exchange
ICryptoNgPool(pool).exchange(p[0], p[1], amount, 0);  // min_dy = 0

// Meta pool exchange
IStableNgMetaPool(pool).exchange_underlying(int128(int256(p[0])), int128(int256(p[1])), amount, 0);  // min_dy = 0

// Liquidity adds also pass 0 for min_mint_amount
IStableNgPool(pool).add_liquidity(a, 0);  // min = 0
```
All Curve pool interactions pass `min_dy = 0` or `min_mint_amount = 0`, completely disabling slippage protection **at the individual hop level**. Only a final aggregate slippage check exists via `amountLimit` on the full route.

**Impact:**
A sandwich attacker can manipulate any individual Curve pool in a multi-hop route without limit. For a 3-hop route, each intermediate pool can be fully sandwiched as long as the final output passes the end-to-end slippage check. In practice, this allows significantly more MEV extraction than intended.

**Recommendation:**
Pass a `min_dy` derived from the `exactOut` quote path, or use a per-hop slippage tolerance (e.g., `amountIn * 995 / 1000`). Alternatively, document that `swapCurve` should only be used for single-hop routes or with very tight `amountLimit`.

---

### [M-03] `multicall` + `payable` allows transient ETH balance inflation

**Severity:** Medium
**Confidence:** Medium
**Location:** `src/zRouter.sol:798-808`, `src/zRouter.sol:813-828`

**Description:**
```solidity
function multicall(bytes[] calldata data) public payable returns (bytes[] memory results) {
    for (uint256 i; i != data.length; ++i) {
        (bool ok, bytes memory result) = address(this).delegatecall(data[i]);
        ...
    }
}
```
`multicall` uses `delegatecall`, preserving `msg.value` across all sub-calls. The `deposit(address(0), 0, amount)` function allows ETH deposit with this check:
```solidity
require(msg.value == (token == address(0) ? amount : 0), InvalidMsgVal());
```
If a caller sends `1 ETH` in a multicall and calls `deposit(address(0), 0, 1 ether)` twice, both calls see `msg.value == 1 ETH == amount` and pass validation, inflating the transient ETH balance to `2 ETH` while only `1 ETH` is held.

**Impact:**
The inflated transient balance can be used to pay for swaps. The first swap spending the phantom credit will succeed (real ETH is present). The second swap will fail at the actual ETH transfer (`dst.call{value: 1 ether}` with 0 ETH), causing the entire multicall to revert. There is **no direct fund theft** possible, but this can be used to create confusing revert patterns and unexpected behavior for contracts integrating with zRouter.

**Recommendation:**
In `deposit`, when `token == address(0)`, track how much ETH has already been credited within the current transaction using an additional transient slot, and subtract from `msg.value` to prevent double-crediting. Alternatively, require that `deposit(ETH)` can only be called once per multicall execution.

---

### [M-04] `wrapETH` silently ignores both ETH deposit and WETH transfer failures

**Severity:** Medium
**Confidence:** High
**Location:** `src/zRouter.sol:1544-1553`

**Description:**
```solidity
function wrapETH(address pool, uint256 amount) {
    assembly ("memory-safe") {
        pop(call(gas(), WETH, amount, codesize(), 0x00, codesize(), 0x00))  // ETH→WETH, result discarded
        mstore(0x14, pool)
        mstore(0x34, amount)
        mstore(0x00, 0xa9059cbb000000000000000000000000)
        pop(call(gas(), WETH, 0, 0x10, 0x44, codesize(), 0x00))  // WETH transfer, result discarded
        ...
    }
}
```
Both `call` results are `pop`-ped without checking. If the WETH contract's `receive()` or `transfer()` fails for any reason, the function silently returns without reverting. This means:
- ETH could be consumed (sent to WETH) but the WETH transfer to `pool` could silently fail
- The pool would receive the swap tokens without the corresponding WETH payment, causing the pool's swap to revert and leaving ETH stranded in the router

**Recommendation:**
Check return values. WETH is a known contract, but defensive coding requires validating both calls. Use `require(success, "WETH wrap failed")` or revert on failure.

---

### [L-01] `IzRouter.ensureAllowance` ABI mismatch with implementation

**Severity:** Low
**Confidence:** High
**Location:** `src/IzRouter.sol:220`, `src/zRouter.sol:723`

**Description:**
```solidity
// IzRouter.sol (interface)
function ensureAllowance(address token, bool is6909, bool isRetro) external payable;

// zRouter.sol (implementation)
function ensureAllowance(address token, bool is6909, address to) public payable onlyOwner {
```
The interface declares `(address, bool, bool)` but the implementation takes `(address, bool, address)`. These compute to **different function selectors**, meaning any integrator using `IzRouter` to call `ensureAllowance` will call a non-existent selector, which routes to `fallback()` (the V3 callback handler) instead.

**Recommendation:**
Update `IzRouter.sol` to match the implementation signature, or vice versa.

---

### [L-02] `revealName` sends entire contract ETH balance — disrupts multicall chains

**Severity:** Low
**Confidence:** Medium
**Location:** `src/zRouter.sol:1254-1264`

**Description:**
```solidity
function revealName(string calldata label, bytes32 innerSecret, address to)
    public payable returns (uint256 tokenId)
{
    bytes32 secret = keccak256(abi.encode(innerSecret, to));
    uint256 val = address(this).balance;         // takes ENTIRE ETH balance
    _useTransientBalance(address(this), address(0), 0, val);  // clears ETH transient slot
    tokenId = INameNFT(NAME_NFT).reveal{value: val}(label, secret);
    ...
}
```
`revealName` uses `address(this).balance` — the router's **entire** current ETH balance — as the fee to send to NameNFT. If this is used in a multicall where other ETH-consuming operations follow, those operations will fail with no ETH remaining.

**Impact:**
Low — this is mostly a UX/integration footgun, but could cause unexpected failures or stranded funds in complex multicall sequences.

**Recommendation:**
Accept an explicit `amount` parameter instead of using the full balance. The `revealName` should allow precise control over how much ETH is forwarded.

---

### [I-01] `SafeExecutor.execute` is publicly callable with no authentication

**Severity:** Informational
**Location:** `src/zRouter.sol:1650-1661`

**Description:**
`SafeExecutor.execute` is `public payable` with no access control. Anyone can call it to make `SafeExecutor` call any target contract. The contract has no token approvals ("safe for arbitrary external calls"), but could be used as a proxy to call contracts that trust its address. This is intentional by design but should be documented.

---

### [I-02] `unwrapETH` silently ignores WETH withdrawal failure

**Severity:** Informational
**Location:** `src/zRouter.sol:1555-1561`

**Description:**
```solidity
function unwrapETH(uint256 amount) {
    assembly ("memory-safe") {
        mstore(0x00, 0x2e1a7d4d)
        mstore(0x20, amount)
        pop(call(gas(), WETH, 0, 0x1c, 0x24, codesize(), 0x00))  // result discarded
    }
}
```
The WETH `withdraw` call result is discarded. On failure, the function silently returns without reverting, leaving the router holding WETH that was expected to be ETH.

---

### [I-03] Typo in custom error: `SnwapSlippage`

**Severity:** Informational
**Location:** `src/zRouter.sol:21`

**Description:**
```solidity
error SnwapSlippage(address token, uint256 received, uint256 minimum);
```
`SnwapSlippage` appears to be a typo for `SwapSlippage` (the 'w' was moved). This is a cosmetic issue and does not affect security or functionality but can confuse developers debugging on-chain errors.

---

## Tool Output Summary

**forge build:** Compilation succeeded after installing submodule dependencies (forge-std, solady, soledge).

**Slither / Aderyn / Mythril:** Not installed. Manual analysis was performed.

---

## Architecture Notes

- **Transient storage pattern:** The router uses EIP-1153 transient storage for inter-function state passing within a multicall. This is a clean design but introduces the msg.value reuse risk (M-03).
- **V3 callback authentication:** The fallback-based V3 callback correctly verifies `msg.sender == computedPool` using deterministic CREATE2 pool address derivation. This is robust.
- **V4 callback authentication:** `unlockCallback` correctly verifies `msg.sender == V4_POOL_MANAGER`.
- **NameNFT commit-reveal:** Well-implemented with proper timing bounds (MIN/MAX_COMMITMENT_AGE) and binding of commitment to `msg.sender + secret`, preventing front-running.
- **NameNFT subdomain epoch system:** The parent epoch tracking for stale subdomain detection is a thoughtful design that correctly handles re-registration scenarios.
- **`execute` function:** Only callable on trusted targets (trust list controlled by owner). The transient storage lock (`tstore(0x00, 1)`) prevents the locked V3/V4 callbacks from being triggered during execution — good defense.

---

## Appendix: Gas / Style

- `zQuoter.sol` simply proxies all calls to `ZQUOTER_BASE` (a fixed address). This is a read-only lookup contract with no security implications.
- `PoolKey.feeOrHook` encoding duality (treating `uint256` as either fee bps or hook address) is a storage optimization that could cause issues if the value space overlaps. Document the encoding convention clearly.
- Multiple functions use `public` visibility where `external` would suffice (gas optimization, no security impact).
