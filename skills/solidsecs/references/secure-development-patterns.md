# Secure Development Patterns Reference

Derived from [OpenZeppelin's secure contract development methodology](https://github.com/OpenZeppelin/openzeppelin-skills). During audit, flag deviations from these patterns as potential findings when they introduce concrete risk.

---

## Core Principle: Library-First

Battle-tested libraries (OpenZeppelin, Solady, Solmate) exist for most common patterns. Custom implementations of solved problems are a recurring source of vulnerabilities.

**Auditor checklist — flag when ALL of these are true:**
1. A library component exists for the functionality
2. The contract implements it from scratch instead of importing
3. The custom implementation deviates from the library's behavior in a way that introduces concrete risk

---

## Pattern Categories

### 1. Access Control

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `Ownable` / `Ownable2Step` | `require(msg.sender == owner)` with hand-rolled `owner` state variable — missing two-step transfer, no zero-address check, no `renounceOwnership` protection |
| `AccessControl` | Custom role mappings (`mapping(address => bool) public admins`) without role admin hierarchy or enumeration — compromised admin grants more admins with no revocation chain |
| `AccessManager` | Ad-hoc per-function modifier soup with no centralized permission registry |

**Key check:** Are privileged functions (`setOracle`, `pause`, `upgradeTo`, `withdrawFees`) guarded by a standard access control contract, or hand-rolled checks that may miss edge cases?

### 2. Reentrancy Protection

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `ReentrancyGuard` / `nonReentrant` | Custom `bool locked` mutex without `uint256` status pattern (gas-inefficient, potential for dirty storage reads in assembly-heavy contracts) |
| Transient storage guard (OZ v5.1+) | Custom `TSTORE`/`TLOAD` mutex without proper lifecycle management |

**Key check:** If the contract makes external calls before state updates, is it protected by a standard guard or relying on ad-hoc CEI ordering that may have gaps across multiple functions?

### 3. Pausability

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `Pausable` / `whenNotPaused` | Custom `bool paused` with inconsistent modifier application — some critical functions check, others don't |
| `ERC20Pausable`, `ERC721Pausable` | Pausable base inherited but token transfers bypass the check due to missing `_update` override (OZ v5) or `_beforeTokenTransfer` override (OZ v4) |

**Key check:** During an emergency pause, can an attacker still drain funds via unpaused paths (withdraw, liquidate, redeem)?

### 4. Token Standards

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `ERC20` (OZ) | Missing `Transfer` event on mint/burn, non-compliant return values, custom balance tracking diverging from standard |
| `SafeERC20` / `safeTransfer` | Raw `.transfer()` / `.transferFrom()` calls — fails silently or reverts on USDT, BNB, and other non-compliant tokens |
| `forceApprove` | Direct `approve(spender, amount)` — reverts on USDT when changing non-zero to non-zero allowance |
| `ERC721` | Missing `_safeMint` (tokens sent to non-receiver contracts get locked), approval not cleared on custom transfer override |
| `ERC1155` | Missing batch callback validation (`onERC1155BatchReceived`), `uri()` without `{id}` substitution |
| `ERC4626` | Wrong rounding direction (must favor vault: floor on deposit/redeem-shares, ceil on withdraw/mint-assets), missing inflation attack mitigation |

### 5. Upgrade Safety

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `Initializable` + `_disableInitializers()` | Implementation constructor without `_disableInitializers()` — attacker calls `initialize()` on impl, takes ownership, bricks proxies via `selfdestruct` |
| `UUPSUpgradeable` | `_authorizeUpgrade` with empty body or missing access control (CVE-2021-41264) |
| `reinitializer(N)` | V2+ upgrades using `initializer` instead of `reinitializer(version)` — may reset initialized state |
| ERC-7201 namespaced storage | Sequential storage layout in upgradeable contracts — base contract reordering shifts all derived slots |

**Key checks:**
- New state variables appended only (never inserted in middle of existing layout)
- No `immutable` variables that should be per-proxy storage (proxy `delegatecall` gets implementation's hardcoded values)
- No `selfdestruct` / `delegatecall` to untrusted targets in implementation
- Storage namespace consistent across upgrade versions (namespace removal between upgrades orphans state)
- `_disableInitializers()` in every implementation constructor

### 6. Cryptographic Primitives

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `ECDSA.recover` | Raw `ecrecover` without 3 critical checks: (1) `s` in lower half order, (2) recovered address != `address(0)`, (3) `v` is 27 or 28 |
| `MessageHashUtils` (EIP-712) | Manual digest construction missing `chainId` or `verifyingContract` in domain separator |
| `MerkleProof` | Leaf not double-hashed (second preimage attack with 64-byte inputs), proof not bound to `msg.sender` |
| `SignatureChecker` | Missing ERC-1271 support — smart contract wallets (Safe, ERC-4337 accounts) can't use the protocol |

### 7. Math and Casting

| Library Component | Custom Anti-Pattern to Flag |
|---|---|
| `Math.mulDiv` | Division before multiplication — `(a / b) * c` truncation amplifies error vs correct `(a * c) / b` |
| `SafeCast` | Unchecked downcasts — `uint128(x)` silently truncates in Solidity >= 0.8 (no revert, just data loss) |

### 8. Embedded Library Code

**Critical anti-pattern:** Copy-pasting library source into the contract instead of importing from a versioned dependency.

**Why it matters:** Embedded code does not receive security patches. When OZ publishes a fix (e.g., ERC721Consecutive balance bug in < 4.8.2, ERC1155 totalSupply inflation in < 4.3.2), projects that import from `@openzeppelin/contracts` get the fix on `npm update` / `forge update`. Projects that embedded the code remain vulnerable indefinitely.

**Detection:** Look for functions or modifiers that duplicate well-known library implementations — a hand-written `_transfer` mirroring OZ's `ERC20._transfer`, a custom `ReentrancyGuard` with the same uint256 status pattern, or inlined `MerkleProof.verify` logic.

---

## OZ Version Compatibility

When auditing contracts that import OpenZeppelin, check for version confusion:

| Pattern | OZ v4 | OZ v5 |
|---|---|---|
| Token hook | `_beforeTokenTransfer` / `_afterTokenTransfer` | `_update` |
| Storage | Sequential slots + `__gap` arrays | ERC-7201 namespaced storage |
| Reentrancy guard | Storage-based (`uint256 private _status`) | Transient storage option (`ReentrancyGuardTransient`) |
| Access control | `AccessControl` (per-contract) | `AccessManager` (centralized, cross-contract) |
| ERC4626 inflation | Manual dead shares or virtual offset | `_decimalsOffset()` built-in |
| Safe ERC20 approve | `safeApprove` (deprecated) | `forceApprove` |

**Flag:** Contracts mixing v4 hooks (`_beforeTokenTransfer`) with v5 base imports, or v5 base contracts with v4-style overrides that silently never fire.

---

## Grep Patterns for Library Misuse

Use during Pass A (syntactic search) to identify potential library misuse:

```bash
# Hand-rolled access control
grep -n "require(msg.sender ==" $SOL_FILES | grep -v "test\|mock\|lib"

# Raw ecrecover (should use ECDSA library)
grep -n "ecrecover(" $SOL_FILES | grep -v "ECDSA\|test\|lib"

# Direct ERC20 calls without SafeERC20
grep -n "\.transfer(\|\.transferFrom(" $SOL_FILES | grep -v "safeTransfer\|SafeERC20\|test\|lib\|ERC721\|ERC1155"

# Missing _disableInitializers in upgradeable implementations
grep -rn "constructor()" $SOL_FILES | grep -v "_disableInitializers\|test\|lib"

# Custom bool-based reentrancy guard
grep -n "bool.*locked\|bool.*entered" $SOL_FILES | grep -v "ReentrancyGuard\|test\|lib"

# Direct approve without forceApprove (USDT incompatible)
grep -n "\.approve(" $SOL_FILES | grep -v "forceApprove\|safeApprove\|SafeERC20\|test\|lib"
```
