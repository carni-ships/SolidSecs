# Audit Report Template

Copy this template and fill in during Phase 6 of the audit.

---

```markdown
# Security Audit Report

**Project:** [Project Name]
**Repository:** [URL or path]
**Commit / Version:** [git hash or tag]
**Audit Date:** [YYYY-MM-DD]
**Auditor:** Claude (solidsecs skill v1.0.0)
**Scope:** [list of files/contracts audited]
**Out of Scope:** [test files, mocks, external dependencies]

---

## Executive Summary

[2–3 sentences. State what was audited, total findings by severity, and overall deployment recommendation.]

**Example:** "The audit covered 5 Solidity contracts implementing a lending protocol (~1,200 LoC).
2 Critical, 3 High, 4 Medium, and 6 Low/Informational findings were identified.
**Do not deploy** until Critical and High findings are resolved."

---

## Risk Score: [0–100]

| Score Range | Interpretation |
|-------------|---------------|
| 90–100 | Low risk — ready for deployment with minor fixes |
| 70–89 | Medium risk — address High findings before deployment |
| 50–69 | High risk — significant issues require resolution |
| 25–49 | Critical risk — major vulnerabilities present |
| 0–24 | Do not deploy — fundamental security flaws |

**Scoring formula:** Start at 100. Deduct: Critical ×25, High ×10, Medium ×5, Low ×1.

---

## Tools Executed

| Tool | Version | Status | Findings |
|------|---------|--------|----------|
| Slither | x.x.x | ✓ Ran | N issues |
| Aderyn | x.x.x | ✓ Ran | N issues |
| Mythril | x.x.x | ✓ Ran | N issues |
| Semgrep | x.x.x | ✓ Ran | N issues |
| forge test | x.x.x | ✓ Ran | N failures |
| [Tool] | — | ✗ Not installed | — |

---

## Findings Summary

| ID | Title | Severity | Confidence | Status |
|----|-------|----------|------------|--------|
| CRIT-01 | [title] | 🔴 Critical | High | Open |
| HIGH-01 | [title] | 🟠 High | High | Open |
| MED-01 | [title] | 🟡 Medium | Medium | Open |
| LOW-01 | [title] | 🔵 Low | High | Open |
| INFO-01 | [title] | ⚪ Info | — | Open |

---

## Detailed Findings

---

### [CRIT-01] [Title]

**Severity:** 🔴 Critical
**Confidence:** High
**Category:** [Reentrancy / Access Control / Arithmetic / etc.]
**Vulnerability Class:** [ETH-XXX if applicable]
**Location:** `contracts/MyContract.sol:L123–L145`
**Tools:** Slither (reentrancy-eth), Manual Analysis

#### Description

[Clear explanation of the vulnerability. What invariant is violated?]

#### Impact

[What can an attacker do? Quantify if possible: "drain all ETH from the contract", "take ownership", etc.]

#### Attack Path

1. Attacker calls `deposit(1 ether)`
2. Contract calls `msg.sender.call{value: 1 ether}("")` before updating `balances[msg.sender]`
3. Attacker's `receive()` re-enters `withdraw()`
4. Balance check passes (not yet updated), funds drained again
5. Repeat until contract is empty

#### Proof of Concept

```solidity
contract Attacker {
    IVulnerable target;

    constructor(address _target) payable {
        target = IVulnerable(_target);
    }

    function attack() external {
        target.deposit{value: 1 ether}();
        target.withdraw(1 ether);
    }

    receive() external payable {
        if (address(target).balance >= 1 ether) {
            target.withdraw(1 ether);
        }
    }
}
```

#### Vulnerable Code

```solidity
// contracts/MyContract.sol:L123
function withdraw(uint256 amount) external {
    require(balances[msg.sender] >= amount, "insufficient");
    // ❌ External call BEFORE state update
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok);
    balances[msg.sender] -= amount; // ❌ Too late
}
```

#### Recommendation

```solidity
function withdraw(uint256 amount) external nonReentrant {
    require(balances[msg.sender] >= amount, "insufficient");
    balances[msg.sender] -= amount; // ✅ State update first
    (bool ok,) = msg.sender.call{value: amount}("");
    require(ok, "transfer failed");
}
```

---

### [HIGH-01] [Title]

**Severity:** 🟠 High
**Confidence:** High
**Category:** [Category]
**Location:** `contracts/MyContract.sol:L67`
**Tools:** Manual Analysis

#### Description
[...]

#### Impact
[...]

#### Recommendation
[...]

---

### [MED-01] [Title]

**Severity:** 🟡 Medium
**Confidence:** Medium
**Category:** [Category]
**Location:** `contracts/MyContract.sol:L89`

#### Description
[...]

#### Recommendation
[...]

---

### [LOW-01] [Title]

**Severity:** 🔵 Low
**Location:** `contracts/MyContract.sol:L12`

[Brief description and fix.]

---

### [INFO-01] [Title]

**Severity:** ⚪ Informational
**Location:** `contracts/MyContract.sol`

[Code quality observation, gas optimization, or best practice suggestion.]

---

## Appendix A: Tool Raw Output Summaries

### Slither Output Summary
[Paste filtered key findings, not the full output]

### Aderyn Output Summary
[...]

### Mythril Output Summary
[...]

---

## Appendix B: Scope Details

**Files Audited:**
- `contracts/MyContract.sol` (245 LoC)
- `contracts/MyToken.sol` (89 LoC)

**External Dependencies (not audited):**
- OpenZeppelin Contracts v4.9.3
- Chainlink contracts

**Test Coverage:**
- Branch coverage: [X]%
- Line coverage: [X]%

---

## Appendix C: Disclosure

This audit was performed by an AI system using the solidsecs skill. It does not constitute a professional security audit. Always have critical contracts reviewed by professional human auditors before mainnet deployment.

Findings represent the state of the code at the audited commit. Changes after this commit are not covered.
```

---

## Severity Classification Reference

| Severity | Criteria |
|----------|----------|
| 🔴 Critical | Direct loss of funds, complete protocol takeover, permanent freeze of all assets. Exploitable by anyone without special conditions. |
| 🟠 High | Significant loss of funds under specific conditions, partial protocol control, temporary freeze, economic manipulation. |
| 🟡 Medium | Functional impact without direct fund loss, griefing potential, logic errors with limited blast radius, edge-case failures. |
| 🔵 Low | Best practice violations, minor issues, gas inefficiencies with security implications, events missing on sensitive operations. |
| ⚪ Info | Code quality, documentation, style, non-security observations. |

## Confidence Levels

| Level | Meaning |
|-------|---------|
| High | Concrete attack path confirmed, code fully traced, no unrealistic assumptions |
| Medium | Plausible attack path, some conditions required that are feasible |
| Low | Theoretical, requires specific configuration or external actor behavior |
