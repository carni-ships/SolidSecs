# Devil's Advocate (DA) Protocol

Formal false-positive evaluation framework. Apply to every finding before finalizing severity.
Use during Phase 4 (ATTACK) and again during Phase 5 (Synthesize) for any CONTESTED finding.

---

## Six Dimensions

Evaluate each dimension by searching the codebase for concrete evidence. Every score requires evidence — no score without a code reference.

| # | Dimension | ID | What to look for |
|---|-----------|-----|-----------------|
| 1 | Guards | `guards` | `require`, `assert`, `revert`, modifiers that block any step of the attack sequence |
| 2 | Reentrancy protection | `reentrancy_protection` | `nonReentrant`, mutex, CEI on affected AND cross-contract paths |
| 3 | Access control | `access_control` | Can the attacker actually call each function in the sequence? Apply Privilege Rule |
| 4 | By-design classification | `by_design` | Is the behavior documented? — Safe / Risky tradeoff / Undocumented |
| 5 | Economic feasibility | `economic_feasibility` | Capital required, gas, expected profit. Cost > yield = partial mitigation |
| 6 | Dry run | `dry_run` | Execute exploit with concrete values. Check arithmetic, rounding, overflow |

---

## Scoring Scale

| Score | Label | Meaning |
|:------|:------|:--------|
| -3 | Full mitigation | Complete guard that prevents the attack under ALL conditions |
| -2 | Safe by design | Documented behavior with no security impact |
| -1 | Partial mitigation | Guard exists but has edge cases, race conditions, or can be bypassed |
| 0 | No mitigation | Nothing relevant found |
| +1 | Edge-case exploitable | The "mitigation" introduces a new vector or has a known bypass |

---

## By-Design Classification (Dimension 4)

Choose exactly one:

| Classification | Score | Action |
|:---------------|:------|:-------|
| Safe by design | -2 | Documented behavior with no security impact — degrade finding |
| Risky tradeoff | 0 | Documented behavior but creates attack surface — emit as `design_tradeoff` category |
| Undocumented | 0 | No documentation found — proceed normally, full severity |

---

## Privilege Rule

Privileged roles (owner, admin, governance) act in good faith. Do NOT dismiss findings based on privileged access alone. These patterns are NOT blocked by access control:

1. **Authority propagation** — honest admin sets a parameter that enables an unprivileged user's exploit
2. **Composition failures** — admin action in protocol A enables exploit in protocol B
3. **Flash-loan governance** — governance power can be borrowed temporarily
4. **Config interaction** — admin sets two individually-valid parameters that together create a vulnerability

---

## Decision Rules

Sum all six dimension scores → `da_total_score`:

| Condition | Result |
|:----------|:-------|
| At least one −3 AND total ≤ −6 | **INVALIDATED** — attack is impossible; discard finding |
| Total −5 to −3 | **DEGRADED** — degrade confidence to "Possible" / CONTESTED |
| Total −2 to +2 | **SUSTAINED** — keep confidence as "Likely" / PARTIAL or CONFIRMED |
| Total ≥ +3 | **ESCALATED** — raise confidence to "Confirmed"; raise severity if at ceiling |

> **Critical rule:** Partial mitigations DEGRADE confidence. They NEVER dismiss alone. Do not INVALIDATE when total > −6, even with several partial mitigations.

---

## DA Evaluation Record

Document each finding's DA evaluation inline:

```
DA Evaluation: [Finding Title]
  guards:                [score] — [evidence, file:line]
  reentrancy_protection: [score] — [evidence, file:line]
  access_control:        [score] — [evidence, file:line]
  by_design:             [score] — [Safe/Risky/Undocumented, evidence]
  economic_feasibility:  [score] — [capital req., gas, expected yield]
  dry_run:               [score] — [concrete values traced, arithmetic result]
  ─────────────────────────────
  Total: [sum]  →  INVALIDATED / DEGRADED / SUSTAINED / ESCALATED
```

---

## Disallowed Behaviors

- Do NOT skip any of the 6 dimensions
- Do NOT assign a score without concrete evidence and a code reference
- Do NOT dismiss a finding when only partial mitigations exist (total > −6)
- Do NOT use the Privilege Rule to dismiss findings where admin actions enable unprivileged exploits
- Do NOT mark `by_design = Safe` without finding actual documentation of the behavior
