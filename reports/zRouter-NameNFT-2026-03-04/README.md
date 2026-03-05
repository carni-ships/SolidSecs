# Audit: zRouter / NameNFT — 2026-03-04

| Field | Value |
|-------|-------|
| **Project** | [z-fi/zRouter](https://github.com/z-fi/zRouter) |
| **Date** | 2026-03-04 |
| **Auditor** | Claude (solidsecs skill) |
| **Risk Score** | 22 / 100 |
| **Findings** | 1 Critical · 1 High · 4 Medium · 2 Low · 3 Info |

## Summary

Multi-AMM aggregator router (Uniswap V2/V3/V4, zAMM, Curve, Lido) + ENS-style `.wei` naming contract.

**Critical finding confirmed by on-chain exploit:** `swapCurve` grants `type(uint256).max` ERC20 approval to user-supplied, unvalidated Curve pool addresses. An attacker deploys a fake Curve pool, passes it in the `route` calldata, and the router approves + immediately calls into it — enabling theft of any token held by the router. 42,606 USDC was stolen on-chain (tx `0xfe34c4b...`), laundered via Railgun.

## Files

- [`audit-report.md`](./audit-report.md) — Full findings with attack paths and recommendations
