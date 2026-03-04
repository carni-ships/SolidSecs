#!/usr/bin/env python3
"""
score.py — Compare solidsecs tool output against DeFiVulnLabs ground truth.

Computes per-category and overall recall / precision / F1 scores.
Writes results to eval/results/metrics.json and eval/results/eval-report.md.

Usage:
    python3 score.py [--raw-dir ../results/raw] [--ground-truth ../ground-truth.json]
"""

import argparse
import json
import re
import sys
from collections import defaultdict
from datetime import datetime
from pathlib import Path


# ---------------------------------------------------------------------------
# Slither detector name → vulnerability category mapping
# ---------------------------------------------------------------------------
DETECTOR_TO_CATEGORY = {
    # Reentrancy
    "reentrancy-eth":         "reentrancy",
    "reentrancy-no-eth":      "reentrancy",
    "reentrancy-benign":      "reentrancy",
    "reentrancy-events":      "reentrancy",
    # Arithmetic
    "integer-overflow":       "arithmetic",
    "divide-before-multiply": "arithmetic",
    "tautology":              "arithmetic",
    "safe-cast":              "arithmetic",
    # Access control
    "tx-origin":              "access_control",
    "suicidal":               "access_control",
    "unprotected-upgrade":    "access_control",
    "controlled-delegatecall":"access_control",
    "delegatecall-loop":      "access_control",
    "uninitialized-local":    "access_control",
    "uninitialized-state":    "access_control",
    "arbitrary-send-erc20":   "access_control",
    "arbitrary-send-eth":     "access_control",
    "assembly":               "access_control",
    "incorrect-equality":     "access_control",
    "unprotected-nft-fork":   "access_control",
    # External calls
    "unchecked-lowlevel":     "external_calls",
    "unchecked-send":         "external_calls",
    "unchecked-transfer":     "external_calls",
    "send-instead-of-call":   "external_calls",
    # Storage / proxy
    "uninitialized-storage":  "proxy",
    # EVM specific
    "weak-prng":              "evm_specific",
    "encode-packed-collision":"evm_specific",
    "is-zero":                "evm_specific",
    # DOS
    "costly-loop":            "dos",
    "calls-loop":             "dos",
}


def load_ground_truth(path: Path) -> dict:
    with open(path) as f:
        data = json.load(f)
    # Index by filename (without path)
    index = {}
    for entry in data["contracts"]:
        key = Path(entry["file"]).name
        index[key] = entry
    return index


def parse_slither_json(path: Path) -> dict[str, set[str]]:
    """
    Parse Slither JSON output.
    Returns: {filename → set of detector names triggered}
    """
    findings: dict[str, set[str]] = defaultdict(set)

    if not path.exists():
        return findings

    try:
        with open(path) as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        print(f"  WARN: Could not parse {path}: {e}", file=sys.stderr)
        return findings

    for result in data.get("results", {}).get("detectors", []):
        detector = result.get("check", "")
        for element in result.get("elements", []):
            source = element.get("source_mapping", {}).get("filename_short", "")
            if source:
                filename = Path(source).name
                findings[filename].add(detector)

    return findings


def parse_aderyn_md(path: Path) -> dict[str, set[str]]:
    """
    Parse Aderyn markdown output.
    Returns: {filename → set of issue titles triggered}
    We map Aderyn titles to categories via keyword matching.
    """
    findings: dict[str, set[str]] = defaultdict(set)

    if not path.exists():
        return findings

    ADERYN_KEYWORD_MAP = {
        "centralization":    "access_control",
        "missing access":    "access_control",
        "unprotected":       "access_control",
        "reentrancy":        "reentrancy",
        "overflow":          "arithmetic",
        "underflow":         "arithmetic",
        "divide before":     "arithmetic",
        "precision":         "arithmetic",
        "unchecked return":  "external_calls",
        "unchecked transfer":"external_calls",
        "fee-on-transfer":   "external_calls",
        "delegatecall":      "access_control",
        "tx.origin":         "access_control",
        "selfdestruct":      "access_control",
        "storage collision": "proxy",
        "uninitialized":     "proxy",
        "oracle":            "oracle",
        "chainlink":         "oracle",
        "slippage":          "oracle",
        "signature":         "signature",
        "replay":            "signature",
        "ecrecover":         "signature",
        "randomness":        "evm_specific",
        "block.timestamp":   "evm_specific",
        "dos":               "dos",
        "denial":            "dos",
    }

    with open(path) as f:
        content = f.read()

    # Aderyn MD has sections like: ### filename.sol
    # and lists issues per file
    current_file = None
    for line in content.splitlines():
        file_match = re.search(r"`([^`]+\.sol)`", line)
        if file_match:
            current_file = Path(file_match.group(1)).name

        if current_file:
            line_lower = line.lower()
            for keyword, category in ADERYN_KEYWORD_MAP.items():
                if keyword in line_lower:
                    findings[current_file].add(f"aderyn:{category}")

    return findings


def score(ground_truth: dict, slither: dict, aderyn: dict) -> dict:
    """
    Compute TP/FP/FN per category and overall.
    A contract is a TP if any tool flagged its expected category.
    """
    categories = sorted({v["category"] for v in ground_truth.values()})

    per_cat: dict[str, dict] = {c: {"tp": 0, "fn": 0, "fp_files": []} for c in categories}
    overall = {"tp": 0, "fn": 0, "total": len(ground_truth)}

    # Track files flagged by tools that aren't in ground truth (FP pool)
    all_flagged_files: set[str] = set(slither.keys()) | set(aderyn.keys())
    gt_files: set[str] = set(ground_truth.keys())

    for filename, truth in ground_truth.items():
        category = truth["category"]
        expected = set(truth.get("expected_detectors", []))

        # What did tools actually flag for this file?
        slither_hits = slither.get(filename, set())
        aderyn_hits  = aderyn.get(filename, set())

        # Map slither detector names → categories
        slither_categories = {DETECTOR_TO_CATEGORY.get(d, "other") for d in slither_hits}
        # Aderyn findings already encoded as "aderyn:category"
        aderyn_categories  = {h.split(":")[1] for h in aderyn_hits if ":" in h}

        detected_categories = slither_categories | aderyn_categories

        if category in detected_categories or (expected and expected & slither_hits):
            per_cat[category]["tp"] += 1
            overall["tp"] += 1
        else:
            per_cat[category]["fn"] += 1
            overall["fn"] += 1

    # False positives: files flagged by tools not in ground truth
    fp_files = all_flagged_files - gt_files
    overall["fp"] = len(fp_files)

    # Compute recall / precision / F1 per category
    results_by_cat = {}
    for cat, counts in per_cat.items():
        tp = counts["tp"]
        fn = counts["fn"]
        gt_count = tp + fn
        recall = tp / gt_count if gt_count > 0 else 0.0
        results_by_cat[cat] = {
            "true_positives": tp,
            "false_negatives": fn,
            "ground_truth_count": gt_count,
            "recall": round(recall, 3),
        }

    # Overall
    tp = overall["tp"]
    fn = overall["fn"]
    fp = overall["fp"]
    total = overall["total"]
    recall    = tp / (tp + fn) if (tp + fn) > 0 else 0.0
    precision = tp / (tp + fp) if (tp + fp) > 0 else 0.0
    f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) > 0 else 0.0

    return {
        "overall": {
            "true_positives": tp,
            "false_negatives": fn,
            "false_positives": fp,
            "total_ground_truth": total,
            "recall":    round(recall,    3),
            "precision": round(precision, 3),
            "f1":        round(f1,        3),
        },
        "by_category": results_by_cat,
        "fp_files": sorted(fp_files),
    }


def render_markdown(metrics: dict, timestamp: str) -> str:
    o = metrics["overall"]
    lines = [
        "# SolidSecs Evaluation Report",
        "",
        f"**Date:** {timestamp}  ",
        f"**Corpus:** DeFiVulnLabs (ground-truth.json)  ",
        f"**Tools scored:** Slither, Aderyn",
        "",
        "---",
        "",
        "## Overall Metrics",
        "",
        f"| Metric | Value |",
        f"|--------|-------|",
        f"| Ground truth contracts | {o['total_ground_truth']} |",
        f"| True Positives (caught) | {o['true_positives']} |",
        f"| False Negatives (missed) | {o['false_negatives']} |",
        f"| False Positives (noise) | {o['false_positives']} |",
        f"| **Recall** | **{o['recall']:.1%}** |",
        f"| **Precision** | **{o['precision']:.1%}** |",
        f"| **F1 Score** | **{o['f1']:.1%}** |",
        "",
        "---",
        "",
        "## Results by Vulnerability Category",
        "",
        "| Category | GT Contracts | Caught | Missed | Recall |",
        "|----------|-------------|--------|--------|--------|",
    ]

    for cat, r in sorted(metrics["by_category"].items()):
        recall_pct = f"{r['recall']:.0%}"
        emoji = "✅" if r["recall"] >= 0.8 else ("⚠️" if r["recall"] >= 0.4 else "❌")
        lines.append(
            f"| {cat} | {r['ground_truth_count']} | "
            f"{r['true_positives']} | {r['false_negatives']} | "
            f"{emoji} {recall_pct} |"
        )

    lines += [
        "",
        "---",
        "",
        "## False Positive Files (flagged but not in ground truth)",
        "",
    ]
    if metrics["fp_files"]:
        for f in metrics["fp_files"]:
            lines.append(f"- `{f}`")
    else:
        lines.append("_None_")

    lines += [
        "",
        "---",
        "",
        "## Interpretation",
        "",
        "- **Recall** = fraction of known vulnerabilities the tools detected.",
        "  A recall of 70%+ per category is considered good for automated tools.",
        "- **Precision** = fraction of tool findings that match ground truth.",
        "  Low precision = high false positive rate = more manual review needed.",
        "- **F1** = harmonic mean of recall and precision.",
        "",
        "### Coverage Gaps (categories with recall < 50%)",
        "",
    ]

    gaps = [
        cat for cat, r in metrics["by_category"].items()
        if r["recall"] < 0.5 and r["ground_truth_count"] > 0
    ]
    if gaps:
        for cat in sorted(gaps):
            r = metrics["by_category"][cat]
            lines.append(
                f"- **{cat}**: {r['true_positives']}/{r['ground_truth_count']} caught — "
                f"requires manual/semantic analysis"
            )
    else:
        lines.append("_No categories below 50% recall._")

    lines += ["", "---", "", "_Generated by solidsecs eval harness._"]
    return "\n".join(lines)


def main():
    parser = argparse.ArgumentParser(description="Score solidsecs tool output against ground truth")
    parser.add_argument("--raw-dir",      default="../results/raw",       help="Directory with tool output")
    parser.add_argument("--ground-truth", default="../ground-truth.json", help="Ground truth JSON")
    parser.add_argument("--out-dir",      default="../results",           help="Output directory")
    args = parser.parse_args()

    script_dir = Path(__file__).parent
    raw_dir    = (script_dir / args.raw_dir).resolve()
    gt_path    = (script_dir / args.ground_truth).resolve()
    out_dir    = (script_dir / args.out_dir).resolve()
    out_dir.mkdir(parents=True, exist_ok=True)

    print(f"Loading ground truth from {gt_path}")
    ground_truth = load_ground_truth(gt_path)
    print(f"  {len(ground_truth)} contracts in ground truth")

    print(f"\nParsing Slither output from {raw_dir / 'slither/full-project.json'}")
    slither = parse_slither_json(raw_dir / "slither" / "full-project.json")
    print(f"  {len(slither)} files with findings")

    print(f"\nParsing Aderyn output from {raw_dir / 'aderyn/full-project.md'}")
    aderyn = parse_aderyn_md(raw_dir / "aderyn" / "full-project.md")
    print(f"  {len(aderyn)} files with findings")

    print("\nScoring...")
    metrics = score(ground_truth, slither, aderyn)

    # Write JSON metrics
    metrics_path = out_dir / "metrics.json"
    with open(metrics_path, "w") as f:
        json.dump(metrics, f, indent=2)
    print(f"  Metrics written to {metrics_path}")

    # Write markdown report
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M")
    md = render_markdown(metrics, timestamp)
    report_path = out_dir / "eval-report.md"
    with open(report_path, "w") as f:
        f.write(md)
    print(f"  Report written to {report_path}")

    # Print summary to stdout
    o = metrics["overall"]
    print(f"""
╔══════════════════════════════════════╗
║       SolidSecs Eval Summary         ║
╠══════════════════════════════════════╣
║  Recall:    {o['recall']:.1%:<28} ║
║  Precision: {o['precision']:.1%:<28} ║
║  F1 Score:  {o['f1']:.1%:<28} ║
║  Caught:    {o['true_positives']}/{o['total_ground_truth']} contracts{'':<19} ║
╚══════════════════════════════════════╝
""")


if __name__ == "__main__":
    main()
