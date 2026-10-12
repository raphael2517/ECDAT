"""
ECDAT Scanner - CLI entry point.

    python -m scanner scan <target> [options]

<target> may be a Git URL, a local path, a zip archive, or a container image
reference.

stdout carries the scan result. stderr carries newline-delimited JSON progress
events, which is what the API worker consumes to stream to the browser.
"""

import argparse
import json
import sys
import time
import traceback
from pathlib import Path
from typing import Any, Dict

# Sibling modules are imported by bare name (from detection import ...), so the
# src directory must be importable regardless of how we were invoked.
_SRC_DIR = str(Path(__file__).resolve().parent)
if _SRC_DIR not in sys.path:
    sys.path.insert(0, _SRC_DIR)

from detection import detect
from enrichment import enrich_all
from ingestion import IngestionError, destroy_workspace, ingest
from utils import PROJECT_ROOT, emit_progress, get_config, log, new_scan_id, write_json

STAGES = [
    ("ingest", 5), ("sbom", 15), ("detect", 30), ("enrich", 55),
    ("risk", 70), ("recommend", 80), ("benchmark", 90), ("cbom", 97), ("done", 100),
]


def _advance(stage: str, **extra: Any) -> None:
    pct = dict(STAGES)[stage]
    emit_progress(stage, pct, **extra)


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="ecdat-scan",
        description="Enterprise Cryptographic Discovery & Analysis Tool - scanner",
    )
    sub = p.add_subparsers(dest="command", required=True)

    s = sub.add_parser("scan", help="Scan a target and emit a CycloneDX CBOM")
    s.add_argument("target", help="Git URL, local path, zip archive, or image ref")
    s.add_argument("-o", "--output", help="Output file (default: <output_dir>/<id>/cbom.json)")
    s.add_argument("--format", choices=["json", "xml"], default="json")
    s.add_argument("--z-estimate", type=float, default=None,
                   help="Mosca collapse time Z in years (default: $Z_ESTIMATE or 15)")
    s.add_argument("--report", help="Sidecar JSON with findings/risks/benchmarks")
    s.add_argument("--branch", help="Git branch to scan")
    s.add_argument("--rules", help="Override rules directory")
    s.add_argument("--no-bench", action="store_true", help="Skip the liboqs benchmark")
    s.add_argument("--iterations", type=int, default=100, help="Benchmark iterations")
    s.add_argument("--fast-bench", action="store_true", help="Benchmark with fewer iterations")
    s.add_argument("--keep-workspace", action="store_true", help="Do not delete the temp workspace")
    s.add_argument("-v", "--verbose", action="store_true")

    r = sub.add_parser("rerisk", help="Recompute risk at a different Mosca Z")
    r.add_argument("findings", help="Path to a findings JSON produced by 'scan --report'")
    r.add_argument("-z", "--z-estimate", type=float, required=True)
    r.add_argument("-o", "--output")

    return p


def cmd_scan(args: argparse.Namespace) -> int:
    from cbom_builder import build as build_bom
    from cbom_builder import serialize
    from recommender import compare, recommend_all, run_benchmarks
    from risk_engine import score_all, summary as risk_summary

    cfg = get_config()
    z = args.z_estimate if args.z_estimate is not None else cfg["z_estimate"]
    rules = Path(args.rules) if args.rules else cfg["rules_path"]
    scan_id = new_scan_id()
    started = time.time()

    log.info("scan %s | target=%s | z=%.1fy | rules=%s", scan_id, args.target, z, rules)

    if not rules.exists():
        log.error("rules directory not found: %s", rules)
        return 2

    _advance("ingest", scan_id=scan_id, target=args.target)
    kind, root, source, sbom = ingest(args.target, branch=args.branch)
    _advance("sbom", scan_id=scan_id, artifacts=len(sbom.get("artifacts", []) or []), kind=kind)

    try:
        _advance("detect", scan_id=scan_id)
        findings = detect(root, sbom, rules)

        _advance("enrich", scan_id=scan_id)
        findings = enrich_all(findings)

        _advance("risk", scan_id=scan_id)
        findings = score_all(findings, z_years=z)

        _advance("recommend", scan_id=scan_id)
        recs = recommend_all(findings)

        bench_rows, bench_cmp = [], []
        if not args.no_bench:
            _advance("benchmark", scan_id=scan_id, iterations=args.iterations)
            bench_rows = run_benchmarks(args.iterations, fast=args.fast_bench)
            bench_cmp = compare(bench_rows)
        else:
            _advance("benchmark", scan_id=scan_id, skipped=True)

        _advance("cbom", scan_id=scan_id)
        meta = {
            "scan_id": scan_id, "target": args.target, "kind": kind,
            "z_estimate": z, "rules": str(rules),
        }
        bom = build_bom(findings, recs, bench_cmp, meta)
        document = serialize(bom, fmt=args.format)

        out_path = Path(args.output) if args.output else cfg["output_dir"] / scan_id / f"cbom.{args.format}"
        write_json(out_path, json.loads(document)) if args.format == "json" else out_path.write_text(document)
        log.info("wrote %s", out_path)

        report = {
            "scan_id": scan_id,
            "target": args.target,
            "kind": kind,
            "z_estimate": z,
            "cbom_path": str(out_path),
            "elapsed_seconds": round(time.time() - started, 2),
            "summary": risk_summary(findings),
            "findings": [f.to_dict() for f in findings],
            "recommendations": recs,
            "benchmarks": [r.to_dict() for r in bench_rows],
            "benchmark_comparisons": bench_cmp,
            "rules": str(rules),
        }
        report_path = Path(args.report) if args.report else out_path.parent / "report.json"
        write_json(report_path, report)
        log.info("wrote %s", report_path)

        _advance("done", scan_id=scan_id, findings=len(findings), cbom=str(out_path))
        print(json.dumps({"scan_id": scan_id, "cbom": str(out_path), "report": str(report_path),
                          "findings": len(findings), "elapsed_seconds": report["elapsed_seconds"]}))
        return 0

    finally:
        if not args.keep_workspace and kind != "image":
            destroy_workspace(root.parent if root.name == "src" else root)


def cmd_rerisk(args: argparse.Namespace) -> int:
    from detection import Finding
    from risk_engine import score_all, summary as risk_summary

    data = json.loads(Path(args.findings).read_text(encoding="utf-8"))
    findings = [Finding(**f) for f in data["findings"]]
    score_all(findings, z_years=args.z_estimate)
    out = {
        "scan_id": data.get("scan_id"),
        "z_estimate": args.z_estimate,
        "summary": risk_summary(findings),
        "findings": [f.to_dict() for f in findings],
    }
    if args.output:
        write_json(Path(args.output), out)
    print(json.dumps(out, indent=2))
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if getattr(args, "verbose", False):
        import logging
        log.setLevel(logging.DEBUG)
    try:
        if args.command == "scan":
            return cmd_scan(args)
        if args.command == "rerisk":
            return cmd_rerisk(args)
    except IngestionError as exc:
        log.error("ingestion failed: %s", exc)
        emit_progress("error", 100, message=str(exc))
        return 3
    except Exception as exc:  # noqa: BLE001
        log.error("scan failed: %s", exc)
        log.debug("%s", traceback.format_exc())
        emit_progress("error", 100, message=str(exc))
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
