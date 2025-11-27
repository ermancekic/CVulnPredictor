"""
Compute, for each metric at its best F3 threshold, how many known vulnerabilities
are found only by that metric (and by no other metric at those thresholds).

The script mirrors the vulnerability-to-metric matching logic in
``src/modules/calculate_results.py``:
  - match by project + localID file name (e.g., ``Qt_123.json``)
  - within the JSON, match the code path suffix against the vulnerability's file
    path and the base function name; parameter count is used when present

Output:
  - prints a small table: Metric | Threshold | Found (at threshold) | Unique
  - writes ``data/general/unique_f3_vulns.json`` with counts and IDs
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Iterable, Set, Tuple

from src.modules.calculate_results import (
    _base_func_name,
    _normalize_loc_path,
    _param_info,
)

# Best Lift thresholds per metric (taken from the table's "Lift" column)
THRESHOLDS: Dict[str, int] = {
    "lines of code": 400,
    "cyclomatic complexity": 200,
    "number of loops": 40,
    "number of nested loops": 8,
    "max nesting loop depth": 5,
    "number of parameter variables": 13,
    "number of callee parameter variables": 45,
    "number of pointer arithmetic": 200,
    "number of variables involved in pointer arithmetic": 12,
    "max pointer arithmetic variable is involved in": 225,
    "number of nested control structures": 6,
    "maximum nesting level of control structures": 10,
    "maximum of control dependent control structures": 70,
    "maximum of data dependent control structures": 30,
    "number of if structures without else": 70,
    "number of variables involved in control predicates": 40,
    "NumChanges": 300,
    "NumDevs": 50,
}


def _load_vulnerabilities(arvo_dir: str) -> Iterable[Tuple[str, Dict[str, Any]]]:
    """Yield (project, vulnerability_dict) tuples from data/arvo-projects."""
    try:
        entries = [e for e in os.listdir(arvo_dir) if e.endswith(".json")]
    except Exception:
        entries = []

    for entry in sorted(entries):
        project = os.path.splitext(entry)[0]
        path = os.path.join(arvo_dir, entry)
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            print(f"Failed to read {path}: {e}", file=sys.stderr)
            continue

        if not isinstance(data, list):
            continue

        for vuln in data:
            if isinstance(vuln, dict):
                yield project, vuln


def _sm_matches_vuln(
    sm_data: Dict[str, Any],
    loc_file: str,
    func_name: str,
    vuln_param_count: int | None,
) -> bool:
    """Return True if the single-metric entry contains the vulnerable method."""
    if not isinstance(sm_data, dict) or not loc_file or not func_name:
        return False

    for code_path, funcs in sm_data.items():
        code_path_norm = (code_path or "").replace("\\", "/")
        if not code_path_norm.endswith(loc_file):
            continue
        if not isinstance(funcs, dict):
            continue

        for sig in funcs.keys():
            sig_base = _base_func_name(sig)
            if sig_base != func_name:
                continue
            sig_param_count, _sig_param_types = _param_info(sig)
            if vuln_param_count is not None:
                if sig_param_count is not None and sig_param_count != vuln_param_count:
                    continue
            return True

    return False


def main() -> None:
    base = os.getcwd()
    arvo_dir = os.path.join(base, "data", "arvo-projects")
    single_metrics_dir = os.path.join(base, "data", "single-metrics")
    out_dir = os.path.join(base, "data", "general")
    os.makedirs(out_dir, exist_ok=True)

    # Prepare per-metric metadata: threshold folder and file listing for quick checks
    metric_info: Dict[str, Dict[str, Any]] = {}
    for metric, thr in THRESHOLDS.items():
        thr_str = str(thr)
        mdir = os.path.join(single_metrics_dir, metric, thr_str)
        try:
            files = {e for e in os.listdir(mdir) if e.endswith(".json")}
        except Exception:
            files = set()
            print(f"No data for metric '{metric}' at threshold {thr_str} ({mdir})", file=sys.stderr)
        metric_info[metric] = {"dir": mdir, "thr": thr_str, "files": files}

    found_by_metric: Dict[str, Set[str]] = {m: set() for m in metric_info.keys()}
    vuln_to_metrics: Dict[str, Set[str]] = {}

    for project, vuln in _load_vulnerabilities(arvo_dir):
        local_id = vuln.get("localID")
        loc = vuln.get("location") if isinstance(vuln.get("location"), dict) else {}
        loc_file_raw = loc.get("file")
        loc_func_raw = loc.get("function", "") if isinstance(loc, dict) else ""

        if local_id is None or not loc_file_raw or not loc_func_raw:
            continue

        loc_file = _normalize_loc_path(loc_file_raw)
        func_name = _base_func_name(str(loc_func_raw))
        vuln_param_count, _vuln_param_types = _param_info(str(loc_func_raw))

        if not loc_file or not func_name:
            continue

        sm_key = f"{project}_{local_id}"
        target_file = f"{sm_key}.json"

        for metric, info in metric_info.items():
            if target_file not in info["files"]:
                continue
            sm_path = os.path.join(info["dir"], target_file)
            try:
                with open(sm_path, "r", encoding="utf-8") as sf:
                    sm_data = json.load(sf)
            except Exception:
                continue

            if _sm_matches_vuln(sm_data, loc_file, func_name, vuln_param_count):
                found_by_metric[metric].add(sm_key)
                vuln_to_metrics.setdefault(sm_key, set()).add(metric)

    # Compute unique vulns: those found by exactly one metric
    unique_by_metric: Dict[str, Set[str]] = {m: set() for m in metric_info.keys()}
    for sm_key, metrics_found in vuln_to_metrics.items():
        if len(metrics_found) == 1:
            metric = next(iter(metrics_found))
            unique_by_metric[metric].add(sm_key)

    # Print summary table
    print("Metric\tThreshold\tFound\tUnique")
    for metric in sorted(metric_info.keys()):
        info = metric_info[metric]
        found = len(found_by_metric.get(metric, set()))
        unique = len(unique_by_metric.get(metric, set()))
        print(f"{metric}\t{info['thr']}\t{found}\t{unique}")

    # Persist JSON summary
    out_path = os.path.join(out_dir, "unique_f3_vulns.json")
    json_out: Dict[str, Dict[str, Any]] = {}
    for metric in sorted(metric_info.keys()):
        info = metric_info[metric]
        json_out[metric] = {
            "threshold": info["thr"],
            "found_vulns": len(found_by_metric.get(metric, set())),
            "unique_vulns": len(unique_by_metric.get(metric, set())),
            "unique_ids": sorted(unique_by_metric.get(metric, set())),
        }

    try:
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(json_out, f, indent=2, ensure_ascii=False)
        print(f"\nWrote summary to {out_path}")
    except Exception as e:
        print(f"Failed to write summary to {out_path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
