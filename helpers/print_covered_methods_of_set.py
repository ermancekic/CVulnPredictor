"""
Print how many unique methods each metric flags at given thresholds, following
the greedy set order, and how the union grows as metrics are added.

Default greedy source:
    data/general/greedy_set_cover_for_f3_all_product_metrics.json
Optional greedy source (pass as first CLI arg):
    data/general/greedy_set_cover_for_f3_top_6.json

Output columns:
    Idx    Metric    Threshold    Methods (unique)    NewUnique    Cumulative

Also writes a JSON summary named after the greedy file into data/general.
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Set

# Thresholds to apply when reading data/single-metrics/<metric>/<threshold>/
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
}


def _load_json(path: str) -> Any:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def _load_greedy_order(path: str) -> List[Dict[str, Any]]:
    try:
        data = _load_json(path)
    except FileNotFoundError:
        print(f"Greedy set file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read greedy set file {path}: {e}", file=sys.stderr)
        sys.exit(1)

    order = data.get("order")
    if not isinstance(order, list):
        print(f"Unexpected greedy set format in {path}: missing 'order' list", file=sys.stderr)
        sys.exit(1)
    return [o for o in order if isinstance(o, dict)]


def _method_id(code_path: str, func_name: str) -> str:
    code_norm = str(code_path).replace("\\", "/")
    return f"{code_norm}::{func_name}"


def _collect_methods_for_metric(metric: str, threshold: int, single_metrics_dir: str) -> Set[str]:
    thr_dir = os.path.join(single_metrics_dir, metric, str(threshold))
    if not os.path.isdir(thr_dir):
        print(f"No data for metric '{metric}' at threshold {threshold} ({thr_dir})", file=sys.stderr)
        return set()

    methods: Set[str] = set()
    for entry in sorted(os.listdir(thr_dir)):
        if not entry.endswith(".json"):
            continue
        path = os.path.join(thr_dir, entry)
        try:
            data = _load_json(path)
        except Exception as e:
            print(f"Failed to read {path}: {e}", file=sys.stderr)
            continue
        if not isinstance(data, dict):
            continue

        for code_path, funcs in data.items():
            if not isinstance(funcs, dict):
                continue
            for func_name in funcs.keys():
                if func_name == "__project_metrics__":
                    continue
                methods.add(_method_id(code_path, func_name))
    return methods


def main() -> None:
    base = os.getcwd()
    default_greedy = os.path.join(
        base, "data", "general", "greedy_set_cover_for_f3_all_product_metrics.json"
    )
    greedy_path = sys.argv[1] if len(sys.argv) > 1 else default_greedy
    single_metrics_dir = sys.argv[2] if len(sys.argv) > 2 else os.path.join(
        base, "data", "single-metrics"
    )

    greedy_order = _load_greedy_order(greedy_path)
    if not greedy_order:
        print("No metrics found in greedy order.", file=sys.stderr)
        sys.exit(1)

    cumulative: Set[str] = set()
    summary: List[Dict[str, Any]] = []

    print("Idx\tMetric\tThreshold\tMethods\tNewUnique\tCumulative")

    for pos, item in enumerate(greedy_order):
        metric = item.get("metric")
        if not metric:
            continue

        threshold = THRESHOLDS.get(metric)
        if threshold is None:
            print(f"No threshold configured for metric '{metric}', skipping.", file=sys.stderr)
            continue

        methods = _collect_methods_for_metric(metric, threshold, single_metrics_dir)
        new_unique = methods - cumulative
        cumulative |= methods

        idx = item.get("index", pos)
        methods_count = len(methods)
        new_count = len(new_unique)
        cumulative_count = len(cumulative)

        print(f"{idx}\t{metric}\t{threshold}\t{methods_count}\t{new_count}\t{cumulative_count}")

        summary.append(
            {
                "metric": metric,
                "index": idx,
                "threshold": threshold,
                "methods": methods_count,
                "new_unique": new_count,
                "cumulative_unique": cumulative_count,
            }
        )

    out_base = os.path.splitext(os.path.basename(greedy_path))[0]
    out_path = os.path.join(base, "data", "general", f"{out_base}_method_counts.json")

    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(
                {
                    "greedy_source": os.path.relpath(greedy_path, base),
                    "thresholds": THRESHOLDS,
                    "metrics": summary,
                    "total_unique_methods": len(cumulative),
                },
                f,
                indent=2,
                ensure_ascii=False,
            )
        print(f"\nWrote JSON summary to {out_path}")
    except Exception as e:
        print(f"Failed to write summary JSON: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
