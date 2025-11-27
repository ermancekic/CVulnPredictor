"""
Utility script to print, for each metric, the threshold at which the
Lift value is maximal, together with that Lift value, how many methods
were selected at that threshold, and how many vulnerabilities were found.

Data source:
    data/general/result_states.json

Structure (see src/modules/calculate_results.save_result_state):
    {
      "<metric>": {
        "<threshold>": [
          total_vulns,       # index 0
          found_vulns,       # index 1
          total_methods,     # index 2  <-- selected methods
          coverage,          # index 3
          lift,              # index 4  <-- we maximize this
          precision,         # index 5
          recall,            # index 6
          f1,                # index 7
          TP,                # index 8
          FP,                # index 9
          TN,                # index 10
          FN,                # index 11
          f2,                # index 12 (optional)
          f3                 # index 13 (optional)
        ]
      },
      ...
    }
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, Tuple


def load_result_states(path: str) -> Dict[str, Dict[str, list[Any]]]:
    try:
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
    except FileNotFoundError:
        print(f"Result states file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read {path}: {e}", file=sys.stderr)
        sys.exit(1)

    if not isinstance(data, dict):
        print(f"Unexpected format in {path}: top-level object must be a dict", file=sys.stderr)
        sys.exit(1)

    cleaned: Dict[str, Dict[str, list[Any]]] = {}
    for metric, thresholds in data.items():
        if not isinstance(thresholds, dict):
            continue
        inner: Dict[str, list[Any]] = {}
        for thr, values in thresholds.items():
            if isinstance(thr, str) and isinstance(values, list):
                inner[thr] = values
        if inner:
            cleaned[metric] = inner
    return cleaned


def _find_best_lift(
    thresholds: Dict[str, list[Any]],
) -> Tuple[str, float, int, int] | None:
    best_thr: str | None = None
    best_lift: float | None = None
    best_methods: int | None = None
    best_found: int | None = None

    for thr, values in thresholds.items():
        if not isinstance(values, list) or len(values) <= 4:
            continue
        lift = values[4]
        methods = values[2] if len(values) > 2 else None
        found_vulns = values[1] if len(values) > 1 else None

        try:
            lift_f = float(lift)
        except Exception:
            continue

        try:
            methods_i = int(methods) if methods is not None else 0
        except Exception:
            methods_i = 0

        try:
            found_i = int(found_vulns) if found_vulns is not None else 0
        except Exception:
            found_i = 0

        if best_lift is None or lift_f > best_lift:
            best_lift = lift_f
            best_thr = thr
            best_methods = methods_i
            best_found = found_i

    if best_thr is None or best_lift is None or best_methods is None or best_found is None:
        return None
    return best_thr, best_lift, best_methods, best_found


def main() -> None:
    base = os.getcwd()
    states_path = os.path.join(base, "data", "general", "result_states.json")

    states = load_result_states(states_path)
    if not states:
        print("No metrics found in result_states.json", file=sys.stderr)
        sys.exit(1)

    json_result: Dict[str, Dict[str, Any]] = {}

    # Print a simple aligned table with Lift information
    print("Metric\tLift threshold\tLift\tMethods\tFound vulns")

    for metric in sorted(states.keys()):
        thresholds = states[metric]
        best = _find_best_lift(thresholds)
        if best is None:
            continue

        thr, lift, methods, found_vulns = best

        json_result[metric] = {
            "threshold": thr,
            "lift": lift,
            "methods": methods,
            "found_vulns": found_vulns,
        }

        print(f"{metric}\t{thr}\t{lift:.10f}\t{methods}\t{found_vulns}")

    out_path = os.path.join(base, "data", "general", "highest_lift.json")
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(json_result, f, indent=2, ensure_ascii=False)
        print(f"\nWrote JSON summary to {out_path}")
    except Exception as e:
        print(f"Failed to write JSON summary to {out_path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
