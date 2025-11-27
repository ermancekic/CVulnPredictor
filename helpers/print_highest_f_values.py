"""
Utility script to print, for each metric, the threshold at which the
F1-score is maximal, together with that F1 value and how many methods
were selected at that threshold.

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
          lift,              # index 4
          precision,         # index 5
          recall,            # index 6
          f1,                # index 7  <-- we maximize this
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

    # Be defensive: ensure nested structure is dict-of-dicts
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


def _find_best_score(
    thresholds: Dict[str, list[Any]],
    score_index: int,
) -> Tuple[str, float, int, int] | None:
    best_thr: str | None = None
    best_score: float | None = None
    best_methods: int | None = None
    best_found: int | None = None

    for thr, values in thresholds.items():
        if not isinstance(values, list) or len(values) <= score_index:
            continue
        score = values[score_index]
        methods = values[2] if len(values) > 2 else None
        found_vulns = values[1] if len(values) > 1 else None

        try:
            score_f = float(score)
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

        if best_score is None or score_f > best_score:
            best_score = score_f
            best_thr = thr
            best_methods = methods_i
            best_found = found_i

    if best_thr is None or best_score is None or best_methods is None or best_found is None:
        return None
    return best_thr, best_score, best_methods, best_found


def main() -> None:
    base = os.getcwd()
    states_path = os.path.join(base, "data", "general", "result_states.json")

    states = load_result_states(states_path)
    if not states:
        print("No metrics found in result_states.json", file=sys.stderr)
        sys.exit(1)

    # Collect results to also write them as JSON
    json_result: Dict[str, Dict[str, Any]] = {}

    # Print a simple aligned table with F1/F2/F3 information
    print(
        "Metric\t"
        "F1 threshold\tF1\tF1 methods\tF1 vulns\t"
        "F2 threshold\tF2\tF2 methods\tF2 vulns\t"
        "F3 threshold\tF3\tF3 methods\tF3 vulns"
    )

    for metric in sorted(states.keys()):
        thresholds = states[metric]

        best_f1 = _find_best_score(thresholds, 7)
        best_f2 = _find_best_score(thresholds, 12)
        best_f3 = _find_best_score(thresholds, 13)

        # Require at least F1 to be present
        if best_f1 is None:
            continue

        thr1, f1, m1, v1 = best_f1

        if best_f2 is not None:
            thr2, f2, m2, v2 = best_f2
            thr2_s = thr2
            f2_s = f"{f2:.10f}"
            m2_s = str(m2)
            v2_s = str(v2)
        else:
            thr2_s = "-"
            f2_s = "-"
            m2_s = "-"
            v2_s = "-"

        if best_f3 is not None:
            thr3, f3, m3, v3 = best_f3
            thr3_s = thr3
            f3_s = f"{f3:.10f}"
            m3_s = str(m3)
            v3_s = str(v3)
        else:
            thr3_s = "-"
            f3_s = "-"
            m3_s = "-"
            v3_s = "-"

        # Store in JSON-friendly structure
        entry: Dict[str, Any] = {
            "f1": {
                "threshold": thr1,
                "score": f1,
                "methods": m1,
                "found_vulns": v1,
            },
            "f2": None,
            "f3": None,
        }
        if best_f2 is not None:
            entry["f2"] = {
                "threshold": thr2,
                "score": f2,
                "methods": m2,
                "found_vulns": v2,
            }
        if best_f3 is not None:
            entry["f3"] = {
                "threshold": thr3,
                "score": f3,
                "methods": m3,
                "found_vulns": v3,
            }
        json_result[metric] = entry

        print(
            f"{metric}\t"
            f"{thr1}\t{f1:.10f}\t{m1}\t{v1}\t"
            f"{thr2_s}\t{f2_s}\t{m2_s}\t{v2_s}\t"
            f"{thr3_s}\t{f3_s}\t{m3_s}\t{v3_s}"
        )

    # Write JSON summary file
    out_path = os.path.join(base, "data", "general", "highest_f_scores.json")
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(json_result, f, indent=2, ensure_ascii=False)
        print(f"\nWrote JSON summary to {out_path}")
    except Exception as e:
        print(f"Failed to write JSON summary to {out_path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
