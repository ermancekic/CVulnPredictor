"""
Utility script to compute a greedy ordering of metrics based on
their pairwise overlap in ``data/general/overlap_matrix.json``.

Interpretation:
    - Each metric corresponds to a set of vulnerabilities.
    - The JSON file contains a symmetric matrix where:
        * matrix[i][i]  ~= |S_i| (vulns found by metric i)
        * matrix[i][j]  ~= |S_i ∩ S_j|
    - We approximate a greedy set-cover style ordering:
        * Start with the metric that covers the most vulns (largest diagonal).
        * Iteratively add the metric that maximizes the estimated number of
          **new** vulns it contributes, i.e.
              new(i | selected) ~= diag(i) - sum_{j in selected} overlap(i, j)
          clamped at zero.
        * This prefers metrics that have high individual coverage but low
          overlap with already selected metrics.

The script prints a small text summary and writes a JSON file to
``data/general/greedy_set_cover.json`` with the structure:

    {
      "metrics": ["m1", "m2", ...],        # original order from the matrix
      "order": [
        {
          "metric": "mX",
          "index": 0,                      # greedy position
          "diag": 202,                     # |S_mX|
          "estimated_new": 202,            # new coverage at this step
          "estimated_total_covered": 202   # cumulative estimate
        },
        ...
      ]
    }
"""

from __future__ import annotations

import json
import os
import sys
from typing import Any, Dict, List, Tuple


def _load_overlap_matrix(path: str) -> Tuple[List[str], List[List[int]]]:
    """Load and validate the overlap matrix JSON."""
    try:
        with open(path, "r", encoding="utf-8") as f:
            data: Dict[str, Any] = json.load(f)
    except FileNotFoundError:
        print(f"Overlap matrix file not found: {path}", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        print(f"Failed to read overlap matrix {path}: {e}", file=sys.stderr)
        sys.exit(1)

    metrics = data.get("metrics")
    matrix = data.get("matrix")

    if not isinstance(metrics, list) or not all(isinstance(m, str) for m in metrics):
        print("Invalid overlap_matrix.json: 'metrics' must be a list of strings", file=sys.stderr)
        sys.exit(1)

    if not isinstance(matrix, list) or not all(isinstance(row, list) for row in matrix):
        print("Invalid overlap_matrix.json: 'matrix' must be a list of lists", file=sys.stderr)
        sys.exit(1)

    n = len(metrics)
    if len(matrix) != n or any(len(row) != n for row in matrix):
        print(
            "Invalid overlap_matrix.json: 'matrix' dimensions must match length of 'metrics'",
            file=sys.stderr,
        )
        sys.exit(1)

    # Normalize to ints for safety
    norm_matrix: List[List[int]] = []
    for i, row in enumerate(matrix):
        norm_row: List[int] = []
        for j, val in enumerate(row):
            try:
                norm_row.append(int(val))
            except Exception:
                print(
                    f"Invalid value at matrix[{i}][{j}] = {val!r}; expected an integer",
                    file=sys.stderr,
                )
                sys.exit(1)
        norm_matrix.append(norm_row)

    return metrics, norm_matrix


def _greedy_order(metrics: List[str], matrix: List[List[int]]) -> List[Dict[str, Any]]:
    """Compute a greedy ordering of metrics based on approximate new coverage."""
    n = len(metrics)
    diag = [matrix[i][i] for i in range(n)]

    # Indices of metrics not yet selected
    remaining = set(range(n))
    selected: List[int] = []

    result: List[Dict[str, Any]] = []
    total_covered_est = 0

    # Helper: compute estimated new coverage for candidate i.
    # Ignore self-overlap so we don't zero-out the first pick if it is
    # temporarily marked as selected.
    def estimated_new(i: int) -> int:
        overlap_sum = sum(matrix[i][j] for j in selected if j != i)
        new_val = diag[i] - overlap_sum
        return new_val if new_val > 0 else 0

    # Step 1: pick metric with largest diagonal (if any)
    if not remaining:
        return []

    first = max(remaining, key=lambda i: diag[i])
    remaining.remove(first)
    # The first metric's new coverage is its full diagonal value
    first_new = diag[first]
    selected.append(first)
    total_covered_est += first_new
    result.append(
        {
            "metric": metrics[first],
            "index": 0,
            "diag": diag[first],
            "estimated_new": first_new,
            "estimated_total_covered": total_covered_est,
        }
    )

    # Subsequent steps: always pick metric with largest estimated_new
    step = 1
    while remaining:
        # Compute estimated new coverage for all remaining metrics
        best_i: int | None = None
        best_new: int | None = None

        for i in remaining:
            new_val = estimated_new(i)
            if best_new is None or new_val > best_new:
                best_new = new_val
                best_i = i
            # In case of ties, prefer the metric with larger diag (more potential)
            elif new_val == best_new and best_i is not None and diag[i] > diag[best_i]:
                best_i = i

        # If for some reason everything has zero estimated_new, we still create
        # an ordering: pick the metric with largest diagonal among remaining.
        if best_i is None:
            best_i = max(remaining, key=lambda i: diag[i])
            best_new = estimated_new(best_i)

        remaining.remove(best_i)
        selected.append(best_i)

        total_covered_est += best_new if best_new is not None and best_new > 0 else 0
        result.append(
            {
                "metric": metrics[best_i],
                "index": step,
                "diag": diag[best_i],
                "estimated_new": int(best_new or 0),
                "estimated_total_covered": total_covered_est,
            }
        )
        step += 1

    return result


def main() -> None:
    base = os.getcwd()
    default_overlap_path = os.path.join(base, "data", "general", "overlap_matrix.json")

    # Optional: allow a custom input path as first CLI argument
    overlap_path = sys.argv[1] if len(sys.argv) > 1 else default_overlap_path

    metrics, matrix = _load_overlap_matrix(overlap_path)
    order = _greedy_order(metrics, matrix)

    if not order:
        print("No metrics found for greedy set cover.", file=sys.stderr)
        sys.exit(1)

    # Print a small human-readable summary
    print("Greedy metric ordering (lower overlap / higher new coverage first):")
    print("Idx\tMetric\tDiag\tEstNew\tEstTotalCovered")
    for item in order:
        print(
            f"{item['index']}\t{item['metric']}\t"
            f"{item['diag']}\t{item['estimated_new']}\t{item['estimated_total_covered']}"
        )

    # Write JSON output
    out_path = os.path.join(base, "data", "general", "greedy_set_cover.json")
    out_data = {
        "metrics": metrics,
        "order": order,
    }
    try:
        os.makedirs(os.path.dirname(out_path), exist_ok=True)
        with open(out_path, "w", encoding="utf-8") as f:
            json.dump(out_data, f, indent=2, ensure_ascii=False)
        print(f"\nWrote greedy set cover JSON to {out_path}")
    except Exception as e:
        print(f"Failed to write greedy set cover JSON to {out_path}: {e}", file=sys.stderr)


if __name__ == "__main__":
    main()
