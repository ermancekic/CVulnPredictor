<img src="Logo.png" alt="Logo" width="200">

# CVulnPredictor

CVulnPredictor is the end-to-end pipeline that underpins my Bachelor's thesis on evaluating software metrics as targeting strategies for directed fuzzing in OSS-Fuzz projects. It clones vulnerable OSS-Fuzz cases, computes a rich set of process and product metrics, and quantifies which metrics surface vulnerable functions most efficiently.

## Overview

At a high level the system:
- prepares a reproducible workspace (folder layout, ARVO database, bundled Clang/LLVM toolchain),
- exports per-project crash manifests from the ARVO dataset and enriches them with best-effort file/line/function locations,
- replays ARVO Docker images to extract the vulnerable source code plus its headers and build artifacts,
- computes file-level process metrics and function-level product metrics via Clang’s Python bindings, and
- analyzes the metric outputs to measure lift, precision/recall, coverage, and \(F_\beta\) scores while recording timing data and overlaps.

The overall goal is to determine which metrics best identify code that deserves attention during directed fuzzing campaigns.


## Metrics

- Detailed list: `docs/Metrics.md`.
- **Function-level (product) metrics:** cyclomatic complexity, LOC, loop nesting, pointer arithmetic intensity, control-structure depth, argument usage, and related structural features extracted from the AST.
- **File-level (process) metrics:** accumulated commit counts, lines added/changed, and distinct contributors gathered via Git history.

Together these metrics describe both the inherent complexity of a function and the development churn around its file, allowing the analysis to blend static structure with change history.

## Requirements

- `python3`, `python3-pip`, `python3-venv`, `git`, `docker`
- The pipeline downloads the necessary Clang/LLVM artifacts automatically during the Project Preparation step.

## Running the Pipeline

Run the full end-to-end workflow from the repository root:

```bash
./src/run.sh
```

The script invokes `main.py`, which walks through each stage in order. Logs and per-step progress reports are written to `logs/`. If a step already produced the expected artifacts it is skipped, keeping reruns fast and safe.
