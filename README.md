<img src="Logo.png" alt="Logo" width="200">

# CVulnPredictor

This code was developed as part of my Bachelor's thesis on evaluating software metrics as targeting strategies for directed fuzzing in OSS-Fuzz projects.

## Overview

This project analyzes the effectiveness of software metrics as targeting strategies for directed fuzzing. It processes C/C++ projects from OSS-Fuzz, calculates function‑level code metrics (e.g., cyclomatic complexity, lines of code, loop nesting depth, pointer arithmetic, control‑structure properties) and product (project‑level) metrics from Git history (e.g., number of changes, lines changed, number of contributors), and evaluates how well these metrics can identify vulnerable functions.

The system:
- Clones vulnerable OSS-Fuzz projects and their specific vulnerable commits
- Uses Clang/LLVM to parse source code and calculate function‑level metrics, plus product (project‑level) metrics from Git history
- Filters functions based on configurable metric thresholds
- Matches filtered functions against known vulnerabilities
- Generates statistical reports on the effectiveness of each metric as a targeting strategy

The goal is to determine which software metrics are most effective at identifying potentially vulnerable code sections for directed fuzzing campaigns.

## Metrics
- Full list and definitions: `docs/Metrics.md`
- Categories:
  - Project Metrics (function‑level): cyclomatic complexity, LOC, loops and nesting, pointer arithmetic, control‑structure metrics, parameters, etc.
  - Product Metrics (project‑level/Git): `NumChanges`, `LinesChanged`, `LinesNew`, `NumDevs`.

## Dependencies
- python3
- python3-pip
- python3-venv
- git

## Run the pipeline

From within the base directory, run:
```
./src/run.sh
```
