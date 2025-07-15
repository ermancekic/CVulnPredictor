<img src="Logo.png" alt="Logo" width="200">

# CVulnPredictor

This code was developed as part of my Bachelor's thesis on evaluating software metrics as targeting strategies for directed fuzzing in OSS-Fuzz projects.

## Overview

This project analyzes the effectiveness of various software metrics as targeting strategies for directed fuzzing. It processes C/C++ projects from OSS-Fuzz, calculates multiple code complexity metrics (such as cyclomatic complexity, lines of code, loop nesting depth, pointer arithmetic usage), and evaluates how well these metrics can identify vulnerable functions.

The system:
- Clones vulnerable OSS-Fuzz projects and their specific vulnerable commits
- Uses Clang/LLVM to parse source code and calculate 14 different software metrics
- Filters functions based on configurable metric thresholds
- Matches filtered functions against known vulnerabilities
- Generates statistical reports on the effectiveness of each metric as a targeting strategy

The goal is to determine which software metrics are most effective at identifying potentially vulnerable code sections for directed fuzzing campaigns.

## Dependencies
- python3
- python3-pip
- python3-venv
- git

## Usage