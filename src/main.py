"""
main.py — Orchestrates the end-to-end workflow of the CVulnPredictor application.

This script performs the following steps:
1. Prepares directories and dependencies (ARVO table, Clang dependencies).
2. Exports and extracts vulnerability location data from the ARVO dataset.
3. Clones and processes ARVO projects to retrieve source and dependencies.
4. Calculates code metrics in parallel processes.
5. Generates final result analyses.
"""

from __future__ import annotations

# --- Standard library imports -------------------------------------------------
from concurrent.futures import ProcessPoolExecutor, as_completed
import logging
import multiprocessing as mp
from pathlib import Path
import os
import traceback

# --- Third‑party imports ------------------------------------------------------
import ujson as json

# --- Local application imports ----------------------------------------------
import modules.calculate_metrics as calc_metrics
import modules.calculate_results as calc_results
import modules.retrieve_arvo_table_data as arvo_data
import modules.prepare_projects as prep
from modules.get_projects import process_arvo_projects


# --- Constants ----------------------------------------------------------------
ROOT_DIR = Path.cwd()
REPOSITORIES_DIR = ROOT_DIR / "repositories"
LOG_DIR = ROOT_DIR / "logs"
METRICS_ERR_JSON_DIR = LOG_DIR / "metrics_json_errors"

THRESHOLDS = {
    # "lines of code": -1,
    # "cyclomatic complexity": -1,
    # "number of loops": -1,
    # "number of nested loops": -1,
    # "max nesting loop depth": -1,
    "number of parameter variables": -1,
    # "number of callee parameter variables": -1,
    # "number of pointer arithmetic": -1,
    # "number of variables involved in pointer arithmetic": -1,
    # "max pointer arithmetic variable is involved in": -1,
    # "number of nested control structures": -1,
    # "maximum nesting level of control structures": -1,
    # "maximum of control dependent control structures": -1,
    # "maximum of data dependent control structures": -1,
    # "number of if structures without else": -1,
    # "number of variables involved in control predicates": -1,
}


# --- Logging ------------------------------------------------------------------

def setup_logging(level: int = logging.INFO) -> logging.Logger:
    """Configure root logging and a dedicated metrics error logger."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    logging.basicConfig(
        level=level,
        format="[%(processName)s] %(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # File handler for metrics errors
    metrics_logger = logging.getLogger("metrics_error_logger")

    # Avoid adding duplicate handlers (useful in tests / repeated runs)
    existing_paths = {
        getattr(h, "baseFilename", None) for h in metrics_logger.handlers
        if isinstance(h, logging.FileHandler)
    }

    metrics_err_path = (LOG_DIR / "metrics_errors.log").resolve()
    if str(metrics_err_path) not in existing_paths:
        fh = logging.FileHandler(metrics_err_path, encoding="utf-8")
        fh.setLevel(logging.ERROR)
        fh.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s in %(name)s: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        metrics_logger.addHandler(fh)

    return metrics_logger


# --- Helpers ------------------------------------------------------------------

def write_json(data, file_path: Path) -> None:
    """Serialize *data* as JSON to *file_path* and log entry count when sensible."""
    file_path.parent.mkdir(parents=True, exist_ok=True)
    with file_path.open("w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

    try:
        n = len(data)  # type: ignore[arg-type]
    except Exception:
        n = "?"
    logging.info("%s entries written to %s", n, file_path)


def clone_project(project_tuple: tuple[str, str, *tuple[str, ...]]):
    """
    Clone a project repository and optionally checkout specific commits.

    Args:
        project_tuple: (project_name, url, *commits)

    Returns:
        (project_name, list_of_commits | None)
    """
    project_name, url, *commits = project_tuple
    logging.info("Cloning project %s from %s with %d commits...", project_name, url, len(commits))
    try:
        prep.get_oss_projects((project_name, url, *commits))
        return project_name, commits
    except Exception as e:  # noqa: BLE001 (surface full traceback below)
        tb = traceback.format_exc()
        logging.info("Error cloning %s: %s\n%s", project_name, e, tb)
        return project_name, None


def run_metrics_for_project(project_path: Path) -> tuple[str, bool]:
    """Run metric calculations for a given project directory.

    Returns (project_name, success).
    """
    project_dir_name = project_path.name
    metrics_logger = logging.getLogger("metrics_error_logger")

    try:
        logging.info("Running metrics for %s...", project_dir_name)
        calc_metrics.run(str(project_path), False)
        return project_dir_name, True

    except Exception as e:  # noqa: BLE001
        tb = traceback.format_exc()

        # 1) Log to dedicated metrics error logger
        metrics_logger.error("Metrics error for %s: %s\n%s", project_dir_name, e, tb)

        # 2) Store as JSON for later inspection
        METRICS_ERR_JSON_DIR.mkdir(parents=True, exist_ok=True)
        err_path = METRICS_ERR_JSON_DIR / f"{project_dir_name}_error.json"
        write_json({"project": project_dir_name, "error": str(e), "traceback": tb}, err_path)

        return project_dir_name, False


# --- Main orchestration -------------------------------------------------------

def main() -> None:
    # Logging
    setup_logging()

    # Prep data & tooling
    prep.prepare_directories()
    prep.get_arvo_table()
    prep.get_clang_dependencies()

    # Extract ARVO data
    arvo_data.export_per_project_crashes()
    arvo_data.extract_vuln_location()
    arvo_data.delete_null_locations_in_vuln()

    # Extract source/include files from ARVO Docker images
    try:
        process_arvo_projects(Path("data/arvo-projects"), REPOSITORIES_DIR)
    except Exception as e:
        logging.error("Error in process_arvo_projects: %s", e)

    prep.get_project_includes()

    # Discover repositories: entries under repositories/<entry>/<repo_name>
    projects: list[Path] = []
    if not REPOSITORIES_DIR.exists():
        logging.warning("Repositories directory missing: %s", REPOSITORIES_DIR)
    else:
        for entry in REPOSITORIES_DIR.iterdir():
            if not entry.is_dir():
                continue
            if "_" not in entry.name:
                logging.warning("Skipping %s: no '_' found in folder name", entry.name)
                continue

            repo_name = entry.name.split("_", 1)[0]
            repo_dir = entry / repo_name
            if repo_dir.is_dir():
                projects.append(repo_dir)
            else:
                logging.warning("Repo directory missing: %s – skipping %s", repo_dir, entry.name)

    # Calculate metrics in parallel
    max_workers = int(os.getenv("MAX_WORKERS", mp.cpu_count() * 3))
    successes = 0
    failures = 0

    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(run_metrics_for_project, p) for p in projects]
        for fut in as_completed(futures):
            try:
                _project, ok = fut.result()
                successes += int(ok)
                failures += int(not ok)
            except Exception as e:
                logging.error("Unhandled error in project task: %s", e)
                failures += 1

    logging.info("Metric runs finished. Successes: %d | Failures: %d", successes, failures)

    # Final result calculations
    calc_results.separate_and_filter_calculated_metrics(THRESHOLDS)
    calc_results.check_if_function_in_vulns()


if __name__ == "__main__":
    main()
