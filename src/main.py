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

# Configure minimal console logging early so that imports below can log visibly.
def _parse_level(val: str | int | None) -> int:
    if isinstance(val, int):
        return val
    if not val:
        return logging.INFO
    s = str(val).strip().upper()
    if s.isdigit():
        try:
            return int(s)
        except Exception:
            return logging.INFO
    return {
        "CRITICAL": logging.CRITICAL,
        "ERROR": logging.ERROR,
        "WARNING": logging.WARNING,
        "WARN": logging.WARNING,
        "INFO": logging.INFO,
        "DEBUG": logging.DEBUG,
        "NOTSET": logging.NOTSET,
    }.get(s, logging.INFO)

_env_level = _parse_level(os.getenv("LOG_LEVEL", "INFO"))
logging.basicConfig(
    level=_env_level,
    format="[%(processName)s] %(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)d: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)

# Early file handler so import-time module logs also land in logs/app.log
try:
    _early_log_dir = Path.cwd() / "logs"
    _early_log_dir.mkdir(parents=True, exist_ok=True)
    _early_app_path = (_early_log_dir / "app.log").resolve()
    root_logger = logging.getLogger()
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(_early_app_path)
               for h in root_logger.handlers):
        _fh = logging.FileHandler(_early_app_path, encoding="utf-8")
        _fh.setLevel(_env_level)
        _fh.setFormatter(logging.Formatter(
            "[%(processName)s] %(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)d: %(message)s",
            datefmt="%Y-%m-%d %H:%M:%S",
        ))
        root_logger.addHandler(_fh)
except Exception:
    # Avoid import-time crashes due to logging setup
    pass

# --- Third‑party imports ------------------------------------------------------
import ujson as json

# --- Local application imports ------------------------------------------------
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
    "lines of code": -1,
    "cyclomatic complexity": -1,
    "number of loops": -1,
    "number of nested loops": -1,
    "max nesting loop depth": -1,
    "number of parameter variables": -1,
    "number of callee parameter variables": -1,
    "number of pointer arithmetic": -1,
    "number of variables involved in pointer arithmetic": -1,
    "max pointer arithmetic variable is involved in": -1,
    "number of nested control structures": -1,
    "maximum nesting level of control structures": -1,
    "maximum of control dependent control structures": -1,
    "maximum of data dependent control structures": -1,
    "number of if structures without else": -1,
    "number of variables involved in control predicates": -1,
    "NumChanges": -1,
    "LinesChanged": -1,
    "LinesNew": -1,
    "NumDevs": -1,
}


# --- Logging ------------------------------------------------------------------

def setup_logging(level: int | None = None) -> logging.Logger:
    """Configure root console + app file logging and a dedicated metrics error logger.

    - Respects LOG_LEVEL env by default, or uses provided numeric level.
    - Adds `logs/app.log` for all module logs.
    - Ensures `metrics_error_logger` writes to `logs/metrics_errors.log`.
    """
    LOG_DIR.mkdir(parents=True, exist_ok=True)

    final_level = _parse_level(level if level is not None else os.getenv("LOG_LEVEL", _env_level))

    root = logging.getLogger()
    root.setLevel(final_level)

    # Align console handlers with our formatter/level (basicConfig already added one)
    console_fmt = logging.Formatter(
        "[%(processName)s] %(asctime)s %(levelname)s %(name)s %(module)s:%(lineno)d: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )
    for h in root.handlers:
        if isinstance(h, logging.StreamHandler):
            h.setLevel(final_level)
            h.setFormatter(console_fmt)

    # Add app file handler once
    app_path = (LOG_DIR / "app.log").resolve()
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(app_path)
               for h in root.handlers):
        app_fh = logging.FileHandler(app_path, encoding="utf-8")
        app_fh.setLevel(final_level)
        app_fh.setFormatter(console_fmt)
        root.addHandler(app_fh)

    # Dedicated metrics error logger
    metrics_logger = logging.getLogger("metrics_error_logger")
    metrics_err_path = (LOG_DIR / "metrics_errors.log").resolve()
    if not any(isinstance(h, logging.FileHandler) and getattr(h, "baseFilename", None) == str(metrics_err_path)
               for h in metrics_logger.handlers):
        fh = logging.FileHandler(metrics_err_path, encoding="utf-8")
        fh.setLevel(logging.ERROR)
        fh.setFormatter(
            logging.Formatter(
                "[%(asctime)s] %(levelname)s in %(name)s %(module)s:%(lineno)d: %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S",
            )
        )
        metrics_logger.addHandler(fh)
    metrics_logger.propagate = True
    metrics_logger.setLevel(logging.ERROR)

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
    except Exception as e:
        tb = traceback.format_exc()
        logging.error("Error cloning %s: %s\n%s", project_name, e, tb)
        return project_name, None


def run_metrics_for_project(project_path: Path) -> tuple[str, bool]:
    """Run metric calculations for a given project directory.

    Returns (project_name, success).
    """
    project_dir_name = project_path.name
    # Ensure logging configuration for worker processes as well
    metrics_logger = setup_logging()

    try:
        logging.info("Running metrics for %s...", project_dir_name)
        calc_metrics.run(str(project_path), True)
        return project_dir_name, True

    except Exception as e:
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
    max_workers = mp.cpu_count() * 3
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
