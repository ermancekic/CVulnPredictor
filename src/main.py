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
import time

# Configure minimal console logging early so that imports below can log visibly.
# Record start time as early as possible to include import overhead.
_MAIN_START_PERF = time.perf_counter()
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

# --- Utilities: write main runtime ------------------------------------------
def _write_main_runtime(seconds: float) -> None:
    """Append the total runtime (seconds) to data/times/main.json.

    Keeps a list of floats, consistent with other timing JSONs under data/times.
    """
    try:
        # Resolve project root from this file location: src/ -> project root
        root = Path(__file__).resolve().parent.parent
        times_dir = root / "data" / "times"
        times_dir.mkdir(parents=True, exist_ok=True)
        out_path = times_dir / "main.json"

        existing: list[float] = []
        if out_path.exists():
            try:
                with out_path.open("r", encoding="utf-8") as rf:
                    data = json.load(rf)
                    if isinstance(data, list):
                        existing = [float(x) for x in data]
            except Exception:
                existing = []

        existing.append(float(seconds))

        with out_path.open("w", encoding="utf-8") as f:
            json_str = json.dumps(existing, indent=2, ensure_ascii=False)
            json_str = json_str.replace('\\/', '/')
            f.write(json_str)
    except Exception as e:
        logging.info(f"Failed to write main runtime: {e}")

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
    "lines of code": 0,
    "cyclomatic complexity": 0,
    "number of loops": 0,
    "number of nested loops": 0,
    "max nesting loop depth": 0,
    "number of parameter variables": 0,
    "number of callee parameter variables": 0,
    "number of pointer arithmetic": 0,
    "number of variables involved in pointer arithmetic": 0,
    "max pointer arithmetic variable is involved in": 0,
    "number of nested control structures": 0,
    "maximum nesting level of control structures": 0,
    "maximum of control dependent control structures": 0,
    "maximum of data dependent control structures": 0,
    "number of if structures without else": 0,
    "number of variables involved in control predicates": 0,
    "NumChanges": 0,
    "LinesChanged": 0,
    "LinesNew": 0,
    "NumDevs": 0,
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
    max_workers = 64
    successes = 0
    failures = 0

    if not projects:
        logging.warning("No repositories discovered under %s", REPOSITORIES_DIR)
        return

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
    calc_results.calculate_time_stats()

    calc_results.separate_and_filter_calculated_metrics(THRESHOLDS)
    calc_results.check_if_function_in_vulns()
    calc_results.delete_not_found_vulns_from_result()
    calc_results.delete_not_found_vulns_from_metrics_dir()
    calc_results.calculate_total_number_of_methods()
    calc_results.calculate_code_coverage()
    calc_results.calculate_lift()
    calc_results.save_result_state()

    finished = False

    # while not finished:
    for i in range(40):
        increments = {
            "lines of code": 100,
            "cyclomatic complexity": 100,
            "number of loops": 10,
            "number of nested loops": 2,
            "max nesting loop depth": 1,
            "number of parameter variables": 1,
            "number of callee parameter variables": 5,
            "number of pointer arithmetic": 200,
            "number of variables involved in pointer arithmetic": 1,
            "max pointer arithmetic variable is involved in": 75,
            "number of nested control structures": 2,
            "maximum nesting level of control structures": 1,
            "maximum of control dependent control structures": 10,
            "maximum of data dependent control structures": 10,
            "number of if structures without else": 10,
            "number of variables involved in control predicates": 2,
            "NumChanges": 50,
            "LinesChanged": 10000,
            "LinesNew": 10000,
            "NumDevs": 5,
        }
        for key in THRESHOLDS:
            THRESHOLDS[key] += increments.get(key, 0)

        calc_results.separate_and_filter_calculated_metrics(THRESHOLDS)
        calc_results.check_if_function_in_vulns(True)
        calc_results.calculate_total_number_of_methods()
        calc_results.calculate_code_coverage()
        calc_results.calculate_lift()
        finished = calc_results.save_result_state()

    # Plots for each metric: x=threshold, y=lift
    try:
        calc_results.plot_graphs()
    except Exception as e:
        logging.info(f"plot_graphs failed: {e}")


    threshold = {
        "lines of code": 500,
        "cyclomatic complexity": 1800,
        "number of loops": 390,
        "number of nested loops": 8,
        "max nesting loop depth": 8,
        "number of parameter variables": 21,
        "number of callee parameter variables": 125,
        "number of pointer arithmetic": 2800,
        "number of variables involved in pointer arithmetic": 39,
        "max pointer arithmetic variable is involved in": 1500,
        "number of nested control structures": 6,
        "maximum nesting level of control structures": 14,
        "maximum of control dependent control structures": 210,
        "maximum of data dependent control structures": 400,
        "number of if structures without else": 270,
        "number of variables involved in control predicates": 74,
    }

    calc_results.calculate_overlap_of_metrics(threshold)

if __name__ == "__main__":
    try:
        main()
    finally:
        duration = max(0.0, time.perf_counter() - _MAIN_START_PERF)
        _write_main_runtime(duration)
