"""
main.py

Orchestrates the end-to-end workflow:
- Set up logging
- Clone OSS-Fuzz definitions and vulnerability data
- Filter and retrieve OSS projects with vulnerabilities and commits
- Clone project repositories
- Calculate metrics in parallel
- Compute and persist final results
"""

import ujson as json
import logging
import os
import traceback
import multiprocessing
import concurrent.futures

def setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="[%(processName)s] %(asctime)s %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    )

setup_logging()
import modules.prepare_projects
modules.prepare_projects.get_clang_dependencies()
modules.prepare_projects.prepare_directories()

# File-Handler nur für Metrik-Fehler
metrics_err_handler = logging.FileHandler("logs/metrics_errors.log", encoding="utf-8")
metrics_err_handler.setLevel(logging.ERROR)
metrics_err_handler.setFormatter(logging.Formatter(
    "[%(asctime)s] %(levelname)s in %(name)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
))
logger = logging.getLogger("metrics_error_logger")
logger.addHandler(metrics_err_handler)

import modules.calculate_metrics
import modules.retrieve_oss_fuzz_data
import modules.calculate_results
import modules.get_stacktraces


# Thresholds for filtering metrics
thresholds = {
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
    # "number of variables involved in control predicates": -1
}


def print_json(data, file_path):
    """
    Write a Python object to a JSON file and log the entry count.

    Args:
        data (Any): Data to serialize (list, dict, etc.).
        file_path (str): Destination file path for the JSON output.

    Returns:
        None
    """
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
    logging.info(f"{len(data)} entries written to {file_path}")


def clone_project(project_tuple):
    """
    Clone a project repository and optionally checkout specific commits.

    Args:
        project_tuple (tuple): (project_name, url, *commits) specifying the repository and commit hashes.

    Returns:
        tuple[str, list[str] | None]: The project name and list of commits on success, or None on failure.
    """
    project_name, url, *commits = project_tuple
    logging.info(f"Cloning project {project_name} from {url} with {len(commits)} commits...")
    try:
        modules.prepare_projects.get_oss_projects((project_name, url, *commits))
        return project_name, commits
    except Exception as e:
        tb = traceback.format_exc()
        logging.info(f"Error cloning {project_name}: {e}\n{tb}")
        return project_name, None

def calculate_metrics(project_path):
    """
    Run metric calculations for a given project directory.

    Args:
        project_path (str): Path to the cloned project directory.

    Returns:
        tuple[str, bool]: Project name and True if metrics ran successfully, False otherwise.
    """
    project_dir = os.path.basename(project_path)
    try:
        logging.info(f"Running metrics for {project_dir}...")
        modules.calculate_metrics.run(project_path, False)
        return project_dir, True

    except Exception as e:
        # vollständigen Traceback als String
        tb = traceback.format_exc()

        # 1) Log in der Konsole/file via eigenem Logger
        logger.info(f"Metrics error for {project_dir}: {e}\n{tb}")

        # 2) (optional) zusätzlich in einer JSON-Datei ablegen
        os.makedirs("logs/metrics_json_errors", exist_ok=True)
        err_path = os.path.join("logs/metrics_json_errors", f"{project_dir}_error.json")
        with open(err_path, "w", encoding="utf-8") as f:
            json.dump({
                "project": project_dir,
                "error": str(e),
                "traceback": tb
            }, f, indent=2, ensure_ascii=False)

        return project_dir, False

def main():
    """
    Main entry point for the metrics pipeline.

    Args:
        None

    Returns:
        None
    """

    base_dir = os.path.join(os.getcwd(), "repositories", "OSS-Projects")

    # Prepare project
    modules.prepare_projects.get_oss_repo()
    modules.prepare_projects.get_arvo_meta()
    modules.prepare_projects.filter_oss_projects()
    modules.prepare_projects.get_oss_fuzz_vulns()
    modules.prepare_projects.get_project_includes()

    # Retrieve vulnerable projects
    modules.retrieve_oss_fuzz_data.get_project_tuples_with_vulns()
    modules.retrieve_oss_fuzz_data.get_oss_vulns_data_as_json()
    modules.retrieve_oss_fuzz_data.update_missing_commits_in_vulns()
    modules.retrieve_oss_fuzz_data.delete_unfixable_broken_commits()
    modules.retrieve_oss_fuzz_data.get_new_oss_vuln_ids(128)
    modules.retrieve_oss_fuzz_data.remove_vulns_that_are_not_in_arvo_table()

    # Get stack traces
    modules.get_stacktraces.get_stacktraces_from_table()
    modules.get_stacktraces.extract_vuln_location()

    # Extract commits
    vulns_with_commits = modules.prepare_projects.get_vulnerable_projects_with_commits()
    logging.info(f"Found {len(vulns_with_commits)} vulnerable projects with commits.")

    # Clone all projects
    clone_results = []
    max_workers = multiprocessing.cpu_count() * 6
    logging.info(f"Using {max_workers} workers for cloning projects.")
    with concurrent.futures.ThreadPoolExecutor(max_workers) as pool:
        futures = [pool.submit(clone_project, proj) for proj in vulns_with_commits]
        for fut in concurrent.futures.as_completed(futures):
            clone_results.append(fut.result())

    projects = []
    for entry in os.listdir(base_dir):
        projects.append(os.path.join(base_dir, entry))
    logging.info("Anzahl geklonter Projekte: ", len(os.listdir(base_dir)))

    # Calculate metrics
    max_workers = multiprocessing.cpu_count() * 3
    with concurrent.futures.ProcessPoolExecutor(max_workers=max_workers) as pool:
        futures = [pool.submit(calculate_metrics, project_path) for project_path in projects]
        for future in concurrent.futures.as_completed(futures):
            try:
                future.result()
            except Exception as e:
                logging.error(f"Fehler bei Projekt: {e}")

    # Final result calculations
    modules.calculate_results.separate_and_filter_calculated_metrics(thresholds)
    modules.calculate_results.check_if_function_in_vulns()
    modules.calculate_results.calculate_infos()

if __name__ == "__main__":
    main()
