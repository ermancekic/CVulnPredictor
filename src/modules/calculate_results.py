"""
calculate_results.py

This module provides functions to separate and filter calculated metrics by thresholds,
identify vulnerable methods based on single-metrics and known vulnerabilities,
and compute summary statistics for vulnerabilities discovered by metrics.
"""

import glob
import ujson as json
import os
import logging
import shutil
import os
from pathlib import Path
from collections import defaultdict

def separate_and_filter_calculated_metrics(thresholds):
    """
    Separate and filter calculated metrics into individual JSON files per metric.

    Args:
        thresholds (dict): Mapping of metric names to minimum threshold values.

    Returns:
        None
    """

    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "metrics")
    single_metrics_dir = os.path.join(base, "data", "single-metrics")

    # Komplettes Aufräumen der Ausgabeverzeichnisse
    if os.path.exists(single_metrics_dir):
        shutil.rmtree(single_metrics_dir)
    os.makedirs(single_metrics_dir, exist_ok=True)

    # Voraus anlegen aller Metrik-Unterordner (während thresholds bekannt)
    for metric_name in thresholds:
        os.makedirs(os.path.join(single_metrics_dir, metric_name), exist_ok=True)

    # Für jede Eingabedatei (Projekt/Commit) einmal einlesen und filtern
    for entry in os.listdir(metrics_dir):
        input_path = os.path.join(metrics_dir, entry)
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                metrics_data = json.load(f)
            logging.info(f"Processing file: {entry}")
        except Exception as e:
            logging.info(f"Fehler beim Lesen von {input_path}: {e}")
            continue

        # Sammelstruktur: metric_name -> file_name -> function_name -> {metric_name: value}
        filtered = defaultdict(lambda: defaultdict(dict))

        for file_name, functions in metrics_data.items():
            for func_name, metrics in functions.items():
                # func_name bleibt vollständig erhalten
                for metric_name, metric_value in metrics.items():
                    if metric_name in thresholds and metric_value >= thresholds[metric_name]:
                        # nur hier einmal anlegen, kein wiederholtes makedirs
                        filtered[metric_name][file_name].setdefault(func_name, {})[metric_name] = metric_value

        # Nun pro Metrik-Ordner genau eine Datei schreiben
        for metric_name, file_dict in filtered.items():
            out_dir = os.path.join(single_metrics_dir, metric_name)
            out_path = os.path.join(out_dir, entry)
            try:
                with open(out_path, 'w', encoding='utf-8') as f_out:
                    json.dump(file_dict, f_out, indent=2, ensure_ascii=False)
            except Exception as e:
                logging.info(f"Fehler beim Schreiben von {out_path}: {e}")

def check_if_function_in_vulns():
    """
    Identify functions from single-metrics that match known vulnerabilities and write results.

    Args:
        None

    Returns:
        None
    """
    single_metrics_dir = os.path.join(os.getcwd(), "data", "single-metrics")
    vulns_dir = os.path.join(os.getcwd(), "data", "vulns")
    output_dir = os.path.join(os.getcwd(), "data", "found-methods")
    os.makedirs(output_dir, exist_ok=True)

    # Iterate through single-metric directory
    for metric_name in os.listdir(single_metrics_dir):
        metric_dir = os.path.join(single_metrics_dir, metric_name)
        metric_result_dir = os.path.join(output_dir, metric_name)
        os.makedirs(metric_result_dir, exist_ok=True)

        # Iterate through each metric directory
        for entry in os.listdir(metric_dir):
            project_name = entry.split('_')[0]
            commit_hash = entry.split('_')[1].split('.')[0]

            project_metric_path = os.path.join(metric_dir, entry)
            project_vulns_path = os.path.join(vulns_dir, project_name + ".json")

            try:
                with open(project_metric_path, 'r') as f:
                    project_metrics = json.load(f)
            except Exception:
                print(f"Error reading metrics file: {project_metric_path}")
                continue

            try:
                with open(project_vulns_path, 'r') as f:
                    project_vulns = json.load(f)
            except Exception:
                print(f"Error reading metrics file: {project_vulns_path}")
                continue

            # Get the vulns for the specific commit
            vulns_for_commit = [
                v for v in project_vulns
                if v.get("introduced_commit") == commit_hash
            ]
            
            for v in project_vulns:
                if v.get("introduced_commit") is None:
                    logging.info(f"Vulnerability {v.get('id')} in {project_name} has no introduced commit, skipping.")
                    continue
            
            if not vulns_for_commit:
                continue

            # Dictionary to store matches
            matches = {}
            for file_path, funcs in project_metrics.items():
                for func_name, metrics in funcs.items():
                    func_name = func_name.split('(')[0]
                    # Prüfen, ob func_name in einer Vulnerability auftaucht
                    for vuln in vulns_for_commit:
                        if vuln.get("method") == func_name:
                            # Treffer speichern
                            matches.setdefault(file_path, {}) \
                                   .setdefault(func_name, []) \
                                   .append({
                                       "id": vuln.get("id"),
                                       "summary": vuln.get("summary"),
                                       "metric_name": metric_name
                                   })
            
            # If matches found, write to output file
            if matches:
                output_path = os.path.join(metric_result_dir, f"{project_name}_{commit_hash}.json")
                try:
                    with open(output_path, 'w', encoding='utf-8') as fout:
                        json.dump(matches, fout, indent=2, ensure_ascii=False)
                except Exception as e:
                    logging.info(f"Fehler beim Schreiben der Output-Datei {output_path}: {e}")
            # Compute and write missing vulnerabilities for debugging
            # Determine found IDs
            found_ids = {
                vuln_info['id']
                for funcs in matches.values()
                for vulns_list in funcs.values()
                for vuln_info in vulns_list
                if 'id' in vuln_info
            }
            # Identify vulnerabilities not matched
            missing_vulns = [
                v for v in vulns_for_commit
                if v.get('id') not in found_ids
            ]

            missing_output_path = os.path.join(os.getcwd(), "data", "not-found-methods")
            os.makedirs(missing_output_path, exist_ok=True)

            if missing_vulns:
                missing_output_path = os.path.join(
                    missing_output_path,
                    f"{project_name}_{commit_hash}_missing.json"
                )
                try:
                    with open(missing_output_path, 'w', encoding='utf-8') as fmiss:
                        json.dump(missing_vulns, fmiss, indent=2, ensure_ascii=False)
                except Exception as e:
                    logging.info(f"Fehler beim Schreiben der Missing-Datei {missing_output_path}: {e}")

def calculate_infos():
    """
    Calculate summary statistics of vulnerabilities discovered by metrics.

    Args:
        None

    Returns:
        dict: Summary containing:
            total_vulns (int): Total number of vulnerabilities across all projects.
            found_vulns (int): Total number of vulnerabilities found by metrics.
            metrics (dict): Mapping each metric name to a dict with:
                found_vulns (int): Vulnerabilities found for the metric.
                found_percentage (float): Percentage of total vulnerabilities found.
    """
    base_dir = os.getcwd()
    vulns_dir = os.path.join(base_dir, "data", "vulns")
    found_dir = os.path.join(base_dir, "data", "found-methods")
    output_dir = os.path.join(base_dir, "data", "general")
    os.makedirs(output_dir, exist_ok=True)

    # Load all vulnerabilities by project
    project_vulns = {}
    total_vulns = 0
    for vuln_file in glob.glob(os.path.join(vulns_dir, "*.json")):
        project = Path(vuln_file).stem
        with open(vuln_file, 'r', encoding='utf-8') as f:
            vuln_list = json.load(f)
        project_vulns[project] = vuln_list
        total_vulns += len(vuln_list)

    # Initialize metric summaries
    metrics_summary = {}
    for metric in os.listdir(found_dir):
        metrics_summary[metric] = {"found_vulns": 0}

    total_found = 0
    # Aggregate found vulnerabilities per metric
    for metric, summary in metrics_summary.items():
        metric_path = os.path.join(found_dir, metric)
        for entry in os.listdir(metric_path):
            project = entry.split('_', 1)[0]
            file_path = os.path.join(metric_path, entry)
            with open(file_path, 'r', encoding='utf-8') as f:
                found_data = json.load(f)

            # Collect unique vulnerability IDs found in this entry
            found_ids = {
                vuln['id']
                for funcs in found_data.values()
                for vulns_list in funcs.values()
                for vuln in vulns_list
                if 'id' in vuln
            }

            # Intersect with the project's known vulnerabilities
            known_ids = {v['id'] for v in project_vulns.get(project, []) if 'id' in v}
            valid_ids = found_ids & known_ids

            count = len(valid_ids)
            summary['found_vulns'] += count
            total_found += count

    # Compute percentages
    for summary in metrics_summary.values():
        summary['found_percentage'] = (summary['found_vulns'] / total_vulns * 100) if total_vulns else 0

    results = {
        "total_vulns": total_vulns,
        "found_vulns": total_found,
        "metrics": metrics_summary
    }

    # Save the results
    output_file = os.path.join(output_dir, "results.json")
    with open(output_file, 'w', encoding='utf-8') as out_f:
        json.dump(results, out_f, indent=2, ensure_ascii=False)

    logging.info(f"Results saved to {output_file}")
    return results
