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
    
    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "single-metrics")
    vulns_dir = os.path.join(base, "data", "arvo-projects")
    output_dir = os.path.join(base, "data", "found-methods")
    general_dir = os.path.join(base, "data", "general")
    # ensure each metric folder exists in output
    metric_names = [m for m in os.listdir(metrics_dir) if os.path.isdir(os.path.join(metrics_dir, m))]
    for metric_name in metric_names:
        metric_out = os.path.join(output_dir, metric_name)
        os.makedirs(metric_out, exist_ok=True)
    # ensure each metric folder exists in not-found-methods
    not_found_dir = os.path.join(base, "data", "not-found-methods")
    for metric_name in metric_names:
        metric_nf_out = os.path.join(not_found_dir, metric_name)
        os.makedirs(metric_nf_out, exist_ok=True)

    # prepare per-metric counters and seen-sets to avoid double counting per project_localid
    metric_counters = {m: {"total_vulns": 0, "found_vulns": 0} for m in metric_names}
    metric_seen_total = {m: set() for m in metric_names}   # keys: project_localid
    metric_seen_found = {m: set() for m in metric_names}   # keys: project_localid

    # iterate each project vulnerability file
    for vuln_file in os.listdir(vulns_dir):
        if not vuln_file.endswith('.json'):
            continue
        project = os.path.splitext(vuln_file)[0]
        vuln_path = os.path.join(vulns_dir, vuln_file)
        try:
            with open(vuln_path, 'r', encoding='utf-8') as vf:
                vuln_list = json.load(vf)
        except Exception:
            continue
        # for each vulnerability entry
        for vuln in vuln_list:
            local_id = vuln.get('localID')
            loc = vuln.get('location', {})
            loc_file = loc.get('file')
            loc_func = loc.get('function', '')
            if not local_id or not loc_file or not loc_func:
                continue
            # normalize function name without parameters
            func_name = loc_func.split('(')[0]
            # check each metric folder for matching single-metric data
            for metric_name in os.listdir(metrics_dir):
                sm_file = os.path.join(metrics_dir, metric_name, f"{project}_{local_id}.json")
                if not os.path.exists(sm_file):
                    continue
                # count this sm_file as a candidate (total_vulns) only once per metric
                sm_key = f"{project}_{local_id}"
                if sm_key not in metric_seen_total.get(metric_name, set()):
                    metric_counters[metric_name]["total_vulns"] += 1
                    metric_seen_total[metric_name].add(sm_key)
                try:
                    with open(sm_file, 'r', encoding='utf-8') as sf:
                        sm_data = json.load(sf)
                except Exception:
                    continue

                # track if this vulnerability function signature was found for this metric
                match_found = False

                # find matching file path in single-metric data
                for code_path, funcs in sm_data.items():
                    if code_path.endswith(loc_file):
                        # find matching function signature
                        for sig, values in funcs.items():
                            if sig.split('(')[0] == func_name:
                                match_found = True
                                # prepare output file for this metric and vuln
                                out_path = os.path.join(output_dir, metric_name, f"{project}_{local_id}.json")
                                # load existing or new container
                                try:
                                    with open(out_path, 'r', encoding='utf-8') as of:
                                        out_data = json.load(of)
                                except Exception:
                                    out_data = {}
                                # append this vulnerability under code_path and signature
                                out_data.setdefault(code_path, {}).setdefault(sig, []).append({'id': local_id})
                                # write back
                                with open(out_path, 'w', encoding='utf-8') as of:
                                    json.dump(out_data, of, indent=2, ensure_ascii=False)
                                # count as found_vulns only once per sm_file
                                if sm_key not in metric_seen_found.get(metric_name, set()):
                                    metric_counters[metric_name]["found_vulns"] += 1
                                    metric_seen_found[metric_name].add(sm_key)
                # if no matching signature found, record in not-found-methods
                if not match_found:
                    nf_path = os.path.join(not_found_dir, metric_name, f"{project}_{local_id}.json")
                    try:
                        with open(nf_path, 'r', encoding='utf-8') as nf:
                            nf_data = json.load(nf)
                    except Exception:
                        nf_data = {}
                    # record missing function name under file
                    nf_data.setdefault(loc_file, []).append(func_name)
                    with open(nf_path, 'w', encoding='utf-8') as nf:
                        json.dump(nf_data, nf, indent=2, ensure_ascii=False)

    # At end of processing, write per-metric results into general/result.json
    result_path = os.path.join(general_dir, "result.json")
    try:
        # load existing to preserve other keys if necessary, otherwise start fresh
        try:
            with open(result_path, 'r', encoding='utf-8') as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}

        # insert/overwrite per-metric entries
        for metric, counters in metric_counters.items():
            result_data[metric] = {
                "total_vulns": counters["total_vulns"],
                "found_vulns": counters["found_vulns"]
            }

        with open(result_path, 'w', encoding='utf-8') as wf:
            json.dump(result_data, wf, indent=2, ensure_ascii=False)
        logging.info(f"Metric results written to {result_path}")
    except Exception as e:
        logging.info(f"Fehler beim Schreiben der Ergebnisdatei {result_path}: {e}")