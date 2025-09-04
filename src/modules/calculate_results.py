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

def _strip_templates(s: str) -> str:
    """
    Entfernt Template-Argumente, z.B.:
      'Visit<arrow::Int8Type>'              -> 'Visit'
      'Foo<Bar<Baz>, Qux>'                  -> 'Foo'
    Arbeitet mit verschachtelten '<...>'.
    """
    out = []
    depth = 0
    for ch in s:
        if ch == '<':
            depth += 1
        elif ch == '>':
            if depth > 0:
                depth -= 1
        else:
            if depth == 0:
                out.append(ch)
    return ''.join(out)

def _base_func_name(sig: str) -> str:
    """
    Liefert den nackten Funktionsnamen ohne Namespace, Parameter, Qualifier und Template-Argumente.
    Beispiele:
      "pcpp::DnsLayer::parseResources()" -> "parseResources"
      "arrow::Status arrow::VisitArrayInline<...>(...)" -> "VisitArrayInline"
      "Visit<arrow::Int8Type>" -> "Visit"
      "PutOffsets<int>" -> "PutOffsets"
      "Bar::~Bar()" -> "~Bar"
      "operator new[](unsigned long)" -> "operator new[]"
      "operator<<(std::ostream&, int)" -> "operator<<"
      "operator()" -> "operator()"
    """
    if not sig:
        return ""

    s = sig.strip()

    # ---- Spezialfall: Operatoren (erhalten Symbole wie <<, [], (), new[])
    op_idx = s.find('operator')
    if op_idx != -1:
        # ab 'operator' bis vor die Parameterklammer
        op = s[op_idx:].split('(', 1)[0].strip()
        # Namespaces vor operator entfernen (z.B. "A::B::operator<<")
        if '::' in op:
            op = op.rsplit('::', 1)[-1]
        # Falls es explizit 'operator' ohne Symbol ist, trotzdem so zurückgeben
        return op if op else 'operator'

    # ---- Normale Funktionen
    # Parameter/Trailing-Qualifier weg
    idx = s.rfind('(')
    if idx != -1:
        s = s[:idx].strip()

    # Template-Argumente robust entfernen (nach Operator-Check!)
    s = _strip_templates(s)

    # Whitespace normalisieren
    s = ' '.join(s.split())

    # letzten Namespace-Teil nehmen
    if '::' in s:
        s = s.rsplit('::', 1)[-1].strip()

    # führende Spezifizierer (static, inline, virtual, Rückgabetyp etc.) entfernen
    parts = s.split(' ')
    name = parts[-1] if parts else s

    return name

def _normalize_loc_path(p: str) -> str:
    """
    Entfernt alles bis einschließlich der letzten '..'-Sequenz und normalisiert Slashes.
    Beispiele:
      '/a/b/../../src/x.h' -> 'src/x.h'
      'a/../b/../c/d.h'    -> 'c/d.h'
      'src/x.h'            -> 'src/x.h'
    """
    if not p:
        return ""
    # Einheitliche Slashes
    p = p.replace('\\', '/')
    # Komponenten ohne leere/`.`-Segmente
    parts = [seg for seg in p.split('/') if seg not in ("", ".")]
    # Index der letzten '..'
    last_dd = -1
    for i, seg in enumerate(parts):
        if seg == "..":
            last_dd = i
    # Alles bis zur letzten '..' wegschneiden
    if last_dd != -1:
        parts = parts[last_dd + 1:]
    # Wieder zusammenbauen
    return "/".join(parts)

def check_if_function_in_vulns():
    """
    Identify functions from single-metrics that match known vulnerabilities and write results.
    Pfadvergleich nutzt eine normalisierte Vulnerability-Datei (.. und davor abgeschnitten),
    Funktionsvergleich nutzt nur den nackten Funktionsnamen (ohne Namespace).
    """
    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "single-metrics")
    vulns_dir = os.path.join(base, "data", "arvo-projects")
    output_dir = os.path.join(base, "data", "found-methods")
    general_dir = os.path.join(base, "data", "general")

    # ensure base output dirs exist
    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(general_dir, exist_ok=True)

    # ensure each metric folder exists in output and not-found
    metric_names = [m for m in os.listdir(metrics_dir) if os.path.isdir(os.path.join(metrics_dir, m))]
    for metric_name in metric_names:
        os.makedirs(os.path.join(output_dir, metric_name), exist_ok=True)

    not_found_dir = os.path.join(base, "data", "not-found-methods")
    for metric_name in metric_names:
        os.makedirs(os.path.join(not_found_dir, metric_name), exist_ok=True)

    # per-metric counters and seen-sets
    metric_counters = {m: {"total_vulns": 0, "found_vulns": 0} for m in metric_names}
    metric_seen_total = {m: set() for m in metric_names}
    metric_seen_found = {m: set() for m in metric_names}

    # iterate vulnerability files
    for vuln_file in os.listdir(vulns_dir):
        if not vuln_file.endswith('.json'):
            continue
        project = os.path.splitext(vuln_file)[0]
        vuln_path = os.path.join(vulns_dir, vuln_file)
        try:
            with open(vuln_path, 'r', encoding='utf-8') as vf:
                vuln_list = json.load(vf)
        except Exception as e:
            logging.info(f"Fehler beim Lesen von {vuln_path}: {e}")
            continue

        for vuln in vuln_list:
            local_id = vuln.get('localID')
            loc = vuln.get('location', {})
            loc_file_raw = loc.get('file')
            loc_func_raw = loc.get('function', '')

            if not local_id or not loc_file_raw or not loc_func_raw:
                continue

            # Vulnerability-Dateipfad normalisieren: alles bis inkl. letzter '..' abschneiden
            loc_file = _normalize_loc_path(loc_file_raw)
            if not loc_file:
                continue

            # Nur nackter Funktionsname
            func_name = _base_func_name(loc_func_raw)

            for metric_name in metric_names:
                sm_file = os.path.join(metrics_dir, metric_name, f"{project}_{local_id}.json")
                if not os.path.exists(sm_file):
                    continue

                sm_key = f"{project}_{local_id}"
                if sm_key not in metric_seen_total[metric_name]:
                    metric_counters[metric_name]["total_vulns"] += 1
                    metric_seen_total[metric_name].add(sm_key)

                try:
                    with open(sm_file, 'r', encoding='utf-8') as sf:
                        sm_data = json.load(sf)
                except Exception as e:
                    logging.info(f"Fehler beim Lesen von {sm_file}: {e}")
                    continue

                match_found = False

                for code_path, funcs in sm_data.items():
                    # code_path vereinheitlichen (nur Slashes)
                    code_path_norm = code_path.replace('\\', '/')
                    # Vergleich über das Ende: code_path muss auf den bereinigten loc_file enden
                    if not code_path_norm.endswith(loc_file):
                        continue

                    for sig in funcs.keys():
                        sig_base = _base_func_name(sig)
                        if sig_base == func_name:
                            match_found = True
                            out_path = os.path.join(output_dir, metric_name, f"{project}_{local_id}.json")
                            try:
                                with open(out_path, 'r', encoding='utf-8') as of:
                                    out_data = json.load(of)
                            except Exception:
                                out_data = {}

                            # In der Ausgabe: Key = originaler code_path, Funktionskey = nackter Name
                            out_data.setdefault(code_path, {}).setdefault(sig_base, []).append({'id': local_id})

                            try:
                                with open(out_path, 'w', encoding='utf-8') as of:
                                    json.dump(out_data, of, indent=2, ensure_ascii=False)
                            except Exception as e:
                                logging.info(f"Fehler beim Schreiben von {out_path}: {e}")

                            if sm_key not in metric_seen_found[metric_name]:
                                metric_counters[metric_name]["found_vulns"] += 1
                                metric_seen_found[metric_name].add(sm_key)

                if not match_found:
                    nf_path = os.path.join(not_found_dir, metric_name, f"{project}_{local_id}.json")
                    try:
                        with open(nf_path, 'r', encoding='utf-8') as nf:
                            nf_data = json.load(nf)
                    except Exception:
                        nf_data = {}
                    # not-found mit bereinigtem Pfad
                    nf_data.setdefault(loc_file, []).append(func_name)
                    try:
                        with open(nf_path, 'w', encoding='utf-8') as nf:
                            json.dump(nf_data, nf, indent=2, ensure_ascii=False)
                    except Exception as e:
                        logging.info(f"Fehler beim Schreiben von {nf_path}: {e}")

    # write general/result.json
    result_path = os.path.join(general_dir, "result.json")
    try:
        try:
            with open(result_path, 'r', encoding='utf-8') as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}

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