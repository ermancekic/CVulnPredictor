"""
calculate_results.py

This module provides functions to separate and filter calculated metrics by thresholds,
identify vulnerable methods based on single-metrics and known vulnerabilities,
and compute summary statistics for vulnerabilities discovered by metrics.
"""

import glob
try:
    import ujson as json
except Exception:  # Fallback, if ujson is not available
    import json  # type: ignore[no-redef]
import os
import logging
import shutil
from pathlib import Path
from collections import defaultdict
from statistics import median
from concurrent.futures import ProcessPoolExecutor, as_completed
import multiprocessing as mp

def _separate_worker(args):
    """Worker to process a single metrics JSON file and write filtered single-metrics.

    Args:
        args: tuple(input_path, thresholds, single_metrics_dir)

    Returns:
        tuple(file_name, ok)
    """
    input_path, thresholds, single_metrics_dir = args
    entry = os.path.basename(input_path)
    try:
        with open(input_path, 'r', encoding='utf-8') as f:
            metrics_data = json.load(f)
    except Exception as e:
        logging.info(f"Fehler beim Lesen von {input_path}: {e}")
        return (entry, False)

    # Collection structure: metric_name -> file_name -> function_name -> {metric_name: value}
    filtered = defaultdict(lambda: defaultdict(dict))

    for file_name, functions in (metrics_data.items() if isinstance(metrics_data, dict) else []):
        # Optionally present: project-level metrics for the whole file
        project_metrics = {}
        try:
            if isinstance(functions, dict):
                project_metrics = functions.get("__project_metrics__", {}) or {}
        except Exception:
            project_metrics = {}

        if not isinstance(functions, dict):
            continue

        for func_name, metrics in functions.items():
            # Skip the container of project-level metrics itself
            if func_name == "__project_metrics__":
                continue

            # Merge: apply project metrics to every function entry
            merged = {}
            if isinstance(project_metrics, dict):
                merged.update(project_metrics)
            if isinstance(metrics, dict):
                merged.update(metrics)

            # func_name remains fully intact
            for metric_name, metric_value in merged.items():
                try:
                    if metric_name in thresholds and metric_value >= thresholds[metric_name]:
                        filtered[metric_name][file_name].setdefault(func_name, {})[metric_name] = metric_value
                except Exception:
                    # Be defensive about unexpected types
                    continue

    # Now write exactly one file per metric folder and threshold subfolder
    for metric_name, file_dict in filtered.items():
        thr_val = thresholds.get(metric_name)
        thr_key = str(thr_val) if thr_val is not None else "0"
        out_dir = os.path.join(single_metrics_dir, metric_name, thr_key)
        try:
            os.makedirs(out_dir, exist_ok=True)
        except Exception:
            pass
        out_path = os.path.join(out_dir, entry)
        try:
            with open(out_path, 'w', encoding='utf-8') as f_out:
                json.dump(file_dict, f_out, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.info(f"Fehler beim Schreiben von {out_path}: {e}")

    return (entry, True)


def separate_and_filter_calculated_metrics(thresholds):
    """
    Separate and filter calculated metrics into individual JSON files per metric.
    Additionally, write the used threshold per metric to data/general/result.json
    under the key "threshold".

    Args:
        thresholds (dict): Mapping of metric names to minimum threshold values.

    Returns:
        None
    """

    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "metrics")
    single_metrics_dir = os.path.join(base, "data", "single-metrics")
    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    # Ensure base output directory exists, but do not delete previous thresholds
    os.makedirs(single_metrics_dir, exist_ok=True)
    # Pre-create metric/threshold subdirectories so readers can discover them if needed
    for metric_name, thr_val in thresholds.items():
        thr_key = str(thr_val) if thr_val is not None else "0"
        os.makedirs(os.path.join(single_metrics_dir, metric_name, thr_key), exist_ok=True)

    # Prepare inputs
    entries = list(os.listdir(metrics_dir)) if os.path.isdir(metrics_dir) else []
    inputs = [os.path.join(metrics_dir, e) for e in entries]

    # Run workers in parallel per input file
    if inputs:
        env_workers = os.getenv("SEPARATE_WORKERS")
        if env_workers and str(env_workers).isdigit():
            max_workers = max(1, int(env_workers))
        else:
            max_workers = min(len(inputs), max(1, mp.cpu_count()))

        tasks = [(p, thresholds, single_metrics_dir) for p in inputs]
        completed = 0
        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            futs = [pool.submit(_separate_worker, t) for t in tasks]
            for fut in as_completed(futs):
                try:
                    _entry, ok = fut.result()
                    completed += int(ok)
                except Exception as e:
                    logging.info(f"Worker failed: {e}")
        logging.info(f"Separated and filtered {completed}/{len(inputs)} metrics files in parallel")
    else:
        logging.info(f"No metrics files found in {metrics_dir}")

    # Update data/general/result.json with the thresholds used per metric
    result_path = os.path.join(general_dir, "result.json")
    try:
        try:
            with open(result_path, 'r', encoding='utf-8') as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}

        if not isinstance(result_data, dict):
            result_data = {}

        for metric_name, value in thresholds.items():
            entry = result_data.get(metric_name)
            if not isinstance(entry, dict):
                entry = {}
            # store the exact numeric threshold used for filtering
            entry["threshold"] = value
            result_data[metric_name] = entry

        with open(result_path, 'w', encoding='utf-8') as wf:
            json.dump(result_data, wf, indent=2, ensure_ascii=False)
        logging.info(f"Thresholds saved to {result_path}")
    except Exception as e:
        logging.info(f"Error writing thresholds to result file {result_path}: {e}")

def _strip_templates(s: str) -> str:
    """
    Removes template arguments, e.g.:
      'Visit<arrow::Int8Type>'              -> 'Visit'
      'Foo<Bar<Baz>, Qux>'                  -> 'Foo'
    Works with nested '<...>'.
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
    Returns the bare function name without namespace, parameters, qualifiers, and template arguments.
    Examples:
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

    # ---- Special case: Operators (preserve symbols like <<, [], (), new[])
    op_idx = s.find('operator')
    if op_idx != -1:
        # from 'operator' up to before the parameter parenthesis
        op = s[op_idx:].split('(', 1)[0].strip()
        # Remove namespaces before operator (e.g. "A::B::operator<<")
        if '::' in op:
            op = op.rsplit('::', 1)[-1]
        # If it's explicitly 'operator' without symbol, still return it as is
        return op if op else 'operator'

    # ---- Normal functions
    # Remove parameters/trailing qualifiers
    idx = s.rfind('(')
    if idx != -1:
        s = s[:idx].strip()

    # Robustly remove template arguments (after operator check!)
    s = _strip_templates(s)

    # Normalize whitespace
    s = ' '.join(s.split())

    # Take the last namespace part
    if '::' in s:
        s = s.rsplit('::', 1)[-1].strip()

    # Remove leading specifiers (static, inline, virtual, return type etc.)
    parts = s.split(' ')
    name = parts[-1] if parts else s

    return name

def _find_param_span(sig: str) -> tuple[int, int] | tuple[None, None]:
    """
    Returns the (start, end) indices of the top-level parameter list in sig,
    i.e., the parentheses of the function call signature. If none found, (None, None).
    This walks backward from the last ')' to find the matching '('.
    """
    if not sig:
        return (None, None)
    s = sig.strip()
    rp = s.rfind(')')
    if rp == -1:
        return (None, None)
    depth = 0
    for i in range(rp, -1, -1):
        ch = s[i]
        if ch == ')':
            depth += 1
        elif ch == '(':
            depth -= 1
            if depth == 0:
                return (i, rp)
    return (None, None)

def _split_top_level_commas(s: str) -> list[str]:
    """
    Split a string by commas, ignoring commas that are nested inside angle brackets or
    parentheses. Used to split parameter lists without breaking template args.
    """
    parts = []
    buf = []
    depth_angle = 0
    depth_paren = 0
    for ch in s:
        if ch == '<':
            depth_angle += 1
        elif ch == '>':
            if depth_angle > 0:
                depth_angle -= 1
        elif ch == '(':
            depth_paren += 1
        elif ch == ')':
            if depth_paren > 0:
                depth_paren -= 1
        if ch == ',' and depth_angle == 0 and depth_paren == 0:
            parts.append(''.join(buf).strip())
            buf = []
        else:
            buf.append(ch)
    if buf:
        parts.append(''.join(buf).strip())
    return parts

def _extract_param_list(sig: str) -> list[str] | None:
    """
    Extracts a raw list of parameter strings from a function signature string.
    Returns None if no parameter list is present (e.g., missing parentheses entirely).
    Returns [] for an empty list '()'.
    """
    lp, rp = _find_param_span(sig)
    if lp is None or rp is None or rp <= lp:
        return None
    inner = sig[lp + 1:rp].strip()
    if inner == "":
        return []
    # Skip purely variadic-only notation
    if inner == '...':
        return []
    return _split_top_level_commas(inner)

def _normalize_type_name(t: str) -> str:
    """
    Best-effort normalization of a parameter type string:
    - drop default values (after '=') and most qualifiers (const/volatile/restrict/struct/class/enum/typename)
    - remove a likely parameter name at the end (heuristic)
    - normalize whitespace around '*' and '&'
    This is heuristic by design; we primarily rely on parameter COUNT for matching.
    """
    import re as _re
    s = (t or '').strip()
    if not s:
        return ''
    # Cut default value
    s = s.split('=', 1)[0].strip()
    # Remove common qualifiers/keywords
    remove_words = {
        'const', 'volatile', 'restrict', 'struct', 'class', 'enum', 'register', 'mutable', 'typename'
    }
    tokens = [tok for tok in _re.split(r'\s+', s) if tok and tok not in remove_words]
    s = ' '.join(tokens)
    # Heuristic: drop trailing parameter name token (no *,&,::,[],<,>)
    toks = s.split()
    if len(toks) >= 2:
        last = toks[-1]
        if _re.match(r'^[A-Za-z_][A-Za-z0-9_]*$', last) and all(c not in last for c in ('*', '&', ':', '[', ']', '<', '>')):
            toks = toks[:-1]
    s = ' '.join(toks)
    # Normalize pointer/ref attachment
    s = _re.sub(r'\s*\*\s*', '*', s)
    s = _re.sub(r'\s*&\s*', '&', s)
    s = _re.sub(r'\s+', ' ', s).strip()
    return s

def _param_info(sig: str) -> tuple[int | None, list[str] | None]:
    """
    Returns (count, normalized_types or None) for a signature string.
    If parameters cannot be determined, returns (None, None).
    """
    raw = _extract_param_list(sig)
    if raw is None:
        return (None, None)
    if not raw:
        return (0, [])
    # Normalize each param; ignore empty strings (defensive)
    norm = [_normalize_type_name(p) for p in raw]
    norm = [p for p in norm if p != '']
    return (len(raw), norm if norm else [])

def _normalize_loc_path(p: str) -> str:
    """
    Removes everything up to and including the last '..' sequence and normalizes slashes.
    Examples:
      '/a/b/../../src/x.h' -> 'src/x.h'
      'a/../b/../c/d.h'    -> 'c/d.h'
      'src/x.h'            -> 'src/x.h'
    """
    if not p:
        return ""
    # Uniform slashes
    p = p.replace('\\', '/')
    # Components without empty/'.' segments
    parts = [seg for seg in p.split('/') if seg not in ("", ".")]
    # Index of the last '..'
    last_dd = -1
    for i, seg in enumerate(parts):
        if seg == "..":
            last_dd = i
    # Cut off everything up to the last '..'
    if last_dd != -1:
        parts = parts[last_dd + 1:]
    # Reassemble
    return "/".join(parts)

def _cifiv_process_vuln_file(args):
    """
    Process exactly one file from data/arvo-projects and write the corresponding
    found/not-found files. Returns sets that allow the main process to compute
    stable counters without double-counting.

    Args:
        args: (vuln_path, metric_names, metrics_dir, output_dir, not_found_dir, skip_writes, thresholds_by_metric)

    Returns:
        dict[str, dict[str, list[str]]]:
            {
              "seen_total": {metric: [sm_key, ...]},
              "seen_found": {metric: [sm_key, ...]}
            }
    """
    (vuln_path, metric_names, metrics_dir, output_dir, not_found_dir, skip_writes, thresholds_by_metric) = args

    seen_total = {m: set() for m in metric_names}
    seen_found = {m: set() for m in metric_names}

    # Derive project name from file name
    project = os.path.splitext(os.path.basename(vuln_path))[0]

    # Build per-metric filename sets once per worker for fast existence checks
    metric_files: dict[str, set[str]] = {}
    for m in metric_names:
        # Prefer current threshold subfolder for the metric
        thr_key = str(thresholds_by_metric.get(m)) if thresholds_by_metric else None
        base_metric_dir = os.path.join(metrics_dir, m)
        mdir = os.path.join(base_metric_dir, thr_key) if thr_key else base_metric_dir
        files: set[str] = set()
        try:
            if thr_key and os.path.isdir(mdir):
                files = set(e for e in os.listdir(mdir) if e.endswith('.json'))
            else:
                # Fallback: collect JSON files from any threshold subdirectories
                for d in os.listdir(base_metric_dir):
                    sub = os.path.join(base_metric_dir, d)
                    if os.path.isdir(sub):
                        for e in os.listdir(sub):
                            if e.endswith('.json'):
                                files.add(e)
        except Exception:
            files = set()
        metric_files[m] = files

    try:
        with open(vuln_path, "r", encoding="utf-8") as vf:
            vuln_list = json.load(vf)
    except Exception as e:
        logging.info(f"Error reading {vuln_path}: {e}")
        return {"seen_total": {m: [] for m in metric_names}, "seen_found": {m: [] for m in metric_names}}

    for vuln in vuln_list if isinstance(vuln_list, list) else []:
        local_id = (vuln.get("localID") if isinstance(vuln, dict) else None)
        loc = vuln.get("location", {}) if isinstance(vuln, dict) else {}
        loc_file_raw = loc.get("file")
        loc_func_raw = loc.get("function", "") or ""

        if not local_id or not loc_file_raw or not loc_func_raw:
            continue

        loc_file = _normalize_loc_path(loc_file_raw)
        if not loc_file:
            continue

        func_name = _base_func_name(loc_func_raw)
        vuln_param_count, vuln_param_types = _param_info(loc_func_raw)

        # Counter key as in the original implementation
        sm_key = f"{project}_{local_id}"
        target_file_name = f"{sm_key}.json"

        for metric_name in metric_names:
            # Count "total" only if the single-metrics file exists (matching original logic)
            if target_file_name not in metric_files.get(metric_name, set()):
                continue
            if sm_key not in seen_total[metric_name]:
                seen_total[metric_name].add(sm_key)

            # Read from the selected threshold subfolder when available
            thr_key = str(thresholds_by_metric.get(metric_name)) if thresholds_by_metric else None
            if thr_key:
                sm_file = os.path.join(metrics_dir, metric_name, thr_key, target_file_name)
            else:
                # Fallback to legacy one-level structure
                sm_file = os.path.join(metrics_dir, metric_name, target_file_name)
            try:
                with open(sm_file, "r", encoding="utf-8") as sf:
                    sm_data = json.load(sf)
            except Exception as e:
                logging.info(f"Error reading {sm_file}: {e}")
                continue

            match_found = False

            if isinstance(sm_data, dict):
                for code_path, funcs in sm_data.items():
                    code_path_norm = (code_path or "").replace("\\", "/")
                    # Compare by suffix: single-metrics path must end with the normalized vuln file path
                    if not code_path_norm.endswith(loc_file):
                        continue
                    if not isinstance(funcs, dict):
                        continue

                    for sig in funcs.keys():
                        sig_base = _base_func_name(sig)
                        if sig_base != func_name:
                            continue

                        # Parameter-aware match: require only the same arity if vuln signature exposes params
                        sig_param_count, sig_param_types = _param_info(sig)
                        if vuln_param_count is not None:
                            if sig_param_count is not None and sig_param_count != vuln_param_count:
                                continue
                            # Type-equality intentionally NOT enforced (kept aligned with original behavior)

                        # We have a match
                        match_found = True
                        # Skip file writes when requested
                        if not skip_writes:
                            out_path = os.path.join(output_dir, metric_name, target_file_name)
                            try:
                                with open(out_path, "r", encoding="utf-8") as of:
                                    out_data = json.load(of)
                            except Exception:
                                out_data = {}

                            log_param_count = (
                                vuln_param_count if vuln_param_count is not None else sig_param_count
                            )
                            log_param_types = (
                                vuln_param_types
                                if (vuln_param_types not in (None, []))
                                else (sig_param_types or [])
                            )

                            found_entry = {
                                "id": local_id,
                                "function": func_name,
                                "signature": loc_func_raw,
                                "param_count": log_param_count,
                                "param_types": log_param_types,
                                "metrics_signature": sig,
                                "metrics_param_count": sig_param_count,
                                "metrics_param_types": sig_param_types if sig_param_types is not None else [],
                            }
                            out_data.setdefault(code_path, {}).setdefault(sig_base, []).append(found_entry)

                            try:
                                with open(out_path, "w", encoding="utf-8") as of:
                                    json.dump(out_data, of, indent=2, ensure_ascii=False)
                            except Exception as e:
                                logging.info(f"Error writing {out_path}: {e}")

                        # Update per-metric found set
                        seen_found[metric_name].add(sm_key)

            # If no match for this metric: write not-found entry
            if not match_found and not skip_writes:
                nf_path = os.path.join(not_found_dir, metric_name, target_file_name)
                try:
                    with open(nf_path, "r", encoding="utf-8") as nf:
                        nf_data = json.load(nf)
                except Exception:
                    nf_data = {}

                entry = {
                    "function": func_name,
                    "signature": loc_func_raw,
                    "param_count": vuln_param_count,
                    "param_types": vuln_param_types if vuln_param_types is not None else [],
                }
                nf_data.setdefault(loc_file, []).append(entry)

                try:
                    with open(nf_path, "w", encoding="utf-8") as nf:
                        json.dump(nf_data, nf, indent=2, ensure_ascii=False)
                except Exception as e:
                    logging.info(f"Error writing {nf_path}: {e}")

    return {
        "seen_total": {m: list(seen_total[m]) for m in metric_names},
        "seen_found": {m: list(seen_found[m]) for m in metric_names},
    }

def check_if_function_in_vulns(skip_set_total: bool = False):
    """
    Parallelized variant: distributes processing per file in data/arvo-projects
    across multiple processes. Aggregates counters at the end and writes them to
    data/general/result.json (same semantics as the original).

    Parallelism control:
      - Environment variable CIFIV_WORKERS (int >= 1)
      - Fallback: min(number of files, CPU cores)
    """
    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "single-metrics")
    vulns_dir = os.path.join(base, "data", "arvo-projects")
    output_dir = os.path.join(base, "data", "found-methods")
    general_dir = os.path.join(base, "data", "general")
    not_found_dir = os.path.join(base, "data", "not-found-methods")

    os.makedirs(output_dir, exist_ok=True)
    os.makedirs(general_dir, exist_ok=True)
    os.makedirs(not_found_dir, exist_ok=True)

    def _dir_has_any_file(path: str) -> bool:
        try:
            for root, _dirs, files in os.walk(path):
                if files:
                    return True
        except Exception:
            return False
        return False

    # If target folders already contain files, skip writing into them
    skip_writes = _dir_has_any_file(output_dir) or _dir_has_any_file(not_found_dir)
    if skip_writes:
        logging.info(
            "found-methods/ or not-found-methods/ already contain files; will not write to them in this run"
        )

    # Enumerate metrics and ensure target directories exist
    metric_names = [m for m in os.listdir(metrics_dir) if os.path.isdir(os.path.join(metrics_dir, m))] \
                   if os.path.isdir(metrics_dir) else []

    # Load current thresholds per metric from result.json to select the threshold subfolders
    thresholds_by_metric: dict[str, str] = {}
    try:
        with open(os.path.join(general_dir, "result.json"), "r", encoding="utf-8") as rf:
            current_results = json.load(rf)
        if isinstance(current_results, dict):
            for m in metric_names:
                entry = current_results.get(m)
                if isinstance(entry, dict) and "threshold" in entry:
                    try:
                        thresholds_by_metric[m] = str(entry.get("threshold"))
                    except Exception:
                        continue
    except Exception:
        thresholds_by_metric = {}
    for metric_name in metric_names:
        # Ensure subdirectories exist; harmless if we skip writes
        os.makedirs(os.path.join(output_dir, metric_name), exist_ok=True)
        os.makedirs(os.path.join(not_found_dir, metric_name), exist_ok=True)

    # Collect vulnerability files
    vuln_files = [os.path.join(vulns_dir, f) for f in os.listdir(vulns_dir)
                  if f.endswith(".json")] if os.path.isdir(vulns_dir) else []

    if not vuln_files:
        logging.info(f"No vulnerability files found in {vulns_dir}")
        # Nothing else to update (found_vulns stays as-is)
        return

    # Determine pool size
    env_workers = os.getenv("CIFIV_WORKERS")
    if env_workers and str(env_workers).isdigit():
        max_workers = max(1, int(env_workers))
    else:
        import multiprocessing as _mp
        max_workers = max(1, min(len(vuln_files), _mp.cpu_count() or 1))

    # Prepare tasks
    tasks = [
        (vp, metric_names, metrics_dir, output_dir, not_found_dir, skip_writes, thresholds_by_metric)
        for vp in vuln_files
    ]

    # Global sets for stable aggregation
    global_seen_total = {m: set() for m in metric_names}
    global_seen_found = {m: set() for m in metric_names}

    from concurrent.futures import ProcessPoolExecutor, as_completed
    completed = 0
    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_cifiv_process_vuln_file, t) for t in tasks]
        for fut in as_completed(futs):
            try:
                res = fut.result()
                st = res.get("seen_total", {}) if isinstance(res, dict) else {}
                sf = res.get("seen_found", {}) if isinstance(res, dict) else {}
                for m in metric_names:
                    global_seen_total[m].update(st.get(m, []))
                    global_seen_found[m].update(sf.get(m, []))
                completed += 1
            except Exception as e:
                logging.info(f"Worker failed: {e}")

    logging.info(f"Processed {completed}/{len(vuln_files)} vulnerability files in parallel")

    # Update result.json once, after aggregation
    result_path = os.path.join(general_dir, "result.json")
    try:
        try:
            with open(result_path, "r", encoding="utf-8") as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}

        if not isinstance(result_data, dict):
            result_data = {}

        for metric in metric_names:
            current = result_data.get(metric)
            if not isinstance(current, dict):
                current = {}

            # Always set found_vulns
            current["found_vulns"] = int(len(global_seen_found[metric]))
            # Optionally set total_vulns (unless suppressed)
            if not skip_set_total:
                current["total_vulns"] = int(len(global_seen_total[metric]))

            result_data[metric] = current

        with open(result_path, "w", encoding="utf-8") as wf:
            json.dump(result_data, wf, indent=2, ensure_ascii=False)
        logging.info(f"Metric results written to {result_path}")
    except Exception as e:
        logging.info(f"Error writing result file {result_path}: {e}")



def calculate_time_stats() -> dict:
    """
    Scan all JSON files under data/times where each file contains a list of
    timing values (seconds) for one metric and compute per metric:
      - average
      - median
      - total (sum of all recorded seconds)
      - top10 (list of the 10 longest durations, desc)
    Writes a single consolidated JSON to data/general/times_summary.json.

    Returns:
        dict: Mapping of metric (filename stem) -> {"average": float, "median": float, "total": float, "top10": list[float]}
    """
    base = os.getcwd()
    times_dir = os.path.join(base, "data", "times")
    out_dir = os.path.join(base, "data", "general")
    os.makedirs(out_dir, exist_ok=True)

    summary: dict[str, dict] = {}

    if not os.path.isdir(times_dir):
        # Nothing to do
        out_path = os.path.join(out_dir, "times_summary.json")
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(summary, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.info(f"Error writing empty summary file {out_path}: {e}")
        return summary

    for path in glob.glob(os.path.join(times_dir, "*.json")):
        name = os.path.splitext(os.path.basename(path))[0]
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
        except Exception as e:
            logging.info(f"Failed to read {path}: {e}")
            continue

        # Expect a list of numeric values; coerce to float and filter invalids
        values: list[float] = []
        if isinstance(data, list):
            for v in data:
                try:
                    values.append(float(v))
                except Exception:
                    continue

        if not values:
            # Skip empty or non-numeric files
            continue

        import heapq
        total = float(sum(values))
        avg = total / len(values)
        med = median(values)
        top10 = heapq.nlargest(10, values)
        summary[name] = {
            "average": float(avg),
            "median": float(med),
            "total": total,
            "top10": [float(x) for x in top10],
        }

    out_path = os.path.join(out_dir, "times_summary.json")
    try:
        with open(out_path, 'w', encoding='utf-8') as f:
            json.dump(summary, f, indent=2, ensure_ascii=False)
        logging.info(f"Time summary written to {out_path}")
    except Exception as e:
        logging.info(f"Error writing time summary {out_path}: {e}")

    return summary

def _methods_file_worker(path: str) -> int:
    """Count methods (excluding project-level keys) in one metrics JSON file."""
    try:
        with open(path, 'r', encoding='utf-8') as f:
            data = json.load(f)
    except Exception as e:
        logging.info(f"Failed to read {path}: {e}")
        return 0

    if not isinstance(data, dict):
        return 0

    NON_METHOD_KEYS = {"__project_metrics__"}
    cnt = 0
    for _file_path, functions in data.items():
        if isinstance(functions, dict):
            for k in functions.keys():
                if k not in NON_METHOD_KEYS:
                    cnt += 1
    return cnt


def _coverage_metric_worker(args) -> tuple[str, int]:
    """Count total methods for a single metric directory (name, count)."""
    metric_name, metric_path = args
    total = 0
    try:
        for entry in os.listdir(metric_path):
            if not entry.endswith('.json'):
                continue
            path = os.path.join(metric_path, entry)
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except Exception as e:
                logging.info(f"Failed to read {path}: {e}")
                continue
            if not isinstance(data, dict):
                continue
            for _code_path, funcs in data.items():
                if isinstance(funcs, dict):
                    total += len(funcs)
    except Exception as e:
        logging.info(f"Failed to scan {metric_path}: {e}")
    return (metric_name, total)


def calculate_total_number_of_methods():
    """
    Count methods across all JSON files in data/metrics in parallel.

    Parallelism:
      - Environment variable TOTAL_METHODS_WORKERS (int >= 1)
      - Default: min(#files, CPU cores)

    Writes:
      - data/general/methods_total.json
      - Also updates data/general/result.json top-level key "total_methods"
    """
    base = os.getcwd()
    metrics_dir = os.path.join(base, "data", "metrics")
    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    # If directory is missing, keep previous behavior but also update result.json
    if not os.path.isdir(metrics_dir):
        total_methods = 0
        methods_out = os.path.join(general_dir, "methods_total.json")
        try:
            with open(methods_out, 'w', encoding='utf-8') as f:
                json.dump({"total_methods": total_methods}, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.info(f"Error writing {methods_out}: {e}")

        result_path = os.path.join(general_dir, "result.json")
        try:
            try:
                with open(result_path, 'r', encoding='utf-8') as rf:
                    result_data = json.load(rf)
            except Exception:
                result_data = {}
            if not isinstance(result_data, dict):
                result_data = {}
            result_data["total_methods"] = total_methods
            with open(result_path, 'w', encoding='utf-8') as wf:
                json.dump(result_data, wf, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.info(f"Error writing result file {result_path}: {e}")
        return total_methods

    # Collect input files
    files = [os.path.join(metrics_dir, e) for e in os.listdir(metrics_dir) if e.endswith(".json")]
    if not files:
        total_methods = 0
    else:
        env_workers = os.getenv("TOTAL_METHODS_WORKERS")
        if env_workers and str(env_workers).isdigit():
            max_workers = max(1, int(env_workers))
        else:
            max_workers = min(len(files), max(1, mp.cpu_count() or 1))

        total_methods = 0
        with ProcessPoolExecutor(max_workers=max_workers) as pool:
            futs = [pool.submit(_methods_file_worker, p) for p in files]
            for fut in as_completed(futs):
                try:
                    total_methods += int(fut.result() or 0)
                except Exception as e:
                    logging.info(f"Worker failed (methods count): {e}")

    # Write consolidated outputs
    methods_out = os.path.join(general_dir, "methods_total.json")
    try:
        with open(methods_out, 'w', encoding='utf-8') as f:
            json.dump({"total_methods": total_methods}, f, indent=2, ensure_ascii=False)
        logging.info(f"Total methods written to {methods_out}")
    except Exception as e:
        logging.info(f"Error writing {methods_out}: {e}")

    # Update result.json top-level "total_methods" for convenience
    result_path = os.path.join(general_dir, "result.json")
    try:
        try:
            with open(result_path, 'r', encoding='utf-8') as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}
        if not isinstance(result_data, dict):
            result_data = {}
        result_data["total_methods"] = total_methods
        with open(result_path, 'w', encoding='utf-8') as wf:
            json.dump(result_data, wf, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.info(f"Error writing result file {result_path}: {e}")

    return total_methods

def delete_not_found_vulns_from_result():
    """
    Update data/general/result.json so that, for each metric, the
    value of "total_vulns" is replaced by the current "found_vulns".
    Additionally, write the difference (old_total_vulns - found_vulns)
    per metric to data/general/deleted_vulns.json.

    Non-metric or malformed entries in result.json are ignored.
    """
    base = os.getcwd()
    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    result_path = os.path.join(general_dir, "result.json")
    deleted_out_path = os.path.join(general_dir, "deleted_vulns.json")

    # Load current results
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            result_data = json.load(f)
    except Exception as e:
        logging.info(f"Could not read result file {result_path}: {e}")
        return

    if not isinstance(result_data, dict):
        logging.info(f"Unexpected format in {result_path}: expected object at top-level")
        return

    deleted_stats: dict[str, int] = {}

    # Iterate over metrics and adjust totals
    for key, val in list(result_data.items()):
        if not isinstance(val, dict):
            # Skip non-metric entries (e.g., potential aggregate fields)
            continue

        old_total = val.get("total_vulns")
        found = val.get("found_vulns")

        # Only process entries that have both counts
        try:
            old_total_int = int(old_total)
            found_int = int(found)
        except Exception:
            # Skip malformed entries
            continue

        diff = max(0, old_total_int - found_int)
        deleted_stats[key] = diff

        # Replace total with found
        val["total_vulns"] = found_int
        result_data[key] = val

    # Write deleted_vulns.json
    try:
        with open(deleted_out_path, 'w', encoding='utf-8') as f:
            json.dump(deleted_stats, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.info(f"Error writing deleted stats to {deleted_out_path}: {e}")

    # Overwrite result.json with updated totals
    try:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logging.info(f"Error writing updated results to {result_path}: {e}")

    return

def calculate_code_coverage() -> dict:
    """
    Traverse data/single-metrics and count, for each metric, how many methods
    exist across all its JSON files. Counting per metric runs in parallel.

    Parallelism:
      - Environment variable CODE_COVERAGE_WORKERS (int >= 1)
      - Default: min(#metric_dirs, CPU cores)

    Writes per metric into data/general/result.json:
      - "total_methods"
      - "coverage" (total_methods / global methods_total)
    """
    base = os.getcwd()

    # Prefer plural directory; fallback to singular if needed
    single_metrics_dir = os.path.join(base, "data", "single-metrics")
    if not os.path.isdir(single_metrics_dir):
        alt = os.path.join(base, "data", "single-metric")
        if os.path.isdir(alt):
            single_metrics_dir = alt

    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    counts: dict[str, int] = {}

    if not os.path.isdir(single_metrics_dir):
        logging.info(f"Single-metrics directory not found: {single_metrics_dir}")
    else:
        # Prepare (metric_name, threshold_path) tasks, selecting current threshold per metric
        metric_tasks: list[tuple[str, str]] = []

        # Load current thresholds from result.json
        thresholds_map: dict[str, str] = {}
        try:
            with open(os.path.join(general_dir, "result.json"), 'r', encoding='utf-8') as rf:
                rd = json.load(rf)
            if isinstance(rd, dict):
                for k, v in rd.items():
                    if isinstance(v, dict) and "threshold" in v:
                        try:
                            thresholds_map[k] = str(v.get("threshold"))
                        except Exception:
                            continue
        except Exception:
            thresholds_map = {}

        for metric_name in os.listdir(single_metrics_dir):
            metric_dir = os.path.join(single_metrics_dir, metric_name)
            if not os.path.isdir(metric_dir):
                continue
            thr_key = thresholds_map.get(metric_name)
            metric_path = os.path.join(metric_dir, thr_key) if thr_key else None
            if metric_path and os.path.isdir(metric_path):
                metric_tasks.append((metric_name, metric_path))

        if metric_tasks:
            env_workers = os.getenv("CODE_COVERAGE_WORKERS")
            if env_workers and str(env_workers).isdigit():
                max_workers = max(1, int(env_workers))
            else:
                max_workers = min(len(metric_tasks), max(1, mp.cpu_count() or 1))

            with ProcessPoolExecutor(max_workers=max_workers) as pool:
                futs = [pool.submit(_coverage_metric_worker, t) for t in metric_tasks]
                for fut in as_completed(futs):
                    try:
                        name, total = fut.result()
                        counts[name] = int(total or 0)
                    except Exception as e:
                        logging.info(f"Worker failed (coverage count): {e}")

    # Read global methods total for coverage calculation
    methods_total_path = os.path.join(general_dir, "methods_total.json")
    global_total_methods: int | None = None
    try:
        with open(methods_total_path, 'r', encoding='utf-8') as f:
            mt = json.load(f)
            if isinstance(mt, dict):
                try:
                    global_total_methods = int(mt.get("total_methods"))
                except Exception:
                    global_total_methods = None
    except Exception as e:
        logging.info(f"Could not read methods_total.json at {methods_total_path}: {e}")

    # Update result.json
    result_path = os.path.join(general_dir, "result.json")
    try:
        try:
            with open(result_path, 'r', encoding='utf-8') as rf:
                result_data = json.load(rf)
        except Exception:
            result_data = {}

        if not isinstance(result_data, dict):
            result_data = {}

        for metric, cnt in counts.items():
            entry = result_data.get(metric)
            if not isinstance(entry, dict):
                entry = {}
            entry["total_methods"] = int(cnt)

            coverage = None
            if isinstance(global_total_methods, int) and global_total_methods > 0:
                try:
                    coverage = float(cnt) / float(global_total_methods)
                except Exception:
                    coverage = None
            elif isinstance(global_total_methods, int) and global_total_methods == 0:
                coverage = 0.0

            if coverage is not None:
                entry["coverage"] = float(coverage)
            result_data[metric] = entry

        with open(result_path, 'w', encoding='utf-8') as wf:
            json.dump(result_data, wf, indent=2, ensure_ascii=False)
        logging.info(f"Code coverage (method counts + coverage) written to {result_path}")
    except Exception as e:
        logging.info(f"Error writing result file {result_path}: {e}")

    return counts


def calculate_lift():
    """
    Compute confusion counts and derived metrics per metric, update data/general/result.json.

    For each metric at its current threshold, compute the following values:
      - TP: Vulnerable methods that are also found ("found_vulns").
      - FP: Found methods that are not vulnerable (selected methods - TP).
      - TN: Not-found methods that are not vulnerable.
      - FN: Vulnerable methods that are not found (total_vulns - TP).

    Derived metrics (per metric):
      - recall    = TP / (TP + FN)
      - coverage  = as currently computed and stored (selected / global_total_methods)
      - precision = TP / (TP + FP)
      - lift      = recall / coverage (as currently defined)
      - f1        = 2 * precision * recall / (precision + recall)
      - f2, f3    = F_beta with beta in {2, 3}:
                    (1 + beta^2) * P * R / (beta^2 * P + R)

    Notes:
      - "selected" refers to the number of methods in the metric's threshold folder
        (stored as entry["total_methods"]).
      - "global_total_methods" is loaded from data/general/methods_total.json when available
        (fallback to result.json top-level key "total_methods").
      - Values are only set when the required inputs are present and denominators are > 0.
    """
    base = os.getcwd()
    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    result_path = os.path.join(general_dir, "result.json")
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            result_data = json.load(f)
    except Exception as e:
        logging.info(f"Could not read result file {result_path}: {e}")
        return None

    if not isinstance(result_data, dict):
        logging.info(f"Unexpected format in {result_path}: expected object at top-level")
        return None

    # Load global total methods to enable TN calculation; prefer methods_total.json
    global_total_methods = None
    methods_total_path = os.path.join(general_dir, "methods_total.json")
    try:
        with open(methods_total_path, 'r', encoding='utf-8') as mtf:
            mt = json.load(mtf)
        if isinstance(mt, dict):
            try:
                global_total_methods = int(mt.get("total_methods"))
            except Exception:
                global_total_methods = None
    except Exception:
        global_total_methods = None

    # Fallback: sometimes also stored on the top-level of result.json
    if not isinstance(global_total_methods, int):
        try:
            gtm = result_data.get("total_methods")
            if gtm is not None:
                global_total_methods = int(gtm)
        except Exception:
            global_total_methods = None

    for metric, entry in list(result_data.items()):
        if not isinstance(entry, dict):
            # skip non-metric entries
            continue

        found = entry.get("found_vulns")
        total = entry.get("total_vulns")
        selected = entry.get("total_methods")  # methods selected by this metric at its threshold
        coverage = entry.get("coverage")

        # Parse numeric values safely
        try:
            found_i = int(found)
            total_i = int(total)
        except Exception:
            # essential for TP/FN/recall
            continue

        # Selected may be missing if coverage wasn't computed; treat as None
        try:
            selected_i = int(selected)
        except Exception:
            selected_i = None

        try:
            coverage_f = float(coverage)
        except Exception:
            coverage_f = None

        # Confusion counts (ensure non-negative where derivable)
        TP = max(0, found_i)
        FN = max(0, total_i - TP)

        FP = None
        TN = None
        if isinstance(selected_i, int):
            try:
                FP = max(0, selected_i - TP)
            except Exception:
                FP = None

            # TN only computable with global total methods
            if isinstance(global_total_methods, int):
                try:
                    TN = max(0, (global_total_methods - selected_i) - FN)
                except Exception:
                    TN = None

        # Recall
        recall = None
        if total_i > 0:
            try:
                recall = float(TP) / float(TP + FN)
            except Exception:
                recall = None

        # Precision
        precision = None
        if isinstance(FP, int):
            denom = TP + FP
            if denom > 0:
                try:
                    precision = float(TP) / float(denom)
                except Exception:
                    precision = None

        # Lift (requires recall and coverage)
        lift = None
        if recall is not None and isinstance(coverage_f, float) and coverage_f > 0.0:
            try:
                lift = recall / coverage_f
            except Exception:
                lift = None

        # F1
        f1 = None
        if precision is not None and recall is not None and (precision + recall) > 0.0:
            try:
                f1 = 2.0 * precision * recall / (precision + recall)
            except Exception:
                f1 = None

        # Generalized F_beta for beta in {2, 3}
        def _f_beta(beta: float, p: float | None, r: float | None) -> float | None:
            try:
                if p is None or r is None:
                    return None
                beta2 = beta * beta
                denom = beta2 * p + r
                if denom <= 0:
                    return None
                return (1.0 + beta2) * p * r / denom
            except Exception:
                return None

        f2 = _f_beta(2.0, precision, recall)
        f3 = _f_beta(3.0, precision, recall)

        # Update entry
        entry["TP"] = int(TP)
        entry["FN"] = int(FN)
        if isinstance(FP, int):
            entry["FP"] = int(FP)
        if isinstance(TN, int):
            entry["TN"] = int(TN)
        if recall is not None:
            entry["recall"] = float(recall)
        if precision is not None:
            entry["precision"] = float(precision)
        if f1 is not None:
            entry["f1"] = float(f1)
        if f2 is not None:
            entry["f2"] = float(f2)
        if f3 is not None:
            entry["f3"] = float(f3)
        if lift is not None:
            entry["lift"] = float(lift)

        result_data[metric] = entry

    try:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Confusion counts and metrics updated in {result_path}")
    except Exception as e:
        logging.info(f"Error writing result file {result_path}: {e}")

    return result_data

def save_result_state():
    """
    Persist a compact snapshot of the current results per metric keyed by threshold.

    Reads data/general/result.json (current run's results written by other steps)
    and stores/updates data/general/result_states.json in the following structure:

        {
          "<metric>": {
            "<threshold>": [
              total_vulns,       # index 0
              found_vulns,       # index 1 (TP)
              total_methods,     # index 2 (selected/predicted positives)
              coverage,          # index 3
              lift,              # index 4
              precision,         # index 5
              recall,            # index 6
              f1,                # index 7
              TP,                # index 8  (redundant with found_vulns)
              FP,                # index 9
              TN,                # index 10
              FN,                # index 11
              f2,                # index 12 (optional; may be None)
              f3                 # index 13 (optional; may be None)
            ]
          },
          ...
        }

    Additional behavior:
    - If a metric's found_vulns is 0 (or cannot be parsed), no entry is written for that metric.
    - Returns True if no metric was written at all in this call; otherwise False.

    If result_states.json already exists, it will be merged (updated) so that
    existing thresholds remain and the current threshold's entry is overwritten
    with the latest values.
    """
    base = os.getcwd()
    general_dir = os.path.join(base, "data", "general")
    os.makedirs(general_dir, exist_ok=True)

    # Source of truth for current run
    result_path = os.path.join(general_dir, "result.json")
    # Aggregated state across thresholds
    out_path = os.path.join(general_dir, "result_states.json")

    # Load current results
    try:
        with open(result_path, 'r', encoding='utf-8') as f:
            current = json.load(f)
    except Exception as e:
        logging.info(f"Could not read current results at {result_path}: {e}")
        return None

    if not isinstance(current, dict):
        logging.info(f"Unexpected format in {result_path}: expected object at top-level")
        return None

    # Load existing states (if any)
    try:
        with open(out_path, 'r', encoding='utf-8') as f:
            states = json.load(f)
            if not isinstance(states, dict):
                states = {}
    except Exception:
        states = {}

    # For each metric entry in current results, update the threshold snapshot
    updated_metrics = 0
    for metric, entry in current.items():
        if not isinstance(entry, dict):
            # Skip non-metric entries
            continue

        # Extract fields; if missing, skip metric to avoid ambiguous state
        thr = entry.get("threshold")
        total_vulns = entry.get("total_vulns")
        found_vulns = entry.get("found_vulns")
        total_methods = entry.get("total_methods")
        coverage = entry.get("coverage")
        lift = entry.get("lift")
        precision = entry.get("precision")
        recall = entry.get("recall")
        f1 = entry.get("f1")
        f2 = entry.get("f2")
        f3 = entry.get("f3")
        TP = entry.get("TP")
        FP = entry.get("FP")
        TN = entry.get("TN")
        FN = entry.get("FN")

        # Require at least a threshold to key by, and basic counts present
        if thr is None:
            # No threshold to key by; skip politely
            continue

        # Build the value list in the requested order
        try:
            tv_i = int(total_vulns) if total_vulns is not None else None
            fv_i = int(found_vulns) if found_vulns is not None else None
            tm_i = int(total_methods) if total_methods is not None else None
            cov_f = float(coverage) if coverage is not None else None
            lift_f = float(lift) if lift is not None else None
            prec_f = float(precision) if precision is not None else None
            rec_f = float(recall) if recall is not None else None
            f1_f = float(f1) if f1 is not None else None
            f2_f = float(f2) if f2 is not None else None
            f3_f = float(f3) if f3 is not None else None
            TP_i = int(TP) if TP is not None else None
            FP_i = int(FP) if FP is not None else None
            TN_i = int(TN) if TN is not None else None
            FN_i = int(FN) if FN is not None else None
        except Exception:
            # If parsing fails, skip this metric to avoid corrupting the state file
            continue

        # Only proceed if we have at least total_vulns and found_vulns
        if tv_i is None or fv_i is None:
            continue

        # Requirement: do not write an entry for metrics with found_vulns == 0
        if fv_i == 0:
            continue

        thr_key = str(thr)
        metric_map = states.get(metric)
        if not isinstance(metric_map, dict):
            metric_map = {}

        metric_map[thr_key] = [
            tv_i,
            fv_i,
            tm_i,
            cov_f,
            lift_f,
            prec_f,
            rec_f,
            f1_f,
            TP_i,
            FP_i,
            TN_i,
            FN_i,
            f2_f,
            f3_f,
        ]
        states[metric] = metric_map
        updated_metrics += 1

    # Write the aggregated state file only if something changed
    if updated_metrics > 0:
        try:
            with open(out_path, 'w', encoding='utf-8') as f:
                json.dump(states, f, indent=2, ensure_ascii=False)
            logging.info(f"Saved result state for {updated_metrics} metrics to {out_path}")
        except Exception as e:
            logging.info(f"Error writing result states to {out_path}: {e}")

    # Return True if nothing was written for all metrics; else False
    return updated_metrics == 0

def delete_not_found_vulns_from_metrics_dir():
    """
    Iterate over all JSON files in `data/not-found-methods/LinesNew` and move
    any files in `data/metrics` that share the same file name into
    `data/deleted` instead of deleting them.

    Returns:
        int: Number of moved files from `data/metrics` to `data/deleted`.
    """
    base = os.getcwd()
    not_found_linesnew_dir = os.path.join(base, "data", "not-found-methods", "LinesNew")
    metrics_dir = os.path.join(base, "data", "metrics")
    deleted_dir = os.path.join(base, "data", "deleted")

    if not os.path.isdir(not_found_linesnew_dir):
        logging.info(f"Not-found directory not present: {not_found_linesnew_dir}")
        return 0
    if not os.path.isdir(metrics_dir):
        logging.info(f"Metrics directory not present: {metrics_dir}")
        return 0

    # Ensure the target directory for moved files exists
    try:
        os.makedirs(deleted_dir, exist_ok=True)
    except Exception as e:
        logging.info(f"Failed to ensure deleted dir {deleted_dir}: {e}")
        return 0

    try:
        candidates = [e for e in os.listdir(not_found_linesnew_dir) if e.endswith('.json')]
    except Exception as e:
        logging.info(f"Failed to list {not_found_linesnew_dir}: {e}")
        return 0

    moved = 0
    for name in candidates:
        target_path = os.path.join(metrics_dir, name)
        try:
            if os.path.isfile(target_path):
                # Compute a destination path; avoid overwriting existing files
                dest_path = os.path.join(deleted_dir, name)
                if os.path.exists(dest_path):
                    root, ext = os.path.splitext(name)
                    # Add a timestamp-based suffix to keep files distinct
                    import time as _time
                    dest_path = os.path.join(deleted_dir, f"{root}_{int(_time.time())}{ext}")

                import shutil as _shutil
                _shutil.move(target_path, dest_path)
                moved += 1
        except Exception as e:
            logging.info(f"Failed to delete {target_path}: {e}")

    logging.info(
        f"Moved {moved}/{len(candidates)} matching metrics files to {deleted_dir} based on not-found LinesNew entries"
    )
    return moved


def plot_graphs():
    """Erzeugt für jede Metrik Diagramme über Threshold aus data/general/result_states.json.

    - Lift        unter data/general/plots/<metric>.png
    - F1-Score    unter data/general/plots/<metric>_f1.png
    - F2-Score    unter data/general/plots/<metric>_f2.png
    - F3-Score    unter data/general/plots/<metric>_f3.png
    - F1/F2/F3    unter data/general/plots/<metric>_f_scores.png
    - Recall      unter data/general/plots/<metric>_recall.png
    - Precision   unter data/general/plots/<metric>_precision.png
    - Precision/Recall (kombiniert, erster Recall-Wert ausgelassen)
                   unter data/general/plots/<metric>_prec_rec.png

    Rückgabe:
        int: Anzahl der generierten Diagramme
             (Lift + F1 + F2 + F3 + F1/F2/F3 kombiniert
              + Recall + Precision + Precision/Recall kombiniert)
    """
    base = os.getcwd()
    general_dir = os.path.join(base, "data", "general")
    states_path = os.path.join(general_dir, "result_states.json")

    # Lade Zustände
    try:
        with open(states_path, "r", encoding="utf-8") as f:
            states = json.load(f)
    except Exception as e:
        logging.info(f"Could not read {states_path}: {e}")
        return 0

    if not isinstance(states, dict) or not states:
        logging.info(f"No metrics to plot in {states_path}")
        return 0

    # Matplotlib nur laden, wenn benötigt
    try:
        import matplotlib
        try:
            matplotlib.use("Agg")  # headless
        except Exception:
            pass
        import matplotlib.pyplot as plt
    except Exception as e:
        logging.info(f"matplotlib not available for plotting: {e}")
        return 0

    out_dir = os.path.join(general_dir, "plots")
    os.makedirs(out_dir, exist_ok=True)

    import re as _re

    plotted = 0
    for metric, thr_map in states.items():
        if not isinstance(thr_map, dict) or not thr_map:
            continue

        # Punkte (Threshold, Metrik) aufbauen
        # Indexe:
        #   4 == Lift
        #   5 == Precision
        #   6 == Recall
        #   7 == F1
        #  12 == F2 (optional)
        #  13 == F3 (optional)
        points_lift = []
        points_f1 = []
        points_f2 = []
        points_f3 = []
        points_precision = []
        points_recall = []
        for thr_key, values in thr_map.items():
            if not isinstance(values, list) or len(values) < 5:
                continue
            try:
                x_thr = float(thr_key)
            except Exception:
                continue

            # Lift sammeln
            lift_val = values[4]
            if lift_val is not None:
                try:
                    y_lift = float(lift_val)
                    if x_thr >= 0 and y_lift >= 0:
                        points_lift.append((x_thr, y_lift))
                except Exception:
                    pass

            # F1 sammeln, falls vorhanden
            if len(values) >= 8:
                f1_val = values[7]
                if f1_val is not None:
                    try:
                        y_f1 = float(f1_val)
                        if x_thr >= 0 and y_f1 >= 0:
                            points_f1.append((x_thr, y_f1))
                    except Exception:
                        pass

            # F2 sammeln (Index 12)
            if len(values) >= 13:
                f2_val = values[12]
                if f2_val is not None:
                    try:
                        y_f2 = float(f2_val)
                        if x_thr >= 0 and y_f2 >= 0:
                            points_f2.append((x_thr, y_f2))
                    except Exception:
                        pass

            # F3 sammeln (Index 13)
            if len(values) >= 14:
                f3_val = values[13]
                if f3_val is not None:
                    try:
                        y_f3 = float(f3_val)
                        if x_thr >= 0 and y_f3 >= 0:
                            points_f3.append((x_thr, y_f3))
                    except Exception:
                        pass

            # Precision sammeln (Index 5)
            if len(values) >= 6:
                prec_val = values[5]
                if prec_val is not None:
                    try:
                        y_prec = float(prec_val)
                        if x_thr >= 0 and y_prec >= 0:
                            points_precision.append((x_thr, y_prec))
                    except Exception:
                        pass

            # Recall sammeln (Index 6)
            if len(values) >= 7:
                rec_val = values[6]
                if rec_val is not None:
                    try:
                        y_rec = float(rec_val)
                        if x_thr >= 0 and y_rec >= 0:
                            points_recall.append((x_thr, y_rec))
                    except Exception:
                        pass

        metric_slug = _re.sub(r"[^0-9a-zA-Z]+", "_", (metric or "").strip().lower()).strip("_") or "metric"

        # LIFT-PLOT
        if points_lift:
            points_lift.sort(key=lambda p: p[0])
            xs, ys = zip(*points_lift)

            fig, ax = plt.subplots()
            ax.plot(xs, ys, marker="o")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(metric)
            ax.set_xlabel("Threshold")
            ax.set_ylabel("Lift")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # F1-PLOT
        if points_f1:
            points_f1.sort(key=lambda p: p[0])
            xs, ys = zip(*points_f1)

            fig, ax = plt.subplots()
            ax.plot(xs, ys, marker="o")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (F1)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("F1-Score")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_f1.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save F1 plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # F2-PLOT
        if points_f2:
            points_f2.sort(key=lambda p: p[0])
            xs, ys = zip(*points_f2)

            fig, ax = plt.subplots()
            ax.plot(xs, ys, marker="o")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (F2)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("F2-Score")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_f2.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save F2 plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # F3-PLOT
        if points_f3:
            points_f3.sort(key=lambda p: p[0])
            xs, ys = zip(*points_f3)

            fig, ax = plt.subplots()
            ax.plot(xs, ys, marker="o")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (F3)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("F3-Score")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_f3.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save F3 plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # Combined F1/F2/F3 plot (falls mindestens eine Kurve vorhanden ist)
        if points_f1 or points_f2 or points_f3:
            fig, ax = plt.subplots()

            # F1
            if points_f1:
                pts = sorted(points_f1, key=lambda p: p[0])
                xs, ys = zip(*pts)
                ax.plot(xs, ys, marker="o", label="F1")

            # F2
            if points_f2:
                pts = sorted(points_f2, key=lambda p: p[0])
                xs, ys = zip(*pts)
                ax.plot(xs, ys, marker="o", label="F2")

            # F3
            if points_f3:
                pts = sorted(points_f3, key=lambda p: p[0])
                xs, ys = zip(*pts)
                ax.plot(xs, ys, marker="o", label="F3")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (F1/F2/F3)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("F-Score")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            ax.legend()
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_f_scores.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save combined F-score plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # PRECISION-PLOT
        if points_precision:
            points_precision.sort(key=lambda p: p[0])
            xs, ys = zip(*points_precision)

            fig, ax = plt.subplots()
            ax.plot(xs, ys, marker="o")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (Precision)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("Precision")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_precision.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save Precision plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

        # RECALL-PLOT (ersten Wert auslassen, falls vorhanden)
        if points_recall:
            pts_rec_plot = sorted(points_recall, key=lambda p: p[0])
            if len(pts_rec_plot) > 1:
                pts_rec_plot = pts_rec_plot[1:]
            else:
                pts_rec_plot = []

            if pts_rec_plot:
                xs, ys = zip(*pts_rec_plot)

                fig, ax = plt.subplots()
                ax.plot(xs, ys, marker="o")

                ax.set_xlim(left=0)
                ax.set_ylim(bottom=0)
                try:
                    ax.spines["top"].set_visible(False)
                    ax.spines["right"].set_visible(False)
                except Exception:
                    pass

                ax.set_title(f"{metric} (Recall)")
                ax.set_xlabel("Threshold")
                ax.set_ylabel("Recall")
                ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
                fig.tight_layout()

                out_path = os.path.join(out_dir, f"{metric_slug}_recall.png")
                try:
                    fig.savefig(out_path)
                    plotted += 1
                except Exception as e:
                    logging.info(f"Failed to save Recall plot for {metric} at {out_path}: {e}")
                finally:
                    plt.close(fig)

        # Combined Precision/Recall plot (erster Recall-Wert wird ausgelassen)
        if points_precision or points_recall:
            fig, ax = plt.subplots()

            # Precision
            if points_precision:
                pts_prec = sorted(points_precision, key=lambda p: p[0])
                xs_p, ys_p = zip(*pts_prec)
                ax.plot(xs_p, ys_p, marker="o", label="Precision")

            # Recall (ohne ersten Wert)
            if points_recall:
                pts_rec = sorted(points_recall, key=lambda p: p[0])
                if len(pts_rec) > 1:
                    pts_rec = pts_rec[1:]
                else:
                    pts_rec = []

                if pts_rec:
                    xs_r, ys_r = zip(*pts_rec)
                    ax.plot(xs_r, ys_r, marker="o", label="Recall")

            ax.set_xlim(left=0)
            ax.set_ylim(bottom=0)
            try:
                ax.spines["top"].set_visible(False)
                ax.spines["right"].set_visible(False)
            except Exception:
                pass

            ax.set_title(f"{metric} (Precision/Recall)")
            ax.set_xlabel("Threshold")
            ax.set_ylabel("Score")
            ax.grid(True, linestyle="--", linewidth=0.5, alpha=0.5)
            ax.legend()
            fig.tight_layout()

            out_path = os.path.join(out_dir, f"{metric_slug}_prec_rec.png")
            try:
                fig.savefig(out_path)
                plotted += 1
            except Exception as e:
                logging.info(f"Failed to save combined Precision/Recall plot for {metric} at {out_path}: {e}")
            finally:
                plt.close(fig)

    logging.info(f"Generated {plotted} metric plot(s) in {out_dir}")
    return plotted


def calculate_overlap_of_metrics(threshold_override: dict | None = None):
    """
    Compute the pairwise overlap of vulnerabilities detected by each metric
    (at its currently selected threshold) and generate a heatmap plot.

    Vorgehen (Deutsch):
    - Für jede Metrik in data/single-metrics wird ausschließlich der
      Threshold-Unterordner verwendet, der in data/general/result.json unter
      "threshold" konfiguriert ist.
    - Wir iterieren über alle Vulnerabilities in data/arvo-projects und
      ermitteln – analog zu check_if_function_in_vulns – pro Metrik die Menge
      der tatsächlich gefundenen Vulnerabilities (sm_key = "{projekt}_{localID}").
      Details zur Übereinstimmung:
        * Es wird per Suffix der Dateipfad verglichen, Funktionsname per
          Basisnamen (ohne Namespace/Templates) gematcht.
        * Falls in der Vulnerability-Quelle Parameter existieren, wird die
          gleiche Parameteranzahl (Arity) gefordert; Typgleichheit wird nicht
          strikt geprüft (entspricht check_if_function_in_vulns).
    - Aus den Found-Mengen bauen wir eine Overlap-Matrix: Zelle (i, j) = Anzahl
      der gemeinsamen sm_keys zwischen Metrik i und Metrik j.
    - Ergebnis wird als JSON unter data/general/overlap_matrix.json gespeichert
      und als Heatmap unter data/general/plots/overlap_matrix.png visualisiert.

    Approach (English):
    - Read metrics under data/single-metrics and, for each metric, select only
      the subfolder that corresponds to its configured threshold from
      data/general/result.json (key: "threshold").
    - Iterate over vulnerabilities in data/arvo-projects and, using the same
      matching semantics as check_if_function_in_vulns, collect per metric the
      set of actually found vulnerability IDs (sm_key = "{project}_{localID}").
      Matching details:
        * Normalize paths (suffix compare) and match base function names.
        * If vuln signature exposes parameters, require equal arity; types are
          not strictly compared (same as check_if_function_in_vulns).
    - Build an overlap matrix where cell (i, j) is |found[i] ∩ found[j]|.
    - Persist JSON to data/general/overlap_matrix.json and render a heatmap to
      data/general/plots/overlap_matrix.png with metrics on both axes.

    Args:
        threshold_override (dict | None): Optional mapping metric -> threshold
            to force a specific threshold folder per metric (e.g.,
            {
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
              "NumDevs": 200,
            }). When not provided, values from data/general/result.json are used.

    Returns:
        dict: {"metrics": [metric names], "matrix": [[int overlaps]]}
    """

    base = os.getcwd()
    single_metrics_dir = os.path.join(base, "data", "single-metrics")
    vulns_dir = os.path.join(base, "data", "arvo-projects")
    general_dir = os.path.join(base, "data", "general")
    plots_dir = os.path.join(general_dir, "plots")
    os.makedirs(general_dir, exist_ok=True)
    os.makedirs(plots_dir, exist_ok=True)

    # Collect metric names from data/single-metrics
    if not os.path.isdir(single_metrics_dir):
        logging.info(f"Single-metrics directory not found: {single_metrics_dir}")
        return {"metrics": [], "matrix": []}

    metric_names = [m for m in os.listdir(single_metrics_dir)
                    if os.path.isdir(os.path.join(single_metrics_dir, m))]
    if not metric_names:
        logging.info("No metrics found under data/single-metrics")
        return {"metrics": [], "matrix": []}

    # Load current thresholds per metric from data/general/result.json
    thresholds_by_metric: dict[str, str] = {}
    result_path = os.path.join(general_dir, "result.json")
    try:
        with open(result_path, "r", encoding="utf-8") as rf:
            rd = json.load(rf)
        if isinstance(rd, dict):
            for m in metric_names:
                entry = rd.get(m)
                if isinstance(entry, dict) and "threshold" in entry:
                    try:
                        thresholds_by_metric[m] = str(entry.get("threshold"))
                    except Exception:
                        continue
    except Exception:
        thresholds_by_metric = {}

    # Apply explicit override when provided (use exactly these thresholds)
    if isinstance(threshold_override, dict):
        for k, v in threshold_override.items():
            try:
                thresholds_by_metric[k] = str(v)
            except Exception:
                continue

    # If override provided, restrict to those metrics explicitly
    if isinstance(threshold_override, dict) and threshold_override:
        metric_names = [m for m in metric_names if m in threshold_override]

    # Filter metrics to those that have an existing threshold directory
    filtered_metrics: list[str] = []
    for m in metric_names:
        thr_key = thresholds_by_metric.get(m)
        if not thr_key:
            continue
        thr_dir = os.path.join(single_metrics_dir, m, thr_key)
        if os.path.isdir(thr_dir):
            filtered_metrics.append(m)
    metric_names = filtered_metrics

    if not metric_names:
        logging.info("No metric threshold directories found for overlap computation")
        return {"metrics": [], "matrix": []}

    # Collect vulnerability files
    vuln_files = [os.path.join(vulns_dir, f) for f in os.listdir(vulns_dir)
                  if f.endswith(".json")] if os.path.isdir(vulns_dir) else []
    if not vuln_files:
        logging.info(f"No vulnerability files found in {vulns_dir}")
        return {"metrics": metric_names, "matrix": [[0 for _ in metric_names] for _ in metric_names]}

    # Prepare tasks for parallel processing, reusing the same worker used by
    # check_if_function_in_vulns but skipping any writes.
    tasks = [
        (vp, metric_names, single_metrics_dir, "", "", True, thresholds_by_metric)
        for vp in vuln_files
    ]

    # Aggregate found sets per metric
    global_seen_found = {m: set() for m in metric_names}

    env_workers = os.getenv("CIFIV_WORKERS")
    if env_workers and str(env_workers).isdigit():
        max_workers = max(1, int(env_workers))
    else:
        max_workers = max(1, min(len(vuln_files), mp.cpu_count() or 1))

    with ProcessPoolExecutor(max_workers=max_workers) as pool:
        futs = [pool.submit(_cifiv_process_vuln_file, t) for t in tasks]
        for fut in as_completed(futs):
            try:
                res = fut.result()
            except Exception as e:
                logging.info(f"Worker failed (overlap): {e}")
                continue
            if not isinstance(res, dict):
                continue
            sf = res.get("seen_found", {})
            if not isinstance(sf, dict):
                continue
            for m in metric_names:
                try:
                    global_seen_found[m].update(sf.get(m, []))
                except Exception:
                    continue

    # Build a deterministic order for matrix and compute pairwise intersections
    metric_names_sorted = sorted(metric_names)
    sets_by_metric = {m: set(global_seen_found.get(m, set())) for m in metric_names_sorted}
    size = len(metric_names_sorted)
    matrix: list[list[int]] = [[0] * size for _ in range(size)]
    for i, mi in enumerate(metric_names_sorted):
        for j, mj in enumerate(metric_names_sorted):
            if i <= j:
                inter = sets_by_metric[mi].intersection(sets_by_metric[mj])
                matrix[i][j] = matrix[j][i] = int(len(inter))

    # Write JSON summary
    overlap_json_path = os.path.join(general_dir, "overlap_matrix.json")
    try:
        with open(overlap_json_path, "w", encoding="utf-8") as f:
            json.dump({"metrics": metric_names_sorted, "matrix": matrix}, f, indent=2, ensure_ascii=False)
        logging.info(f"Overlap matrix written to {overlap_json_path}")
    except Exception as e:
        logging.info(f"Error writing overlap matrix {overlap_json_path}: {e}")

    # Create heatmap plot
    try:
        import matplotlib
        try:
            matplotlib.use("Agg")
        except Exception:
            pass
        import matplotlib.pyplot as plt
    except Exception as e:
        logging.info(f"matplotlib not available for overlap plot: {e}")
        return {"metrics": metric_names_sorted, "matrix": matrix}

    fig, ax = plt.subplots(figsize=(max(6, len(metric_names_sorted) * 0.6),
                                    max(5, len(metric_names_sorted) * 0.6)))
    im = ax.imshow(matrix, cmap="viridis")
    ax.set_xticks(range(size))
    ax.set_xticklabels(metric_names_sorted, rotation=45, ha="right")
    ax.set_yticks(range(size))
    ax.set_yticklabels(metric_names_sorted)
    ax.set_xlabel("Metric")
    ax.set_ylabel("Metric")
    ax.set_title("Vulnerability Overlap Between Metrics")

    # Annotate cells with counts for readability
    try:
        for i in range(size):
            for j in range(size):
                ax.text(j, i, str(matrix[i][j]), ha="center", va="center", color="white" if matrix[i][j] > 0 else "black")
    except Exception:
        pass

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04, label="Overlap count")
    fig.tight_layout()

    out_plot = os.path.join(plots_dir, "overlap_matrix.png")
    try:
        fig.savefig(out_plot)
        logging.info(f"Overlap heatmap saved to {out_plot}")
    except Exception as e:
        logging.info(f"Failed to save overlap plot at {out_plot}: {e}")
    finally:
        plt.close(fig)

    return {"metrics": metric_names_sorted, "matrix": matrix}
