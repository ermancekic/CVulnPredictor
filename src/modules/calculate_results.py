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

    # Now write exactly one file per metric folder
    for metric_name, file_dict in filtered.items():
        out_dir = os.path.join(single_metrics_dir, metric_name)
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

    # Complete cleanup of output directories
    if os.path.exists(single_metrics_dir):
        shutil.rmtree(single_metrics_dir)
    os.makedirs(single_metrics_dir, exist_ok=True)

    # Pre-create all metric subdirectories (while thresholds are known)
    for metric_name in thresholds:
        os.makedirs(os.path.join(single_metrics_dir, metric_name), exist_ok=True)

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
        args: (vuln_path, metric_names, metrics_dir, output_dir, not_found_dir)

    Returns:
        dict[str, dict[str, list[str]]]:
            {
              "seen_total": {metric: [sm_key, ...]},
              "seen_found": {metric: [sm_key, ...]}
            }
    """
    (vuln_path, metric_names, metrics_dir, output_dir, not_found_dir) = args

    seen_total = {m: set() for m in metric_names}
    seen_found = {m: set() for m in metric_names}

    # Derive project name from file name
    project = os.path.splitext(os.path.basename(vuln_path))[0]

    # Build per-metric filename sets once per worker for fast existence checks
    metric_files: dict[str, set[str]] = {}
    for m in metric_names:
        mpth = os.path.join(metrics_dir, m)
        try:
            metric_files[m] = set(e for e in os.listdir(mpth) if e.endswith(".json"))
        except Exception:
            metric_files[m] = set()

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
                        out_path = os.path.join(output_dir, metric_name, target_file_name)
                        try:
                            with open(out_path, "r", encoding="utf-8") as of:
                                out_data = json.load(of)
                        except Exception:
                            out_data = {}

                        log_param_count = vuln_param_count if vuln_param_count is not None else sig_param_count
                        log_param_types = (
                            vuln_param_types if (vuln_param_types not in (None, [])) else (sig_param_types or [])
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
            if not match_found:
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

    # Enumerate metrics and ensure target directories exist
    metric_names = [m for m in os.listdir(metrics_dir) if os.path.isdir(os.path.join(metrics_dir, m))] \
                   if os.path.isdir(metrics_dir) else []
    for metric_name in metric_names:
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
    tasks = [(vp, metric_names, metrics_dir, output_dir, not_found_dir) for vp in vuln_files]

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
        # Prepare (metric_name, metric_path) tasks
        metric_tasks: list[tuple[str, str]] = []
        for metric_name in os.listdir(single_metrics_dir):
            metric_path = os.path.join(single_metrics_dir, metric_name)
            if os.path.isdir(metric_path):
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
    Compute Recall and Lift per metric and update data/general/result.json.

    Formulas (per metric):
      Recall = found_vulns / total_vulns
      Effort = coverage
      Lift   = Recall / Effort = (found_vulns / total_vulns) / coverage

    Only sets values when the required inputs are present and denominators are > 0.
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

    for metric, entry in list(result_data.items()):
        if not isinstance(entry, dict):
            continue

        found = entry.get("found_vulns")
        total = entry.get("total_vulns")
        coverage = entry.get("coverage")

        # Parse numeric values safely
        try:
            found_i = int(found)
            total_i = int(total)
        except Exception:
            continue

        try:
            coverage_f = float(coverage)
        except Exception:
            coverage_f = None

        # Compute recall if possible
        recall = None
        if total_i > 0:
            try:
                recall = float(found_i) / float(total_i)
            except Exception:
                recall = None

        # Compute lift if possible (requires recall and coverage > 0)
        lift = None
        if recall is not None and isinstance(coverage_f, float) and coverage_f > 0.0:
            try:
                lift = recall / coverage_f
            except Exception:
                lift = None

        # Update entry
        # if recall is not None:
            # entry["recall"] = float(recall)
        if lift is not None:
            entry["lift"] = float(lift)
        result_data[metric] = entry

    try:
        with open(result_path, 'w', encoding='utf-8') as f:
            json.dump(result_data, f, indent=2, ensure_ascii=False)
        logging.info(f"Recall and Lift updated in {result_path}")
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
            "<threshold>": [total_vulns, found_vulns, total_methods, coverage, lift]
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

        metric_map[thr_key] = [tv_i, fv_i, tm_i, cov_f, lift_f]
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
    Iterate over all JSON files in `data/not-found-methods/LinesNew` and delete
    any files in `data/metrics` that share the same file name.

    Returns:
        int: Number of deleted files in `data/metrics`.
    """
    base = os.getcwd()
    not_found_linesnew_dir = os.path.join(base, "data", "not-found-methods", "LinesNew")
    metrics_dir = os.path.join(base, "data", "metrics")

    if not os.path.isdir(not_found_linesnew_dir):
        logging.info(f"Not-found directory not present: {not_found_linesnew_dir}")
        return 0
    if not os.path.isdir(metrics_dir):
        logging.info(f"Metrics directory not present: {metrics_dir}")
        return 0

    try:
        candidates = [e for e in os.listdir(not_found_linesnew_dir) if e.endswith('.json')]
    except Exception as e:
        logging.info(f"Failed to list {not_found_linesnew_dir}: {e}")
        return 0

    deleted = 0
    for name in candidates:
        target_path = os.path.join(metrics_dir, name)
        try:
            if os.path.isfile(target_path):
                os.remove(target_path)
                deleted += 1
        except Exception as e:
            logging.info(f"Failed to delete {target_path}: {e}")

    logging.info(
        f"Deleted {deleted}/{len(candidates)} matching metrics files based on not-found LinesNew entries"
    )
    return deleted


def plot_graphs():
    """Erzeugt für jede Metrik ein Lift-über-Threshold-Diagramm aus data/general/result_states.json.

    - X-Achse: Thresholds (Schwellenwerte)
    - Y-Achse: 5. Wert (Lift)
    - Nur positive X- und Y-Achse sichtbar

    Rückgabe:
        int: Anzahl der generierten Diagramme
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

        # Punkte (Threshold, Lift) aufbauen; Index 4 == Lift
        points = []
        for thr_key, values in thr_map.items():
            if not isinstance(values, list) or len(values) < 5:
                continue
            lift_val = values[4]
            if lift_val is None:
                continue
            try:
                x_thr = float(thr_key)
                y_lift = float(lift_val)
            except Exception:
                continue
            if x_thr < 0 or y_lift < 0:
                # Nur positive Quadrant-Werte berücksichtigen
                continue
            points.append((x_thr, y_lift))

        if not points:
            continue

        # Nach Threshold sortieren
        points.sort(key=lambda p: p[0])
        xs, ys = zip(*points)

        fig, ax = plt.subplots()
        ax.plot(xs, ys, marker="o")

        # Nur positive Achsen anzeigen
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

        # Dateiname absichern
        metric_slug = _re.sub(r"[^0-9a-zA-Z]+", "_", (metric or "").strip().lower()).strip("_") or "metric"
        out_path = os.path.join(out_dir, f"{metric_slug}.png")
        try:
            fig.savefig(out_path)
            plotted += 1
        except Exception as e:
            logging.info(f"Failed to save plot for {metric} at {out_path}: {e}")
        finally:
            plt.close(fig)

    logging.info(f"Generated {plotted} metric plot(s) in {out_dir}")
    return plotted
