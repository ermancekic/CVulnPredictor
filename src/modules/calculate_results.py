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

    # Complete cleanup of output directories
    if os.path.exists(single_metrics_dir):
        shutil.rmtree(single_metrics_dir)
    os.makedirs(single_metrics_dir, exist_ok=True)

    # Pre-create all metric subdirectories (while thresholds are known)
    for metric_name in thresholds:
        os.makedirs(os.path.join(single_metrics_dir, metric_name), exist_ok=True)

    # For each input file (project/commit), read and filter once
    for entry in os.listdir(metrics_dir):
        input_path = os.path.join(metrics_dir, entry)
        try:
            with open(input_path, 'r', encoding='utf-8') as f:
                metrics_data = json.load(f)
            logging.info(f"Processing file: {entry}")
        except Exception as e:
            logging.info(f"Fehler beim Lesen von {input_path}: {e}")
            continue

        # Collection structure: metric_name -> file_name -> function_name -> {metric_name: value}
        filtered = defaultdict(lambda: defaultdict(dict))

        for file_name, functions in metrics_data.items():
            for func_name, metrics in functions.items():
                # func_name remains fully intact
                for metric_name, metric_value in metrics.items():
                    if metric_name in thresholds and metric_value >= thresholds[metric_name]:
                        # only create here once, no repeated makedirs
                        filtered[metric_name][file_name].setdefault(func_name, {})[metric_name] = metric_value

        # Now write exactly one file per metric folder
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

def check_if_function_in_vulns():
    """
    Identify functions from single-metrics that match known vulnerabilities and write results.
    Path comparison uses a normalized vulnerability file (.. and before cut off),
    function comparison uses only the bare function name (without namespace).
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
            logging.info(f"Error reading {vuln_path}: {e}")
            continue

        for vuln in vuln_list:
            local_id = vuln.get('localID')
            loc = vuln.get('location', {})
            loc_file_raw = loc.get('file')
            loc_func_raw = loc.get('function', '')

            if not local_id or not loc_file_raw or not loc_func_raw:
                continue

            # Normalize vulnerability file path: cut off everything up to and including the last '..'
            loc_file = _normalize_loc_path(loc_file_raw)
            if not loc_file:
                continue

            # Bare function name and parameter info (if available)
            func_name = _base_func_name(loc_func_raw)
            vuln_param_count, vuln_param_types = _param_info(loc_func_raw)

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
                    logging.info(f"Error reading {sm_file}: {e}")
                    continue

                match_found = False

                for code_path, funcs in sm_data.items():
                    # code_path vereinheitlichen (nur Slashes)
                    code_path_norm = code_path.replace('\\', '/')
                    # Comparison by end: code_path must end with the cleaned loc_file
                    if not code_path_norm.endswith(loc_file):
                        continue

                    for sig in funcs.keys():
                        sig_base = _base_func_name(sig)
                        if sig_base != func_name:
                            continue

                        # Parameter-aware matching:
                        # If vulnerability signature exposes parameter info, require same arity only.
                        # The stricter type-equality checks are intentionally commented out per request.
                        sig_param_count, sig_param_types = _param_info(sig)
                        if vuln_param_count is not None:
                            # If metrics signature has no parameters parsed, fall back to name-only
                            if sig_param_count is not None and sig_param_count != vuln_param_count:
                                continue
                            # Optional: if both sides have normalized types, require equality
                            # (Deactivated to only compare parameter count)
                            # if (
                            #     sig_param_types is not None
                            #     and vuln_param_types is not None
                            #     and sig_param_types
                            #     and vuln_param_types
                            #     and sig_param_types != vuln_param_types
                            # ):
                            #     continue

                        # If we get here, we consider it a match
                        match_found = True
                        out_path = os.path.join(output_dir, metric_name, f"{project}_{local_id}.json")
                        try:
                            with open(out_path, 'r', encoding='utf-8') as of:
                                out_data = json.load(of)
                        except Exception:
                            out_data = {}

                        # In output: Key = original code_path, function key = bare name
                        # Enrich each found entry with the same details as not-found
                        # Prefer vulnerability-side params if provided; otherwise fall back to metrics-side
                        log_param_count = vuln_param_count if vuln_param_count is not None else sig_param_count
                        log_param_types = (
                            vuln_param_types if (vuln_param_types not in (None, [])) else (sig_param_types or [])
                        )

                        found_entry = {
                            'id': local_id,
                            'function': func_name,
                            'signature': loc_func_raw,
                            'param_count': log_param_count,
                            'param_types': log_param_types,
                            'metrics_signature': sig,
                            'metrics_param_count': sig_param_count,
                            'metrics_param_types': sig_param_types if sig_param_types is not None else [],
                        }
                        out_data.setdefault(code_path, {}).setdefault(sig_base, []).append(found_entry)

                        try:
                            with open(out_path, 'w', encoding='utf-8') as of:
                                json.dump(out_data, of, indent=2, ensure_ascii=False)
                        except Exception as e:
                            logging.info(f"Error writing {out_path}: {e}")

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

                    # Enriched not-found entry with signature and parameter details
                    # Keep the structure grouped by normalized file path
                    entry = {
                        "function": func_name,
                        "signature": loc_func_raw,
                        "param_count": vuln_param_count,
                        "param_types": vuln_param_types if vuln_param_types is not None else [],
                    }

                    nf_data.setdefault(loc_file, []).append(entry)

                    try:
                        with open(nf_path, 'w', encoding='utf-8') as nf:
                            json.dump(nf_data, nf, indent=2, ensure_ascii=False)
                    except Exception as e:
                        logging.info(f"Error writing {nf_path}: {e}")

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
        logging.info(f"Error writing result file {result_path}: {e}")
