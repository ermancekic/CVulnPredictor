"""
retrieve_arvo_table_data.py

Exports per-project crash data from the ARVO SQLite database (arvo.db).

For each distinct project found in the DB, a JSON file named after the project
is written containing entries with: localID, crash_type, crash_output, severity.
"""

from __future__ import annotations

import os
import re
import sqlite3
import logging
import ujson as json
import multiprocessing
from typing import Dict, List, Any

_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>.+?)\s+(?P<file>\/[^:\s]+):(?P<line>\d+)(?::(?P<col>\d+))?"
)

_EXCLUDE_SUBSTRINGS = (
    "/llvm-project/",
    "/aflpp/",
    "/aflplusplus/",
    "/lib/",
    "/usr/",
    "sanitizer_common",
    "/compiler-rt/",
)

def _normalize(name: str) -> str:
	"""Normalize column names for fuzzy matching (case/underscore insensitive)."""
	return re.sub(r"[^a-z0-9]+", "", name.lower())


def export_per_project_crashes():
	"""
	Reads arvo.db and generates a JSON file for each "project" with fields:
	  - localID
	  - crash_type
	  - crash_output
	  - severity

	Files are saved under data/arvo-projects/<project>.json.

	Args:
		db_path: Path to arvo.db (Default: ./arvo.db)
		out_dir: Output directory (Default: ./data/arvo-projects)
	"""
	cwd = os.getcwd()
	db_path = os.path.join(cwd, "arvo.db")
	out_dir = os.path.join(cwd, "data", "arvo-projects")

	os.makedirs(out_dir, exist_ok=True)

	if not os.path.exists(db_path):
		logging.info(f"arvo.db not found: {db_path}")
		return

	target_norm = {
		"project": "project",
		"localid": "localID",
		"crashtype": "crash_type",
		"crashoutput": "crash_output",
		"severity": "severity",
	}

	project_entries: Dict[str, List[Dict[str, Any]]] = {}

	conn = None
	try:
		conn = sqlite3.connect(db_path)
		conn.row_factory = sqlite3.Row
		cur = conn.cursor()

		# List all tables (excluding sqlite internal tables)
		cur.execute("SELECT name FROM sqlite_master WHERE type='table' AND name NOT LIKE 'sqlite_%'")
		tables = [r[0] for r in cur.fetchall()]

		for tbl in tables:
			try:
				# Read column information
				cur.execute(f"PRAGMA table_info('{tbl}')")
				cols = [r[1] for r in cur.fetchall()]
				if not cols:
					continue

				# Mapping: desired normalized name -> actual column name
				norm_to_actual: Dict[str, str] = {}
				normalized_cols = { _normalize(c): c for c in cols }

				# Match candidates for 'project' more generously (project, projectname)
				for cand in ("project", "projectname"):
					if cand in normalized_cols and "project" not in norm_to_actual:
						norm_to_actual["project"] = normalized_cols[cand]

				# Direct matching for the remaining target columns
				for need in ("localid", "crashtype", "crashoutput", "severity"):
					if need in normalized_cols and need not in norm_to_actual:
						norm_to_actual[need] = normalized_cols[need]

				# If there is no project column, skip
				if "project" not in norm_to_actual:
					continue

				# Build SELECT list dynamically; alias missing columns as NULL
				select_parts = [f"'{tbl}' AS _table"]
				for need, out_key in target_norm.items():
					if need == "project":
						actual = norm_to_actual.get("project")
						select_parts.append(f"\"{actual}\" AS project")
						continue
					actual = norm_to_actual.get(need)
					alias = out_key  # desired output name
					if actual:
						select_parts.append(f"\"{actual}\" AS \"{alias}\"")
					else:
						select_parts.append(f"NULL AS \"{alias}\"")

				sql = f"SELECT {', '.join(select_parts)} FROM '{tbl}'"
				cur.execute(sql)
				rows = cur.fetchall()

				for row in rows:
					project = row["project"]
					if project is None or str(project).strip() == "":
						continue
					entry = {
						"localID": row["localID"],
						"crash_type": row["crash_type"],
						"crash_output": row["crash_output"],
						"severity": row["severity"],
					}
					project_entries.setdefault(str(project), []).append(entry)

			except Exception as e:
				logging.info(f"Error reading table {tbl}: {e}")

	except Exception as e:
		logging.info(f"Error opening/reading {db_path}: {e}")
		return
	finally:
		try:
			if conn:
				conn.close()
		except Exception:
			pass

	# Write one file per project
	total_entries = 0
	for project, entries in project_entries.items():
		safe_name = re.sub(r"[^A-Za-z0-9._-]+", "_", project)
		path = os.path.join(out_dir, f"{safe_name}.json")
            
		if os.path.exists(path):
			continue

		try:
			with open(path, "w", encoding="utf-8") as f:
				json.dump(entries, f, indent=2, ensure_ascii=False)
			total_entries += len(entries)
		except Exception as e:
			logging.info(f"Error writing {path}: {e}")

	logging.info(f"Export completed: {len(project_entries)} projects, {total_entries} entries.")

def _parse_location_from_stacktrace(stacktrace: str):
    """
    Returns a dict with {file, line, column, function} or None,
    where the first frame from project code is preferred.
    """
    if not stacktrace:
        return None

    candidates = []
    for line in stacktrace.splitlines():
        m = _FRAME_RE.search(line)
        if not m:
            continue
        func = m.group("func").strip()
        path = m.group("file").strip()
        line_no = int(m.group("line"))
        col = m.group("col")
        col_no = int(col) if col is not None else None

        entry = {
            "file": path,
            "line": line_no,
            "column": col_no,
            "function": func,
        }
        candidates.append(entry)

    if not candidates:
        return None

    def is_project(entry):
        p = entry["file"]
        if any(x in p for x in _EXCLUDE_SUBSTRINGS):
            return False
        # Prefer typical project paths (e.g. /src/ or /home/…/code/)
        return ("/src/" in p) or ("/home/" in p) or ("/work/" in p)

    # 1) first "project" frame
    for c in candidates:
        if is_project(c):
            return c
    # 2) otherwise the very first recognized frame
    return candidates[0]

def _inject_location(rep):
    """
    Adds rep['location'] (or None), based on rep['stacktrace'].
    """
    try:
        # If already present, do not parse again
        if rep.get("location") is not None:
            return rep

        loc = _parse_location_from_stacktrace(rep.get("crash_output") or "")
        if loc and loc.get("file"):
            loc["file"] = loc["file"].replace("/src", "", 1)
        rep["location"] = loc  # dict oder None
        return rep
    except Exception:
        # In case of error, set None instead of crashing
        rep["location"] = None
        return rep

def extract_vuln_location():
    """
    Iterates over all JSONs under data/arvo-projects, extracts from 'crash_output' the
    most likely code location and stores it as 'location' in the entry.
    Uses parallelization for speed.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "arvo-projects")
    if not os.path.isdir(vulns_dir):
        raise FileNotFoundError(f"Vuln directory not found: {vulns_dir}")

    try:
        cpu_count = max(1, multiprocessing.cpu_count())
    except Exception:
        cpu_count = 4

    for fname in os.listdir(vulns_dir):
        if not fname.endswith(".json"):
            continue

        file_path = os.path.join(vulns_dir, fname)

        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reports = json.load(f)
        except Exception as e:
            logging.warning(f"Skipping {file_path}: failed to read JSON ({e})")
            continue

        if not isinstance(reports, list):
            logging.warning(f"Skipping {file_path}: JSON is not a list")
            continue

        with multiprocessing.Pool(cpu_count) as pool:
            reports_out = pool.map(_inject_location, reports)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(reports_out, f, indent=2, ensure_ascii=False)
            logging.info(f"Wrote locations into {file_path}")
        except Exception as e:
            logging.error(f"Failed to write {file_path}: {e}")

def delete_null_locations_in_vuln():
    """
    Iterate over all JSON files in data/arvo-projects, remove any entries
    where entry['location'] is None (or missing), and write back the filtered
    list. If a JSON file becomes empty after filtering, delete the file.
    """
    cwd = os.getcwd()
    projects_dir = os.path.join(cwd, "data", "arvo-projects")

    if not os.path.isdir(projects_dir):
        raise FileNotFoundError(f"Projects directory not found: {projects_dir}")

    removed_entries_total = 0
    deleted_files = 0
    processed_files = 0

    for fname in os.listdir(projects_dir):
        if not fname.endswith(".json"):
            continue

        file_path = os.path.join(projects_dir, fname)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            logging.warning(f"Skipping {file_path}: failed to read JSON ({e})")
            continue

        if not isinstance(data, list):
            logging.warning(f"Skipping {file_path}: JSON root is not a list")
            continue

        processed_files += 1
        original_len = len(data)
        # Keep only entries that have a non-null location
        filtered = [rep for rep in data if rep.get("location") is not None]
        removed = original_len - len(filtered)
        removed_entries_total += max(removed, 0)

        if not filtered:
            # Delete the file if no entries remain
            try:
                os.remove(file_path)
                deleted_files += 1
                logging.info(f"Deleted empty JSON after filtering: {file_path}")
            except Exception as e:
                logging.error(f"Failed to delete {file_path}: {e}")
            continue

        # Write back filtered content
        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(filtered, f, indent=2, ensure_ascii=False)
        except Exception as e:
            logging.error(f"Failed to write {file_path}: {e}")

    logging.info(
        f"Finished filtering: processed_files={processed_files}, "
        f"removed_entries_total={removed_entries_total}, deleted_files={deleted_files}"
    )