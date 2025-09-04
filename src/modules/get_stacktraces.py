import os
import ujson as json
import subprocess
import multiprocessing
import re
import logging
import sqlite3

# When True, existing stacktrace entries will be skipped
SKIP_EXISTING = False

logging.basicConfig(
    level=logging.INFO,
    format="[%(processName)s] %(asctime)s %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)

_FRAME_RE = re.compile(
    r"#\d+\s+0x[0-9a-fA-F]+\s+in\s+(?P<func>.+?)\s+(?P<file>\/[^:\s]+):(?P<line>\d+)(?::(?P<col>\d+))?"
)

# Framework/Runtime paths that we do NOT consider as project code
_EXCLUDE_SUBSTRINGS = (
    "/llvm-project/",
    "/aflpp/",
    "/aflplusplus/",
    "/lib/",
    "/usr/",
    "sanitizer_common",
    "/compiler-rt/",
)

def _process_report(rep):
	"""
	Process a single report: run docker and set stacktrace.
    Delete container afterwards
	"""
	# Skip if stacktrace already exists and skipping is enabled
	if SKIP_EXISTING and rep.get("stacktrace") is not None:
		return rep
	oss_id = rep.get("oss-id")
	if not oss_id:
		return rep
	image = f"n132/arvo:{oss_id}-vul"
	container_name = f"arvo_{oss_id}-vul"
	cmd = ["docker", "run", "--name", container_name, "-it", image, "arvo"]
	logging.info(f"Running docker for OSS-ID {oss_id} with command: {' '.join(cmd)}")
	try:
		result = subprocess.run(
			cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, timeout=400
		)
		rep["stacktrace"] = result.stdout
	except Exception as e:
		rep["stacktrace"] = f"Error running docker for {oss_id}: {e}"
	finally:
		# Try to remove the container, ignore errors
		rm_cmd = ["docker", "rm", "-f", container_name]
		try:
			subprocess.run(rm_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
		except Exception as e:
			logging.warning(f"Failed to remove container {container_name}: {e}")
	return rep

def get_stacktraces_from_docker(skip_existing=False):
	"""
	Iterate over each vulnerability entry in JSON files under data/vulns.
	If skip_existing is True, existing 'stacktrace' entries will be skipped.
	For each entry, run the docker command to generate a stacktrace for the OSS-ID
	and store the output in the 'stacktrace' field of each entry.
	"""
	# Set skip flag based on parameter
	global SKIP_EXISTING
	SKIP_EXISTING = skip_existing
	
	cwd = os.getcwd()
	vulns_dir = os.path.join(cwd, "data", "vulns")
	for fname in os.listdir(vulns_dir):
		if not fname.endswith(".json"):
			continue
          
		file_path = os.path.join(vulns_dir, fname)
		with open(file_path, "r", encoding="utf-8") as f:
			reports = json.load(f)
               
		# Parallel processing of reports using all CPU cores
		cpu_count = 15
		with multiprocessing.Pool(cpu_count) as pool:
			reports = pool.map(_process_report, reports)
               
		# Write updated reports back to the file
		with open(file_path, "w", encoding="utf-8") as f:
			json.dump(reports, f, indent=2, ensure_ascii=False)

def _parse_location_from_stacktrace(stacktrace: str):
    """
    Returns a dict with {file, line, column, function} or None,
    preferring the first frame from project code.
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

        loc = _parse_location_from_stacktrace(rep.get("stacktrace") or "")
        rep["location"] = loc  # dict oder None
        return rep
    except Exception as e:
        # In case of error, better to set None instead of crashing
        rep["location"] = None
        rep["location_error"] = f"{type(e).__name__}: {e}"
        return rep


def extract_vuln_location():
    """
    Iterates over all JSONs under data/vulns, extracts from 'stacktrace' the
    most likely code location and stores it as 'location' in the entry.
    Uses parallelization for speed.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "vulns")
    if not os.path.isdir(vulns_dir):
        raise FileNotFoundError(f"Vuln directory not found: {vulns_dir}")

    cpu_count = 20

    for fname in os.listdir(vulns_dir):
        if not fname.endswith(".json"):
            continue

        file_path = os.path.join(vulns_dir, fname)
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                reports = json.load(f)
        except Exception as e:
            print(f"Skipping {file_path}: failed to read JSON ({e})")
            continue

        if not isinstance(reports, list):
            print(f"Skipping {file_path}: JSON is not a list")
            continue

        with multiprocessing.Pool(cpu_count) as pool:
            reports_out = pool.map(_inject_location, reports)

        try:
            with open(file_path, "w", encoding="utf-8") as f:
                json.dump(reports_out, f, indent=2, ensure_ascii=False)
            print(f"Wrote locations into {file_path}")
        except Exception as e:
            print(f"Failed to write {file_path}: {e}")

def get_stacktraces_from_table():
    """
    Go over all JSON files in data/vulns and for each entry with
    'new-oss-id' search in the local SQLite database 'arvo.db' for an
    entry with 'localId' == new-oss-id. If found, get the field
    'report' from the DB and store it as 'stacktrace' in the JSON entry.
    Write the JSON files with the updated entries back.
    """
    cwd = os.getcwd()
    vulns_dir = os.path.join(cwd, "data", "vulns")
    db_path = os.path.join(cwd, "arvo.db")

    if not os.path.isdir(vulns_dir):
        raise FileNotFoundError(f"Vuln directory not found: {vulns_dir}")
    if not os.path.isfile(db_path):
        raise FileNotFoundError(f"Database not found: {db_path}")

    # Open DB once and find tables that have both localId and report
    conn = sqlite3.connect(db_path)
    try:
        cur = conn.cursor()
        cur.execute("SELECT name FROM sqlite_master WHERE type='table'")
        tables = [r[0] for r in cur.fetchall()]

        tables_with_cols = []
        for t in tables:
            try:
                cur.execute(f"PRAGMA table_info('{t}')")
                cols = [r[1] for r in cur.fetchall()]
                if 'localId' in cols and 'crash_output' in cols:
                    tables_with_cols.append(t)
            except Exception:
                # ignore tables we can't introspect
                continue

        if not tables_with_cols:
            logging.warning(f"No table with both 'localId' and 'crash_output' columns found in {db_path}")

        # For each JSON file: load, update, save
        for fname in os.listdir(vulns_dir):
            if not fname.endswith('.json'):
                continue
            file_path = os.path.join(vulns_dir, fname)
            try:
                with open(file_path, 'r', encoding='utf-8') as f:
                    reports = json.load(f)
            except Exception as e:
                logging.warning(f"Skipping {file_path}: failed to read JSON ({e})")
                continue

            if not isinstance(reports, list):
                logging.warning(f"Skipping {file_path}: JSON is not a list")
                continue

            changed = False
            for rep in reports:
                try:
                    new_id = rep.get('new-oss-id')
                    if not new_id:
                        # no id to lookup
                        continue

                    # If stacktrace already present, skip (keeps behavior consistent)
                    if rep.get('stacktrace') is not None:
                        continue

                    found = False
                    for t in tables_with_cols:
                        try:
                            # select crash_output column
                            cur.execute(f'SELECT "crash_output" FROM "{t}" WHERE localId = ? LIMIT 1', (new_id,))
                            row = cur.fetchone()
                            if row is not None:
                                # store the crash output (as-is). If it's bytes, decode to str
                                crash_val = row[0]
                                if isinstance(crash_val, bytes):
                                    try:
                                        crash_val = crash_val.decode('utf-8')
                                    except Exception:
                                        crash_val = repr(crash_val)
                                rep['stacktrace'] = crash_val
                                found = True
                                break
                        except Exception:
                            # ignore per-table query errors and continue
                            continue

                    if not found:
                        # mark explicitly if nothing found
                        rep.setdefault('stacktrace', None)
                        rep.setdefault('stacktrace_error', f"no db entry for localId={new_id}")
                except Exception as e:
                    rep['stacktrace'] = None
                    rep['stacktrace_error'] = f"{type(e).__name__}: {e}"

            # write only if changed (or if we want to always overwrite)
            try:
                with open(file_path, 'w', encoding='utf-8') as f:
                    json.dump(reports, f, indent=2, ensure_ascii=False)
            except Exception as e:
                logging.error(f"Failed to write {file_path}: {e}")
    finally:
        conn.close()

     