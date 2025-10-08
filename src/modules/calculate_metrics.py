"""
calculate_metrics.py

This module implements functions to compute various software metrics on C/C++ source code
using Clang's Python bindings. It provides utilities to parse source files, calculate metrics
such as lines of code, cyclomatic complexity, loop counts, pointer arithmetic statistics,
and control structure analysis, and serialize the results to JSON.
"""

import os
import sys
import ujson as json
import logging
import traceback
import re
import shutil
import hashlib
import time

clang_path   = os.path.abspath(os.path.join(os.getcwd(), "llvm-project-llvmorg-21.1.2", "clang", "bindings", "python"))
logging.info(f"clang_path: {clang_path}")
sys.path.insert(0, clang_path)

from clang import cindex
from clang.cindex import TokenKind, CursorKind, TypeKind, TranslationUnit

libclang_path =  os.path.abspath(os.path.join(os.getcwd(), "LLVM-21.1.2-Linux-X64", "lib", "libclang.so"))
logging.info(f"libclang_path:  {libclang_path}")
cindex.Config.set_library_file(libclang_path)
cindex.Config.set_compatibility_check(False)

cindex.Config.set_library_path(os.path.dirname(libclang_path))
logging.info(cindex.__file__)

# Initialize Clang index
index = cindex.Index.create()

# Import concrete metric implementations
from .metrics import leopard_metrics, project_metrics
from .metrics.improving_fuzzing_metrics import calculate_loc
DATA_ROOT = os.path.join(os.getcwd(), "data")

# Precompiled patterns and small caches to reduce per-file overhead
INCLUDE_RE = re.compile(r'#\s*include\s*([<"])([^">]+)[">]')

# Cache for include lists per project to avoid re-reading JSON for every file
_INC_CACHE: dict[str, dict] = {}

def _get_project_includes(project_name: str) -> tuple[list[str], dict[str, set[str]]]:
    """Return (headers, base_index) for a project, cached.

    - headers: list of absolute header file paths
    - base_index: basename -> set of directories containing that header
    """
    cached = _INC_CACHE.get(project_name)
    if cached is not None:
        return cached.get("headers", []), cached.get("base_index", {})

    headers: list[str] = []
    base_index: dict[str, set[str]] = {}
    proj_file = os.path.join(DATA_ROOT, 'includes', f"{project_name}.json")
    if os.path.exists(proj_file):
        try:
            with open(proj_file, 'r', encoding='utf-8') as f:
                headers = json.load(f) or []
            for h in headers:
                b = os.path.basename(h)
                base_index.setdefault(b, set()).add(os.path.dirname(h))
        except Exception as e:
            logging.info(f"Fehler beim Laden von Include-Pfaden {proj_file}: {e}")
            headers = []
            base_index = {}

    _INC_CACHE[project_name] = {"headers": headers, "base_index": base_index}
    return headers, base_index

def get_method_name(cursor):
    """
    Return the display name of a method cursor.

    Args:
        cursor (cindex.Cursor): A Clang cursor representing a function or method declaration.

    Returns:
        str: The method's display name.
    """
    return cursor.displayname

def get_project_name(source_path):
    """
    Return the project name extracted from a source path.

    Args:
        source_path (str): File or directory path of the project source code.

    Returns:
        str: The base name of the normalized source path.
    """
    
    path = os.path.normpath(source_path)
    basename = os.path.basename(path)
    parent = os.path.basename(os.path.dirname(path))

    if basename.lower() == 'work' and parent:
        return parent
    # If parent folder already encodes project and ID (e.g., 'proj_ID'), and basename equals proj,
    # avoid duplication and return parent only
    if parent and (parent.startswith(f"{basename}_") or parent.endswith(f"_{basename}")):
        return parent
    # Otherwise include both parent and basename
    if parent:
        return f"{parent}_{basename}"
    return basename

def print_json(solution, source_path):
    """
    Serialize the metrics solution to a JSON file in the data/metrics directory.

    Args:
        solution (dict): Nested dictionary mapping file paths and method names to metrics values.
        source_path (str): The path to the analyzed source directory (used to derive output filename).

    Returns:
        None
    """
    output_file = f"{get_project_name(source_path)}.json"

    destination_path = os.path.join(os.getcwd(), "data", "metrics", output_file)

    with open(destination_path, "w") as f:
        # Serialize with dumps, avoid escaped forward slashes
        json_str = json.dumps(solution, indent=2, ensure_ascii=False)
        json_str = json_str.replace('\\/', '/')
        f.write(json_str)
    
def get_source_files(source_path, *, skip_dirs=None):
    """
    Recursively collect all C/C++ source file paths under the given directory.
    """
    source_path = os.path.abspath(source_path)
    source_files = []

    # Use only the user-provided skip_dirs. If None, no directories are skipped.
    skip_dirs = set(skip_dirs or [])

    if os.path.isdir(source_path):
        for root, dirs, files in os.walk(source_path, followlinks=False):
            # Filter directories in-place according to skip_dirs
            if skip_dirs:
                dirs[:] = [d for d in dirs if d not in skip_dirs]

            for f in files:
                if not f.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx")):
                    continue
                path = os.path.join(root, f)

                # Keep only regular existing files; skip broken symlinks
                if not os.path.exists(path):
                    continue
                if os.path.islink(path) and not os.path.exists(os.path.realpath(path)):
                    # Broken symlink
                    continue
                if not os.path.isfile(path):
                    continue

                source_files.append(path)

    return source_files

def _data_path(*parts):
    return os.path.join(DATA_ROOT, *parts)

def _slug(s: str) -> str:
    return re.sub(r'[^0-9A-Za-z_]+', '_', s)

def _short_hash(s: str) -> str:
    return hashlib.sha1(s.encode("utf-8")).hexdigest()[:8]

def _looks_like_cxx_header(text_sample: str) -> bool:
    # simple Heuristik: reicht für >90% der Fälle
    needles = ('template<', 'namespace ', 'class ', 'std::', 'using ', '#include <vector>',
               '#include <string>', '#include <array>', '#include <cstdint>')
    t = text_sample
    return any(n in t for n in needles)

def parse_file(source_file, project_name):
    try:
        # Existenz/Regulärcheck (schützt gegen ENOENT)
        if not (os.path.exists(source_file) and os.path.isfile(source_file)):
            logging.info(f"Skip non-regular or missing file: {source_file}")
            return None

        # Sprachwahl
        ext = os.path.splitext(source_file)[1].lower()
        is_cxx = ext in ('.cpp', '.cc', '.cxx', '.hpp', '.hh', '.hxx')

        # Heuristik für .h: kurzer Read
        if ext == '.h':
            try:
                with open(source_file, 'r', encoding='utf-8', errors='ignore') as f:
                    sample = f.read(4000)
                if _looks_like_cxx_header(sample):
                    is_cxx = True
            except Exception:
                pass

        args = ['-std=c++17', '-x', 'c++'] if is_cxx else ['-std=c11', '-x', 'c']

        # Includes im File scannen
        include_names = set()
        try:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as src_f:
                for line in src_f:
                    m = INCLUDE_RE.search(line)
                    if m:
                        inc = m.group(2)
                        include_names.add(inc)
        except Exception as e:
            logging.info(f"Error reading includes from {source_file}: {e}")

        # Project includes
        includes_dir = _data_path('includes')
        headers, base_index = _get_project_includes(project_name)

        # Pfadbewusstes Matching der echten Header → richtige Include-Roots ableiten
        missing = []
        include_roots = set()

        def _norm(p: str) -> str:
            return p.replace('\\', '/')

        for inc_name in include_names:
            inc_norm = _norm(inc_name)

            # 1) Pfadbewusst: Headerpfad als Suffix matchen (deckt "config/foo.h" ab)
            path_matches = [
                h for h in headers
                if _norm(h).endswith('/' + inc_norm) or _norm(h).endswith(inc_norm)
            ]
            if path_matches:
                for h in path_matches:
                    h_norm = _norm(h)
                    # Include-Root = voller Pfad minus "config/foo.h"
                    root = h_norm[: -len(inc_norm)].rstrip('/\\')
                    if root:
                        include_roots.add(root)
                continue

            # 2) Fallback: nur Basename (für Fälle ohne Unterordner im Include)
            base = os.path.basename(inc_name)
            dirs = base_index.get(base)
            if dirs:
                for d in dirs:
                    include_roots.add(d)
            else:
                missing.append(inc_name)

        # am Ende einmalig die -I Pfade anhängen
        for inc_dir in sorted(include_roots):
            args.extend(['-I', inc_dir])

        # Missing-Includes loggen unter data/logs/...
        if missing:
            miss_dir = _data_path('logs', 'missing_includes', project_name)
            os.makedirs(miss_dir, exist_ok=True)
            base = os.path.basename(source_file)
            stem, _ext = os.path.splitext(base)
            miss_file = os.path.join(miss_dir, f"{stem}-{_short_hash(os.path.abspath(source_file))}.json")
            with open(miss_file, 'w', encoding='utf-8') as mf:
                json.dump(missing, mf, indent=2, ensure_ascii=False)

        # robuste Defaults
        args.extend([
            '-ferror-limit=0',
            '-Wno-unknown-attributes',
            '-Wno-pragma-once-outside-header',
        ])

        # Needed for macro filtering; brings macro definition/instantiation cursors into the AST
        args.extend(['-Xclang', '-detailed-preprocessing-record'])

        tu = index.parse(
            source_file,
            args=args,
            options=TranslationUnit.PARSE_INCOMPLETE
        )
    except Exception as e:
        logging.getLogger("metrics_error_logger").error(f"Failed to parse {source_file}: {e}")
        return None

    return tu

def is_function_like(cursor):
    """
    Check if a cursor represents a function-like declaration (functions, methods, constructors, etc.).

    Args:
        cursor (cindex.Cursor): Clang cursor to inspect.

    Returns:
        bool: True if the cursor is a definition of a function-like entity, False otherwise.
    """
    return (
        cursor.is_definition() and
        cursor.kind in {
            CursorKind.FUNCTION_DECL,
            CursorKind.CXX_METHOD,
            CursorKind.CONSTRUCTOR,
            CursorKind.DESTRUCTOR,
            CursorKind.FUNCTION_TEMPLATE
        }
    )
    

# ---------------------------------------------------------------------------
# Delegation: expose metric function names from leopard_metrics
calculate_cyclomatic_complexity = leopard_metrics.calculate_cyclomatic_complexity
calculate_number_of_loops = leopard_metrics.calculate_number_of_loops
calculate_number_of_nested_loops = leopard_metrics.calculate_number_of_nested_loops
calculate_max_nesting_loop_depth = leopard_metrics.calculate_max_nesting_loop_depth
calculate_number_of_parameter_variables = leopard_metrics.calculate_number_of_parameter_variables
calculate_number_of_callee_parameter_variables = leopard_metrics.calculate_number_of_callee_parameter_variables
calculate_number_of_pointer_arithmetic = leopard_metrics.calculate_number_of_pointer_arithmetic
calculate_number_of_variables_involved_in_pointer_arithmetic = leopard_metrics.calculate_number_of_variables_involved_in_pointer_arithmetic
calculate_max_pointer_arithmetic_variable_is_involved_in = leopard_metrics.calculate_max_pointer_arithmetic_variable_is_involved_in
calculate_number_of_nested_control_structures = leopard_metrics.calculate_number_of_nested_control_structures
calculate_maximum_nesting_level_of_control_structures = leopard_metrics.calculate_maximum_nesting_level_of_control_structures
calculate_maximum_of_control_dependent_control_structures = leopard_metrics.calculate_maximum_of_control_dependent_control_structures
calculate_maximum_of_data_dependent_control_structures = leopard_metrics.calculate_maximum_of_data_dependent_control_structures
calculate_number_of_if_structures_without_else = leopard_metrics.calculate_number_of_if_structures_without_else
calculate_number_of_variables_involved_in_control_predicates = leopard_metrics.calculate_number_of_variables_involved_in_control_predicates

def _iter_function_nodes_in_file(root_cursor, source_file):
    """Yield only function-like cursors whose location belongs to source_file.

    Traverses only container nodes declared in the same file to avoid
    descending into included headers. This prunes the AST substantially
    versus cursor.walk_preorder().
    """
    want = os.path.abspath(source_file)

    def _same_file(node) -> bool:
        loc = getattr(node, "location", None)
        if loc is None:
            return False
        f = getattr(loc, "file", None)
        if f is None:
            return False
        try:
            return os.path.abspath(f.name) == want
        except Exception:
            return False

    containers = {
        CursorKind.TRANSLATION_UNIT,
        CursorKind.NAMESPACE,
        CursorKind.STRUCT_DECL,
        CursorKind.CLASS_DECL,
        CursorKind.UNION_DECL,
        CursorKind.CLASS_TEMPLATE,
    }

    stack = [root_cursor]
    while stack:
        node = stack.pop()

        # Only emit functions that belong to the current source file
        if is_function_like(node):
            if _same_file(node):
                yield node
            continue  # do not descend into function bodies

        # Descend only through container nodes, and only when they are in the same file
        if node.kind in containers:
            # For TU we don't have a meaningful file; select children explicitly
            for child in node.get_children():
                if is_function_like(child):
                    if _same_file(child):
                        stack.append(child)
                    continue
                if child.kind in containers and _same_file(child):
                    stack.append(child)


def run(source_path, skip_existing=False):
    """
    Main function to run the metrics on the given source path.
    It parses the source files, calculates metrics, and writes them to a JSON file.
    Result is written to data/metrics/<project_name>.json.

    Args:
        source_path (str): The path to the source code directory.
        skip_existing (bool): If True, skip calculation if metrics file already exists.

    Returns:
        None
    """

    # solution = Dict[FileName -> Dict[MethodName -> MetricsStats]]
    solution = {}
    # timings = Dict[MetricKey -> List[Entry]]
    # Entry for function-level metric: {file, method, seconds}
    # Entry for file-level metric: {file, seconds}
    timings = {}

    def add_timing(metric_key: str, entry: dict):
        key = metric_key.strip()
        if not key:
            return
        timings.setdefault(key, []).append(entry)

    def write_timings():
        times_dir = os.path.join(os.getcwd(), "data", "times")
        os.makedirs(times_dir, exist_ok=True)

        def _slug_name(name: str) -> str:
            return re.sub(r"[^0-9A-Za-z_]+", "_", name).strip("_") or "metric"

        for metric_key, entries in timings.items():
            # Persist only the times as a flat array, aggregated across runs
            times_only = [float(e.get("seconds", 0.0)) for e in entries]
            fname = f"{_slug_name(metric_key)}.json"
            out_path = os.path.join(times_dir, fname)
            try:
                # Load existing times and extend
                existing: list[float] = []
                if os.path.exists(out_path):
                    try:
                        with open(out_path, "r", encoding="utf-8") as rf:
                            data = json.load(rf)
                            if isinstance(data, list):
                                existing = [float(x) for x in data]
                    except Exception:
                        existing = []
                merged = existing + times_only
                with open(out_path, "w", encoding="utf-8") as f:
                    json_str = json.dumps(merged, indent=2, ensure_ascii=False)
                    json_str = json_str.replace('\\/', '/')
                    f.write(json_str)
            except Exception as e:
                logging.info(f"Failed to write timing file {out_path}: {e}")

    source_files = get_source_files(source_path)

    project_name = get_project_name(source_path)

    # Clear old missing_includes logs for this project
    missing_root = os.path.join(os.getcwd(), 'data', 'logs', 'missing_includes', project_name)
    if os.path.isdir(missing_root):
        shutil.rmtree(missing_root)

    # Ensure metrics output directory
    metrics_dir = os.path.join(os.getcwd(), "data", "metrics")
    output_file = f"{project_name}.json"
    destination_path = os.path.join(metrics_dir, output_file)

    if skip_existing and os.path.exists(destination_path):
        return

    for source_file in source_files:
        tu = parse_file(source_file, project_name)
        if tu is None:
            continue  # Skip files that failed to parse
        cursor = tu.cursor

        # Pre-fill file entry with project (git) metrics, timed individually
        vals = {"NumChanges": 0, "LinesChanged": 0, "LinesNew": 0, "NumDevs": 0}
        # NumChanges
        try:
            t0 = time.perf_counter(); vals["NumChanges"] = project_metrics.calculate_num_changes(source_file); t1 = time.perf_counter()
            add_timing("NumChanges", {"seconds": max(0.0, t1 - t0)})
        except Exception:
            vals["NumChanges"] = 0
        # LinesChanged
        try:
            t0 = time.perf_counter(); vals["LinesChanged"] = project_metrics.calculate_lines_changed(source_file); t1 = time.perf_counter()
            add_timing("LinesChanged", {"seconds": max(0.0, t1 - t0)})
        except Exception:
            vals["LinesChanged"] = 0
        # LinesNew
        try:
            t0 = time.perf_counter(); vals["LinesNew"] = project_metrics.calculate_lines_new(source_file); t1 = time.perf_counter()
            add_timing("LinesNew", {"seconds": max(0.0, t1 - t0)})
        except Exception:
            vals["LinesNew"] = 0
        # NumDevs
        try:
            t0 = time.perf_counter(); vals["NumDevs"] = project_metrics.calculate_num_devs(source_file); t1 = time.perf_counter()
            add_timing("NumDevs", {"seconds": max(0.0, t1 - t0)})
        except Exception:
            vals["NumDevs"] = 0

        file_proj_metrics = vals

        solution[source_file] = {"__project_metrics__": file_proj_metrics}

        for c in _iter_function_nodes_in_file(cursor, source_file):
            try:
                method_name = get_method_name(c)

                # LOC
                t0 = time.perf_counter(); loc = calculate_loc(c); t1 = time.perf_counter()
                add_timing("lines of code", {
                    "file": source_file,
                    "method": method_name,
                    "seconds": max(0.0, t1 - t0),
                })

                # # Leopard C
                t0 = time.perf_counter(); cyclomatic_complexity  = calculate_cyclomatic_complexity(c); t1 = time.perf_counter()
                add_timing("cyclomatic complexity", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_loops = calculate_number_of_loops(c); t1 = time.perf_counter()
                add_timing("number of loops", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_nested_loops = calculate_number_of_nested_loops(c); t1 = time.perf_counter()
                add_timing("number of nested loops", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); max_nesting_loop_depth = calculate_max_nesting_loop_depth(c); t1 = time.perf_counter()
                add_timing("max nesting loop depth", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                # # Leopard V
                t0 = time.perf_counter(); number_of_parameter_variables = calculate_number_of_parameter_variables(c); t1 = time.perf_counter()
                add_timing("number of parameter variables", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_callee_parameter_variables = calculate_number_of_callee_parameter_variables(c); t1 = time.perf_counter()
                add_timing("number of callee parameter variables", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_pointer_arithmetic = calculate_number_of_pointer_arithmetic(c); t1 = time.perf_counter()
                add_timing("number of pointer arithmetic", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_variables_involved_in_pointer_arithmetic = calculate_number_of_variables_involved_in_pointer_arithmetic(c); t1 = time.perf_counter()
                add_timing("number of variables involved in pointer arithmetic", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); max_pointer_arithmetic_variable_is_involved_in = calculate_max_pointer_arithmetic_variable_is_involved_in(c); t1 = time.perf_counter()
                add_timing("max pointer arithmetic variable is involved in", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_nested_control_structures = calculate_number_of_nested_control_structures(c); t1 = time.perf_counter()
                add_timing("number of nested control structures", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); maximum_nesting_level_of_control_structures = calculate_maximum_nesting_level_of_control_structures(c); t1 = time.perf_counter()
                add_timing("maximum nesting level of control structures", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); maximum_of_control_dependent_control_structures = calculate_maximum_of_control_dependent_control_structures(c); t1 = time.perf_counter()
                add_timing("maximum of control dependent control structures", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); maximum_of_data_dependent_control_structures = calculate_maximum_of_data_dependent_control_structures(c); t1 = time.perf_counter()
                add_timing("maximum of data dependent control structures", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_if_structures_without_else = calculate_number_of_if_structures_without_else(c); t1 = time.perf_counter()
                add_timing("number of if structures without else", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})

                t0 = time.perf_counter(); number_of_variables_involved_in_control_predicates = calculate_number_of_variables_involved_in_control_predicates(c); t1 = time.perf_counter()
                add_timing("number of variables involved in control predicates", {"file": source_file, "method": method_name, "seconds": max(0.0, t1 - t0)})
            except Exception as e:
                logging.info(f"Error for {c.displayname} in {source_file}: {e}")
                logging.info(f"Stack trace: {traceback.format_exc()}")
                continue

            solution[source_file][method_name] = {
                'lines of code': loc,
                'cyclomatic complexity': cyclomatic_complexity,
                'number of loops': number_of_loops,
                'number of nested loops': number_of_nested_loops,
                'max nesting loop depth': max_nesting_loop_depth,
                'number of parameter variables': number_of_parameter_variables,
                'number of callee parameter variables': number_of_callee_parameter_variables,
                'number of pointer arithmetic' : number_of_pointer_arithmetic,
                'number of variables involved in pointer arithmetic': number_of_variables_involved_in_pointer_arithmetic,
                'max pointer arithmetic variable is involved in': max_pointer_arithmetic_variable_is_involved_in,
                'number of nested control structures': number_of_nested_control_structures,
                'maximum nesting level of control structures': maximum_nesting_level_of_control_structures,
                'maximum of control dependent control structures': maximum_of_control_dependent_control_structures,
                'maximum of data dependent control structures': maximum_of_data_dependent_control_structures,
                'number of if structures without else': number_of_if_structures_without_else,
                'number of variables involved in control predicates': number_of_variables_involved_in_control_predicates
            }
                
    print_json(solution, source_path)
    # Write per-metric timing JSONs under data/times (one file per metric type)
    try:
        write_timings()
    except Exception as e:
        logging.info(f"Failed to write timings: {e}")

def run_test(source_file, metric_function):
    """
    Run a specific metric function on a single source file with a minimal local parser.

    This uses its own lightweight parse routine and adds the system Clang builtin
    headers include path: /usr/lib/clang/<VER>/include/.

    Args:
        source_file (str): The path to the source code file.
        metric_function (function): The metric function to run.

    Returns:
        list[tuple[str, any]]: List of method names and their corresponding metric values.
    """

    def _find_clang_builtin_include_dir() -> str | None:
        base = "/usr/lib/clang"
        try:
            if not os.path.isdir(base):
                return None
            versions = [d for d in os.listdir(base) if os.path.isdir(os.path.join(base, d))]
            if not versions:
                return None
            # Choose the highest-looking version
            import re
            def ver_key(s: str):
                nums = [int(x) for x in re.findall(r"\d+", s)]
                return nums or [0]
            best = sorted(versions, key=ver_key)[-1]
            inc = os.path.join(base, best, "include")
            return inc if os.path.isdir(inc) else None
        except Exception:
            return None

    def _parse_file_for_test(path: str):
        try:
            if not (os.path.exists(path) and os.path.isfile(path)):
                return None

            ext = os.path.splitext(path)[1].lower()
            is_cxx = ext in (".cpp", ".cc", ".cxx", ".hpp", ".hh", ".hxx")
            args = ["-std=c++17", "-x", "c++"] if is_cxx else ["-std=c11", "-x", "c"]

            # Add builtin headers from system Clang
            inc_dir = _find_clang_builtin_include_dir()
            if inc_dir:
                args.extend(["-isystem", inc_dir])

            # Keep forgiving defaults
            args.extend([
                "-ferror-limit=0",
                "-Wno-unknown-attributes",
                "-Wno-pragma-once-outside-header",
            ])

            args.extend(["-Xclang", "-detailed-preprocessing-record"])

            tu = index.parse(path, args=args, options=TranslationUnit.PARSE_INCOMPLETE)
            return tu
        except Exception:
            return None

    tu = _parse_file_for_test(source_file)
    if tu is None:
        return []
    cursor = tu.cursor

    result = []
    for c in cursor.get_children():
        if is_function_like(c):
            method_name = get_method_name(c)
            metric_value = metric_function(c)
            result.append((method_name, metric_value))

    return result
