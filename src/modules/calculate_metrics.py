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

clang_path   = os.path.abspath(os.path.join(os.getcwd(), "llvm-project-llvmorg-20.1.8", "clang", "bindings", "python"))
logging.info(f"clang_path: {clang_path}")
sys.path.insert(0, clang_path)

from clang import cindex
from clang.cindex import TokenKind, CursorKind, TypeKind, TranslationUnit

libclang_path =  os.path.abspath(os.path.join(os.getcwd(), "LLVM-20.1.8-Linux-X64", "lib", "libclang.so"))
logging.info(f"libclang_path:  {libclang_path}")
cindex.Config.set_library_file(libclang_path)
cindex.Config.set_compatibility_check(False)

cindex.Config.set_library_path(os.path.dirname(libclang_path))
logging.info(cindex.__file__)

# Initialize Clang index
index = cindex.Index.create()
DATA_ROOT = os.path.join(os.getcwd(), "data")

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
    Skips broken symlinks and common test/third_party dirs by default.
    """
    source_path = os.path.abspath(source_path)
    source_files = []

    # Standardmäßig noisy/verursachende Ordner ausschließen
    default_skips = {
        'internal', 'third_party', 'thirdparty', 'tests', 'test',
        'googletest', 'gtest', 'benchmark', 'benchmarks', 'examples', 'tools'
    }
    skip_dirs = set(skip_dirs or []) | default_skips

    if os.path.isdir(source_path):
        for root, dirs, files in os.walk(source_path, followlinks=False):
            # Verzeichnisse filtern (in-place, wirkt auf os.walk)
            dirs[:] = [d for d in dirs if d not in skip_dirs]

            for f in files:
                if not f.endswith((".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hh", ".hxx")):
                    continue
                path = os.path.join(root, f)

                # Nur reguläre existierende Dateien behalten
                if not os.path.exists(path):
                    continue
                if os.path.islink(path) and not os.path.exists(os.path.realpath(path)):
                    # Kaputter Symlink
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
        include_pattern = re.compile(r'#\s*include\s*([<"])([^">]+)[">]')
        include_names = set()
        try:
            with open(source_file, 'r', encoding='utf-8', errors='ignore') as src_f:
                for line in src_f:
                    m = include_pattern.search(line)
                    if m:
                        inc = m.group(2)
                        include_names.add(inc)
        except Exception as e:
            logging.info(f"Error reading includes from {source_file}: {e}")

        # Project includes
        includes_dir = _data_path('includes')
        headers = []
        proj_file = os.path.join(includes_dir, f"{project_name}.json")
        if os.path.exists(proj_file):
            try:
                with open(proj_file, 'r', encoding='utf-8') as f:
                    headers.extend(json.load(f))
            except Exception as e:
                logging.info(f"Fehler beim Laden von Include-Pfaden {proj_file}: {e}")

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
            base_matches = [h for h in headers if os.path.basename(h) == base]
            if base_matches:
                for h in base_matches:
                    include_roots.add(os.path.dirname(h))
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

        tu = index.parse(
            source_file,
            args=args,
            options=TranslationUnit.PARSE_INCOMPLETE
        )
    except Exception as e:
        logging.getLogger("metrics_error_logger").error(f"Failed to parse {source_file}: {e}")
        return None

    return tu

def calculate_loc(cursor):
    """
    Calculate lines of code (excluding comments and blanks) for a function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of distinct non-comment, non-blank lines in the function body.
    """
    tu = cursor.translation_unit
    # gather all non-comment, non-whitespace tokens in this cursor’s extent
    tokens = tu.get_tokens(extent=cursor.extent)
    locLines = set()
    for tok in tokens:
        # skip comments
        if tok.kind == TokenKind.COMMENT:
            continue
        
        # skip any token that is purely whitespace
        try:
            text = tok.spelling
        except Exception as e:
            continue
        
        if not text.strip():
            continue
        
        # record the source line
        locLines.add(tok.location.line)
    return len(locLines)

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
    
def calculate_cyclomatic_complexity(cursor):
    """
    Approximate cyclomatic complexity by counting decision points and entry.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Cyclomatic complexity (count of branches plus one).
    """
    tu = cursor.translation_unit
    complexity = 1  # entry point

    for tok in tu.get_tokens(extent=cursor.extent):
        try:
            s = tok.spelling
        except Exception as e:
            continue
        # count keywords that introduce branching
        if tok.kind == TokenKind.KEYWORD and s in ('if', 'for', 'while', 'case', 'catch'):
            complexity += 1
        # count ternary operator
        elif tok.kind == TokenKind.PUNCTUATION and s == '?':
            complexity += 1

    return complexity

def calculate_number_of_loops(cursor):
    """
    Count all loop statements within a function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Total number of loop constructs (for, while, do, ranged-for).
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT
    }

    count = 0

    def visit(node):
        nonlocal count
        if node.kind in loop_kinds:
            count += 1
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return count

def calculate_number_of_nested_loops(cursor):
    """
    Count loop statements that contain at least one nested loop.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of loops that have another loop in their subtree.
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT
    }

    nested_count = 0

    def contains_loop_in_subtree(node):
        """
        Check if the subtree rooted at node contains any loop.
        """
        for child in node.get_children():
            if child.kind in loop_kinds:
                return True
            if contains_loop_in_subtree(child):
                return True
        return False

    def visit(node):
        nonlocal nested_count

        # If this node is a loop, check if it contains another loop in its subtree
        if node.kind in loop_kinds:
            if contains_loop_in_subtree(node):
                nested_count += 1
            return

        # Otherwise, continue visiting children
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return nested_count

def calculate_max_nesting_loop_depth(cursor):
    """
    Determine the maximum depth of nested loops in a function.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum nesting depth of loops.
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT
    }
    
    max_depth = 0
    
    def visit(node, depth=0):
        nonlocal max_depth
        
        if node.kind in loop_kinds:
            depth += 1
            max_depth = max(max_depth, depth)
            
        for child in node.get_children():
            visit(child, depth)
            
    visit(cursor)
    return max_depth

def calculate_number_of_parameter_variables(cursor):
    """
    Count parameters declared by the function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of parameters the function takes.
    """
    return len(list(cursor.get_arguments()))

def calculate_number_of_callee_parameter_variables(cursor):
    """
    Count distinct variables used as arguments in calls to other functions within the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of distinct callee parameter variables used in the function.
    """
    callee_param_vars = set()
    
    def extractVars(node):
        # If this node is a variable reference, record it
        if node.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = node.referenced
            # If the reference is a variable declaration, parameter, or field declaration
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                callee_param_vars.add(node.spelling)
        # Recurse into children
        for child in node.get_children():
            extractVars(child)

    def visit(node):
        if node.kind == CursorKind.CALL_EXPR:
            args = list(node.get_arguments())

            for arg in args:
                extractVars(arg)

        for child in node.get_children():
            visit(child)
            
    visit(cursor)
    return len(callee_param_vars)

def calculate_number_of_pointer_arithmetic(cursor):
    """
    Count the number of pointer arithmetic operations in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of pointer arithmetic operations (binary, unary, compound) in the function.
    """
    count = 0
    binary_arithmetic_ops = {'+', '-', '/', '^', '|'}
    compound_pointer_ops = {'+=', '-=', '*=', '/=', '^=', '&=', '|='}
    unary_pointer_ops = {'++', '--'}

    def visit(node, parent=None):
        nonlocal count

        # 1) Binary Operator
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                # Check if we have a pointer-integer combination
                is_ptr_int_combo = ((lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER))

                # Check if we have a pointer-pointer subtraction
                is_ptr_ptr_sub = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)

                # Check if the operation is a binary arithmetic operation
                if is_ptr_int_combo:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in binary_arithmetic_ops:
                            count += 1
                            break
                elif is_ptr_ptr_sub and \
                     lhs.kind != CursorKind.BINARY_OPERATOR and \
                     rhs.kind != CursorKind.BINARY_OPERATOR:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '-':
                            count += 1
                            break

        # 2) Compound Assignment
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                # Check if we have a pointer-integer combination
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    for tok in node.get_tokens():
                        # Check if the operation is a compound assignment
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in compound_pointer_ops:
                            count += 1
                            break

        # 3) Unary Operator
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                # Check if the base is a pointer type 
                if child.type.kind == TypeKind.POINTER:
                    for tok in node.get_tokens():
                        # Check if the operation is a unary pointer operation
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in unary_pointer_ops:
                            count += 1
                            break

        # Recurse into children
        for child in node.get_children():
            visit(child, node)

    visit(cursor)
    return count
    
def calculate_number_of_variables_involved_in_pointer_arithmetic(cursor):
    """
    Count the number of distinct variables involved in pointer arithmetic operations
    within the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of distinct variables involved in pointer arithmetic.
    """
    vars_nvolved = set()

    # Helper function to collect variable names from a subnode
    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (
                CursorKind.VAR_DECL,
                CursorKind.PARM_DECL,
                CursorKind.FIELD_DECL
            ):
                vars_nvolved.add(subnode.spelling)
        for child in subnode.get_children():
            collect_vars(child)

    def visit(node):
        # 1) BINARY_OPERATOR
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                # pointer–integer combination
                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )

                # pointer–pointer subtraction
                is_ptr_ptr_sub = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)

                if is_ptr_int_combo:
                    # whichever side is the pointer, collect its variable refs
                    if lhs_kind == TypeKind.POINTER:
                        collect_vars(lhs)
                    else:
                        collect_vars(rhs)
                elif is_ptr_ptr_sub and \
                     lhs.kind != CursorKind.BINARY_OPERATOR and \
                     rhs.kind != CursorKind.BINARY_OPERATOR:
                    collect_vars(lhs)
                    collect_vars(rhs)

        # 2) COMPOUND_ASSIGNMENT_OPERATOR
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                # pointer on lhs, integer (or non-pointer) on rhs
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_vars(lhs)

        # 3) UNARY_OPERATOR (e.g. ++ptr or ptr++)
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                if child.type.kind == TypeKind.POINTER:
                    collect_vars(child)

        # Recurse into children
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return len(vars_nvolved)

def calculate_max_pointer_arithmetic_variable_is_involved_in(cursor):
    """
    Calculate the maximum number of pointer arithmetic operations a variable is involved in
    within the given function cursor, with debug output.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum number of pointer arithmetic operations for any single variable.
    """
    var_counts = {}

    # Helper function to collect variable names from a subnode
    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (
                CursorKind.VAR_DECL,
                CursorKind.PARM_DECL,
                CursorKind.FIELD_DECL
            ):
                name = subnode.spelling
                if name not in var_counts:
                    var_counts[name] = 0
                var_counts[name] += 1

        for child in subnode.get_children():
            collect_vars(child)

    def visit(node):
        # 1) Binary Operator
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )

                is_ptr_ptr_sub = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)

                if is_ptr_int_combo:
                    # Sammle Variablen im „Pointer“-Teil
                    if lhs_kind == TypeKind.POINTER:
                        collect_vars(lhs)
                    else:
                        collect_vars(rhs)
                elif is_ptr_ptr_sub and \
                     lhs.kind != CursorKind.BINARY_OPERATOR and \
                     rhs.kind != CursorKind.BINARY_OPERATOR:
                    collect_vars(lhs)
                    collect_vars(rhs)

        # 2) Compound Assignment Operator
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_vars(lhs)

        # 3) Unary Operator
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                if child.type.kind == TypeKind.POINTER:
                    collect_vars(child)

        # Recurse into children
        for child in node.get_children():
            visit(child)

    visit(cursor)

    if var_counts:
        return max(var_counts.values())
    else:
        return 0

def calculate_number_of_nested_control_structures(cursor):
    """
    Calculate the number of nested control structures in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of control structures nested within other control structures.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT
    }

    nested_count = 0

    def contains_control_in_subtree(node):
        """
        Check if the subtree rooted at `node` contains any control structure.
        """
        for child in node.get_children():
            if child.kind in control_kinds:
                return True
            if contains_control_in_subtree(child):
                return True
        return False

    def visit(node):
        nonlocal nested_count
        if node.kind in control_kinds:
            if contains_control_in_subtree(node):
                nested_count += 1
            return

        for child in node.get_children():
            visit(child)

    visit(cursor)
    return nested_count

def calculate_maximum_nesting_level_of_control_structures(cursor):
    """
    Calculate the maximum nesting level of control structures in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum nesting level of control structures.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT
    }

    max_depth = 0

    def visit(node, depth=0):
        nonlocal max_depth
        # If node is a control structure, increment depth and update maxDepth
        if node.kind in control_kinds:
            depth += 1
            max_depth = max(max_depth, depth)

        # Recurse into children, passing along the updated depth
        for child in node.get_children():
            visit(child, depth)

    visit(cursor, 0)
    return max_depth

def calculate_maximum_of_control_dependent_control_structures(cursor):
    """
    Calculate the maximum of control-dependent control structures in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum number of control structures in the subtree of any single control structure.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT
    }

    def count_control_in_subtree(node):
        """
        Recursively count all control-structure nodes in the subtree rooted at `node`,
        including `node` itself if it is a control-structure.
        """
        count = 1 if node.kind in control_kinds else 0

        for child in node.get_children():
            count += count_control_in_subtree(child)
        return count

    max_count = 0

    def visit(node):
        nonlocal max_count
        if node.kind in control_kinds:
            subtree_count = count_control_in_subtree(node)
            if subtree_count > max_count:
                max_count = subtree_count
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return max_count

def calculate_maximum_of_data_dependent_control_structures(cursor):
    """
    Calculate the maximum of data-dependent control structures in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum number of data-dependent control structures in the function.
    """

    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT
    }

    # Helper: collect all variable names (from DECL_REF_EXPR or MEMBER_REF_EXPR)
    # in the subtree rooted at `node`.
    def collect_vars(subnode, var_set):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (
                CursorKind.VAR_DECL,
                CursorKind.PARM_DECL,
                CursorKind.FIELD_DECL
            ):
                var_set.add(subnode.spelling)
        for child in subnode.get_children():
            collect_vars(child, var_set)

    # Map variable name → how many control-statements' conditions reference it
    var_counts = {}

    # Process a single control-structure node: find its "condition" subtree
    # and collect all distinct variables used there.
    def process_control(node):
        # Determine which child node represents the "condition" expression,
        # depending on the kind of control statement.
        cond = None
        children = list(node.get_children())

        if node.kind == CursorKind.IF_STMT:
            # children: [ condition , then-branch, else-branch? ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.WHILE_STMT:
            # children: [ condition, body ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.FOR_STMT:
            # children: [ init, condition, increment, body ]
            if len(children) >= 2:
                cond = children[1]

        elif node.kind == CursorKind.DO_STMT:
            # children: [ body, condition ]
            if len(children) >= 2:
                cond = children[1]

        elif node.kind == CursorKind.SWITCH_STMT:
            # children: [ condition, body ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.CXX_FOR_RANGE_STMT:
            # children: [ loop-var, range-init, body ]
            # the "range-init" acts as the controlling expression
            if len(children) >= 2:
                cond = children[1]

        # If we found a condition subtree, extract all variable names from it.
        if cond is not None:
            local_vars = set()
            collect_vars(cond, local_vars)
            for v in local_vars:
                var_counts[v] = var_counts.get(v, 0) + 1

    def visit(node):
        if node.kind in control_kinds:
            process_control(node)
        for child in node.get_children():
            visit(child)

    visit(cursor)

    # If no variable ever appeared in a condition, return 0.
    if not var_counts:
        return 0

    return max(var_counts.values())

def calculate_number_of_if_structures_without_else(cursor):
    """
    Calculate the number of if structures without an else branch in the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of if structures lacking an else branch.
    """
    count = 0

    def visit(node):
        nonlocal count
        if node.kind == CursorKind.IF_STMT:
            # children of IF_STMT: [ condition, then-branch, else-branch? ]
            children = list(node.get_children())
            # If there is no else-branch, there will be only 2 children (condition and then-branch)
            if len(children) < 3:
                count += 1
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return count

def calculate_number_of_variables_involved_in_control_predicates(cursor):
    """
    Count the number of variables involved in control predicates (conditions) within the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of distinct variables used in the conditions of control structures.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT
    }

    vars_in_conditions = set()

    def collect_vars(subnode):
        """
        Recursively collect any variable references (DECL_REF_EXPR or MEMBER_REF_EXPR)
        in the subtree rooted at subnode, and add their spellings to vars_in_conditions.
        """

        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (
                CursorKind.VAR_DECL,
                CursorKind.PARM_DECL,
                CursorKind.FIELD_DECL
            ):
                vars_in_conditions.add(subnode.spelling)

        for child in subnode.get_children():
            collect_vars(child)

    def process_control(node):
        """
        Given a control-structure node, identify its 'condition' subtree,
        then collect all variable names used in that subtree.
        """
        cond = None
        children = list(node.get_children())

        if node.kind == CursorKind.IF_STMT:
            # children: [ condition , then-branch, else-branch? ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.WHILE_STMT:
            # children: [ condition, body ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.FOR_STMT:
            # children: [ init, condition, increment, body ]
            if len(children) >= 2:
                cond = children[1]

        elif node.kind == CursorKind.DO_STMT:
            # children: [ body, condition ]
            if len(children) >= 2:
                cond = children[1]

        elif node.kind == CursorKind.SWITCH_STMT:
            # children: [ condition, body ]
            if children:
                cond = children[0]

        elif node.kind == CursorKind.CXX_FOR_RANGE_STMT:
            # children: [ loop-var, range-init, body ]
            # the "range-init" is the controlling expression
            if len(children) >= 2:
                cond = children[1]

        if cond is not None:
            collect_vars(cond)

    def visit(node):
        if node.kind in control_kinds:
            process_control(node)
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return len(vars_in_conditions)

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

        solution[source_file] = {}

        for c in cursor.walk_preorder():
            # Skip cursors that come from other files (headers, included sources).
            # We only want functions defined in the current source_file.
            loc = getattr(c, 'location', None)
            if loc is None or getattr(loc, 'file', None) is None:
                continue
            try:
                node_file = os.path.abspath(loc.file.name)
            except Exception:
                continue
            if node_file != os.path.abspath(source_file):
                # cursor originates from an included header or different file
                continue
            if is_function_like(c):
                try:
                    method_name = get_method_name(c)
                    # loc = calculate_loc(c)
                
                    # Leopard C
                    # cyclomatic_complexity  = calculate_cyclomatic_complexity(c)
                    # number_of_loops = calculate_number_of_loops(c)
                    # number_of_nested_loops = calculate_number_of_nested_loops(c)
                    # max_nesting_loop_depth = calculate_max_nesting_loop_depth(c)
                    
                    # Leopard V
                    number_of_parameter_variables = calculate_number_of_parameter_variables(c)
                    # number_of_callee_parameter_variables = calculate_number_of_callee_parameter_variables(c)
                    # number_of_pointer_arithmetic = calculate_number_of_pointer_arithmetic(c)
                    # number_of_variables_involved_in_pointer_arithmetic = calculate_number_of_variables_involved_in_pointer_arithmetic(c)
                    # max_pointer_arithmetic_variable_is_involved_in = calculate_max_pointer_arithmetic_variable_is_involved_in(c)
                    # number_of_nested_control_structures = calculate_number_of_nested_control_structures(c)
                    # maximum_nesting_level_of_control_structures = calculate_maximum_nesting_level_of_control_structures(c)
                    # maximum_of_control_dependent_control_structures = calculate_maximum_of_control_dependent_control_structures(c)
                    # maximum_of_data_dependent_control_structures = calculate_maximum_of_data_dependent_control_structures(c)
                    # number_of_if_structures_without_else = calculate_number_of_if_structures_without_else(c)
                    # number_of_variables_involved_in_control_predicates = calculate_number_of_variables_involved_in_control_predicates(c)
                except Exception as e:
                    logging.info(f"Error for {c.displayname} in {source_file}: {e}")
                    logging.info(f"Stack trace: {traceback.format_exc()}")
                    continue

                solution[source_file][method_name] = {
                    # 'lines of code': loc,
                    # 'cyclomatic complexity': cyclomatic_complexity,
                    # 'number of loops': number_of_loops,
                    # 'number of nested loops': number_of_nested_loops,
                    # 'max nesting loop depth': max_nesting_loop_depth,
                    'number of parameter variables': number_of_parameter_variables,
                    # 'number of callee parameter variables': number_of_callee_parameter_variables,
                    # 'number of pointer arithmetic' : number_of_pointer_arithmetic,
                    # 'number of variables involved in pointer arithmetic': number_of_variables_involved_in_pointer_arithmetic,
                    # 'max pointer arithmetic variable is involved in': max_pointer_arithmetic_variable_is_involved_in,
                    # 'number of nested control structures': number_of_nested_control_structures,
                    # 'maximum nesting level of control structures': maximum_nesting_level_of_control_structures,
                    # 'maximum of control dependent control structures': maximum_of_control_dependent_control_structures,
                    # 'maximum of data dependent control structures': maximum_of_data_dependent_control_structures,
                    # 'number of if structures without else': number_of_if_structures_without_else,
                    # 'number of variables involved in control predicates': number_of_variables_involved_in_control_predicates
                }
                
    print_json(solution, source_path)

def run_test(source_file, metric_function):
    """
    Run a specific metric function on the source file and print the result as JSON,
    in the same format as produced by run().

    Args:
        source_file (str): The path to the source code file.
        metric_function (function): The metric function to run.

    Returns:
        list[tuple[str, any]]: List of method names and their corresponding metric values.
    """

    tu = parse_file(source_file)
    cursor = tu.cursor

    result = []
    for c in cursor.get_children():
        if is_function_like(c):
            method_name = get_method_name(c)
            metric_value = metric_function(c)
            result.append((method_name, metric_value))

    return result
