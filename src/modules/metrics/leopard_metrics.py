"""
leopard_metrics.py

Concrete implementations of metric calculations operating on Clang cursors.
These functions are imported and used by modules.calculate_metrics.
"""

import weakref
from bisect import bisect_left, bisect_right
from typing import Dict, List, Optional, Tuple

from clang import cindex
from clang.cindex import TokenKind, CursorKind, TypeKind


# -----------------------
# Types and global caches
# -----------------------

_MacroDefinitions = Dict[str, bool]
_MacroExtents = List[Tuple[str, int, int, int, int]]
_MacroCacheEntry = Tuple[Optional[weakref.ReferenceType], Tuple[_MacroDefinitions, _MacroExtents]]
_MACRO_CACHE: Dict[int, _MacroCacheEntry] = {}
_MACRO_CACHE_ATTR = "_cvuln_macro_context"

# Cache for per-extents quick index:
# id(macro_extents) -> { file: {"intervals": [(sL,sC,eL,eC), ...],
#                               "starts":   [sL, ...],
#                               "end_pref": [max_endL up to i, ...]} }
_MACRO_EXTENTS_INDEX: Dict[int, Dict[str, Dict[str, List]]] = {}

# Common operator sets (single allocation)
_BINARY_PTR_INT_OPS = {"+", "-"}      # pointer +/- integer
_BINARY_PTR_PTR_OPS = {"-"}           # pointer - pointer
_COMPOUND_PTR_OPS = {"+=", "-="}      # pointer += integer, pointer -= integer
_UNARY_PTR_OPS = {"++", "--"}         # ++p / --p


# -----------------------
# Small helper primitives
# -----------------------

def _is_system_header_location(location):
    if location is None:
        return False
    attr = getattr(location, "is_in_system_header", None)
    if callable(attr):
        return bool(attr())
    return bool(attr)


def _is_system_header_cursor(cursor):
    if cursor is None:
        return False
    location = getattr(cursor, "location", None)
    return _is_system_header_location(location)


def _references_system_header(cursor):
    try:
        referenced = cursor.referenced
    except (AttributeError, ValueError, cindex.LibclangError):
        return False
    if referenced is None:
        return False
    return _is_system_header_cursor(referenced)


def _collect_macro_definitions(cursor, macro_map: _MacroDefinitions) -> None:
    """
    Iterative AST walk collecting macro definitions and whether they reside in system headers.
    """
    stack = [cursor]
    while stack:
        node = stack.pop()
        try:
            kind = node.kind
        except (AttributeError, cindex.LibclangError):
            continue

        if kind == CursorKind.MACRO_DEFINITION:
            name = node.spelling
            if name:
                macro_map[name] = _is_system_header_cursor(node)

        try:
            # Avoid recursion depth issues on large ASTs
            for child in node.get_children():
                stack.append(child)
        except (AttributeError, cindex.LibclangError):
            continue


def _collect_system_macro_extents(
    cursor,
    macro_definitions: _MacroDefinitions,
    extents: _MacroExtents,
) -> None:
    """
    Iterative AST walk collecting extents of MACRO_INSTANTIATIONs that are defined in system headers.
    """
    stack = [cursor]
    while stack:
        node = stack.pop()
        try:
            kind = node.kind
        except (AttributeError, cindex.LibclangError):
            continue

        if kind == CursorKind.MACRO_INSTANTIATION:
            name = node.spelling
            if name and macro_definitions.get(name):
                extent = node.extent
                start = getattr(extent, "start", None)
                end = getattr(extent, "end", None)
                if start and end and start.file and end.file:
                    extents.append(
                        (
                            start.file.name,
                            start.line,
                            start.column,
                            end.line,
                            end.column,
                        )
                    )

        try:
            for child in node.get_children():
                stack.append(child)
        except (AttributeError, cindex.LibclangError):
            continue


# -------- Macro extent indexing (performance critical) --------

def _build_macro_extent_index(macro_extents: _MacroExtents) -> Dict[str, Dict[str, List]]:
    """
    Build a per-file index to check membership in O(log n) by line,
    preserving exact behavior of the previous linear scan.

    For each file we store:
      - intervals: [(sL, sC, eL, eC), ...] sorted by (sL, sC)
      - starts:    [sL, ...]
      - end_pref:  prefix maximum of end_line to prune unrelated ranges quickly
    """
    per_file: Dict[str, List[Tuple[int, int, int, int]]] = {}
    for f, sL, sC, eL, eC in macro_extents:
        lst = per_file.setdefault(f, [])
        lst.append((sL, sC, eL, eC))

    index: Dict[str, Dict[str, List]] = {}
    for f, lst in per_file.items():
        # Sort by (start_line, start_col) to maintain deterministic coverage checks
        lst.sort(key=lambda t: (t[0], t[1]))
        starts = [t[0] for t in lst]
        # Prefix max of end_line for fast pruning
        end_pref = []
        max_end = -1
        for _, _, eL, _ in lst:
            if eL > max_end:
                max_end = eL
            end_pref.append(max_end)
        index[f] = {
            "intervals": lst,
            "starts": starts,
            "end_pref": end_pref,
        }
    return index


def _get_macro_extent_index(macro_extents: _MacroExtents) -> Dict[str, Dict[str, List]]:
    """
    Retrieve or build the cached index for the given extents list.
    """
    key = id(macro_extents)
    idx = _MACRO_EXTENTS_INDEX.get(key)
    if idx is None:
        idx = _build_macro_extent_index(macro_extents)
        _MACRO_EXTENTS_INDEX[key] = idx
    return idx


def _point_in_extent(line: int, col: int, sL: int, sC: int, eL: int, eC: int) -> bool:
    """
    Exact membership test consistent with the original linear implementation.
    """
    if sL == eL:
        return line == sL and sC <= col <= eC
    # Multi-line extent
    if line == sL:
        return col >= sC
    if line == eL:
        return col <= eC
    return sL < line < eL


def _is_within_macro_extent(cursor, macro_extents: _MacroExtents) -> bool:
    """
    Optimized membership check that preserves the exact original semantics.

    Previously: linear scan through all extents.
    Now: O(log n) per file using (starts, prefix max of ends) pruning.
    """
    loc = getattr(cursor, "location", None)
    if not loc or not getattr(loc, "file", None):
        return False

    file_obj = loc.file
    file_name = getattr(file_obj, "name", None)
    if not file_name:
        return False

    line = loc.line
    col = loc.column
    if not macro_extents:
        return False

    idx = _get_macro_extent_index(macro_extents)
    per = idx.get(file_name)
    if not per:
        return False

    intervals = per["intervals"]
    starts = per["starts"]
    end_pref = per["end_pref"]

    # Find last interval whose start_line <= line
    pos = bisect_right(starts, line) - 1
    if pos < 0:
        return False

    # If the max end_line up to pos is still < line, nothing can contain (line, col)
    if end_pref[pos] < line:
        return False

    # Narrow the left boundary: first index in [0..pos] with end_pref[i] >= line
    left = bisect_left(end_pref, line, 0, pos + 1)

    # Only intervals in [left..pos] can possibly cover the (line, col)
    for i in range(left, pos + 1):
        sL, sC, eL, eC = intervals[i]
        if _point_in_extent(line, col, sL, sC, eL, eC):
            return True
    return False


# -----------------------
# Macro context retrieval
# -----------------------

def _get_macro_context(cursor) -> Optional[Tuple[_MacroDefinitions, _MacroExtents]]:
    tu = getattr(cursor, "translation_unit", None)
    if tu is None:
        return None

    # Prefer per-TU attribute cache (fast path)
    cached = getattr(tu, _MACRO_CACHE_ATTR, None)
    if cached is not None:
        return cached

    key = id(tu)
    entry = _MACRO_CACHE.get(key)
    if entry is not None:
        ref, info = entry
        if ref is None:
            return info
        target = ref()
        if target is tu:
            return info
        if target is None:
            _MACRO_CACHE.pop(key, None)

    try:
        root = tu.cursor
    except AttributeError:
        return None

    macro_definitions: _MacroDefinitions = {}
    _collect_macro_definitions(root, macro_definitions)

    macro_extents: _MacroExtents = []
    if macro_definitions:
        _collect_system_macro_extents(root, macro_definitions, macro_extents)
        # Building the index here ensures the first membership check is fast;
        # if extents is empty this is a no-op.
        _get_macro_extent_index(macro_extents)

    info = (macro_definitions, macro_extents)

    # Cache on the TU object if possible; otherwise use a weakref-based global cache
    try:
        setattr(tu, _MACRO_CACHE_ATTR, info)
    except AttributeError:
        try:
            ref = weakref.ref(tu, lambda _ref, cache_key=key: _MACRO_CACHE.pop(cache_key, None))
        except TypeError:
            _MACRO_CACHE[key] = (None, info)
        else:
            _MACRO_CACHE[key] = (ref, info)
    else:
        _MACRO_CACHE.pop(key, None)

    return info


# -----------------------
# AST filtering helpers
# -----------------------

def _should_ignore_node(cursor):
    # Ignore nodes from system headers altogether
    if _is_system_header_cursor(cursor):
        return True

    # Calls that originate in user code but target functions declared in system
    # headers (e.g. printf) should still be analysed so that their arguments
    # contribute to metrics. Keep ignoring other node kinds that merely
    # reference system headers to avoid walking into system-provided ASTs.
    if cursor.kind != CursorKind.CALL_EXPR and _references_system_header(cursor):
        return True

    macro_context = _get_macro_context(cursor)
    if macro_context is None:
        return False

    macro_definitions, macro_extents = macro_context

    if cursor.kind == CursorKind.MACRO_INSTANTIATION:
        name = cursor.spelling
        if name and macro_definitions.get(name):
            return True

    if macro_extents and _is_within_macro_extent(cursor, macro_extents):
        return True

    return False


def _iter_relevant_children(cursor):
    try:
        children = cursor.get_children()
    except (AttributeError, cindex.LibclangError):
        return
    for child in children:
        if _should_ignore_node(child):
            continue
        yield child


def _children(cursor):
    # Materialize only when necessary (several call sites rely on indexing)
    return list(_iter_relevant_children(cursor))


# -----------------------
# Metrics implementations
# -----------------------

def calculate_cyclomatic_complexity(cursor):
    """
    Cyclomatic complexity based on AST control-flow nodes.
    Counts one for function entry plus a point for each of:
      - If/For/While/Do statements
      - Case labels (switch)
      - Ternary conditional operator (?:)
      - C++ catch statements
    """
    complexity = 1  # entry point
    decision_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CASE_STMT,
    }

    CK_COND = getattr(CursorKind, "CONDITIONAL_OPERATOR", None)
    CK_CATCH = getattr(CursorKind, "CXX_CATCH_STMT", None)

    def visit(node):
        nonlocal complexity
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in decision_kinds:
            complexity += 1
        elif CK_COND is not None and k == CK_COND:
            complexity += 1
        elif CK_CATCH is not None and k == CK_CATCH:
            complexity += 1
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return complexity


def calculate_number_of_loops(cursor):
    """
    Count all loop statements within a function cursor.
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
    }

    count = 0

    def visit(node):
        nonlocal count
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in loop_kinds:
            count += 1
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return count


def calculate_number_of_nested_loops(cursor):
    """
    Count loop statements that contain at least one nested loop.
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
    }

    nested_count = 0

    def contains_loop_in_subtree(node):
        for child in _iter_relevant_children(node):
            try:
                if child.kind in loop_kinds:
                    return True
            except (AttributeError, cindex.LibclangError):
                continue
            if contains_loop_in_subtree(child):
                return True
        return False

    def visit(node):
        nonlocal nested_count
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in loop_kinds:
            if contains_loop_in_subtree(node):
                nested_count += 1
            return
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return nested_count


def calculate_max_nesting_loop_depth(cursor):
    """
    Determine the maximum depth of nested loops in a function.
    """
    loop_kinds = {
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
    }

    max_depth = 0

    def visit(node, depth=0):
        nonlocal max_depth
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in loop_kinds:
            depth += 1
            if depth > max_depth:
                max_depth = depth
        for child in _iter_relevant_children(node):
            visit(child, depth)

    visit(cursor)
    return max_depth


def calculate_number_of_parameter_variables(cursor):
    """
    Count parameters declared by the function cursor.
    """
    try:
        return len(list(cursor.get_arguments()))
    except (AttributeError, cindex.LibclangError):
        return 0


def calculate_number_of_callee_parameter_variables(cursor):
    """
    Count distinct variables used as arguments in calls to other functions within the given function cursor.
    """
    callee_param_vars = set()

    def extract_vars(node):
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            try:
                ref = node.referenced
            except (AttributeError, ValueError, cindex.LibclangError):
                ref = None
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                callee_param_vars.add(node.spelling)
        for child in _iter_relevant_children(node):
            extract_vars(child)

    def visit(node):
        try:
            if node.kind == CursorKind.CALL_EXPR:
                args = list(node.get_arguments())
                for arg in args:
                    extract_vars(arg)
        except (AttributeError, cindex.LibclangError):
            pass
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return len(callee_param_vars)


def calculate_number_of_pointer_arithmetic(cursor):
    """
    Count pointer arithmetic operations (binary, unary, compound) in the function.
    """
    count = 0

    def visit(node, parent=None):
        nonlocal count
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return

        if k == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)
                if lhs_kind is None or rhs_kind is None:
                    pass
                else:
                    is_ptr_int_combo = ((lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                                        (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER))
                    is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                    if is_ptr_int_combo:
                        for tok in node.get_tokens():
                            if tok.kind == TokenKind.PUNCTUATION and tok.spelling in _BINARY_PTR_INT_OPS:
                                count += 1
                                break
                    elif is_ptr_ptr_combo and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR:
                        for tok in node.get_tokens():
                            if tok.kind == TokenKind.PUNCTUATION and tok.spelling == "-":
                                count += 1
                                break

        elif k == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in _COMPOUND_PTR_OPS:
                            count += 1
                            break

        elif k == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                child_kind = getattr(getattr(child, "type", None), "kind", None)
                # Single pass over tokens to detect ++/-- and '*'
                incdec_hit = False
                star_hit = False
                for tok in node.get_tokens():
                    if tok.kind != TokenKind.PUNCTUATION:
                        continue
                    s = tok.spelling
                    if not incdec_hit and s in _UNARY_PTR_OPS:
                        incdec_hit = True
                    elif not star_hit and s == "*":
                        star_hit = True
                    if incdec_hit and star_hit:
                        break
                if child_kind == TypeKind.POINTER:
                    if incdec_hit:
                        count += 1
                    if star_hit:
                        count += 1

        elif k == CursorKind.MEMBER_REF_EXPR:
            # p->m (member access via pointer)
            for tok in node.get_tokens():
                if tok.kind == TokenKind.PUNCTUATION and tok.spelling == "->":
                    count += 1
                    break

        for child in _iter_relevant_children(node):
            visit(child, node)

    visit(cursor)
    return count


def calculate_number_of_variables_involved_in_pointer_arithmetic(cursor):
    """
    Count distinct variables involved in pointer arithmetic operations within the function.
    """

    vars_involved = set()

    def collect_declref_vars(subnode):
        try:
            if subnode.kind == CursorKind.DECL_REF_EXPR:
                try:
                    ref = subnode.referenced
                except (AttributeError, ValueError, cindex.LibclangError):
                    ref = None
                if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                    vars_involved.add(subnode.spelling)
        except (AttributeError, cindex.LibclangError):
            return
        for child in _iter_relevant_children(subnode):
            collect_declref_vars(child)

    def _node_has_any_op(node, ops: set[str]) -> bool:
        for tok in node.get_tokens():
            if tok.kind == TokenKind.PUNCTUATION and tok.spelling in ops:
                return True
        return False

    def visit(node):
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return

        if k == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)

                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )
                is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)

                if is_ptr_int_combo and _node_has_any_op(node, _BINARY_PTR_INT_OPS):
                    if lhs_kind == TypeKind.POINTER:
                        collect_declref_vars(lhs)
                    else:
                        collect_declref_vars(rhs)
                elif (is_ptr_ptr_combo and
                      lhs.kind != CursorKind.BINARY_OPERATOR and
                      rhs.kind != CursorKind.BINARY_OPERATOR and
                      _node_has_any_op(node, _BINARY_PTR_PTR_OPS)):
                    collect_declref_vars(lhs)
                    collect_declref_vars(rhs)

        elif k == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2 and _node_has_any_op(node, _COMPOUND_PTR_OPS):
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_declref_vars(lhs)

        elif k == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                child_kind = getattr(getattr(child, "type", None), "kind", None)
                incdec_hit = False
                star_hit = False
                for tok in node.get_tokens():
                    if tok.kind != TokenKind.PUNCTUATION:
                        continue
                    s = tok.spelling
                    if not incdec_hit and s in _UNARY_PTR_OPS:
                        incdec_hit = True
                    elif not star_hit and s == "*":
                        star_hit = True
                    if incdec_hit and star_hit:
                        break
                if child_kind == TypeKind.POINTER:
                    if incdec_hit or star_hit:
                        collect_declref_vars(child)

        elif k == CursorKind.MEMBER_REF_EXPR:
            # p->m: collect the base pointer variable (left-hand side)
            has_arrow = any(tok.kind == TokenKind.PUNCTUATION and tok.spelling == "->" for tok in node.get_tokens())
            if has_arrow:
                children = _children(node)
                if children:
                    collect_declref_vars(children[0])

        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return len(vars_involved)


def calculate_max_pointer_arithmetic_variable_is_involved_in(cursor):
    """
    Calculate the maximum number of pointer arithmetic operations a variable is involved in.
    """
    var_counts: Dict[str, int] = {}

    def bump_vars(subnode):
        try:
            if subnode.kind == CursorKind.DECL_REF_EXPR:
                try:
                    ref = subnode.referenced
                except (AttributeError, ValueError, cindex.LibclangError):
                    ref = None
                if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                    name = subnode.spelling
                    var_counts[name] = var_counts.get(name, 0) + 1
        except (AttributeError, cindex.LibclangError):
            return
        for child in _iter_relevant_children(subnode):
            bump_vars(child)

    def _node_has_any_op(node, ops: set[str]) -> bool:
        for tok in node.get_tokens():
            if tok.kind == TokenKind.PUNCTUATION and tok.spelling in ops:
                return True
        return False

    def visit(node):
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return

        if k == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)
                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )
                is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                if is_ptr_int_combo and _node_has_any_op(node, _BINARY_PTR_INT_OPS):
                    if lhs_kind == TypeKind.POINTER:
                        bump_vars(lhs)
                    else:
                        bump_vars(rhs)
                elif (is_ptr_ptr_combo and
                      lhs.kind != CursorKind.BINARY_OPERATOR and
                      rhs.kind != CursorKind.BINARY_OPERATOR and
                      _node_has_any_op(node, _BINARY_PTR_PTR_OPS)):
                    bump_vars(lhs)
                    bump_vars(rhs)

        elif k == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2 and _node_has_any_op(node, _COMPOUND_PTR_OPS):
                lhs, rhs = children
                lhs_kind = getattr(getattr(lhs, "type", None), "kind", None)
                rhs_kind = getattr(getattr(rhs, "type", None), "kind", None)
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    bump_vars(lhs)

        elif k == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                child_kind = getattr(getattr(child, "type", None), "kind", None)
                incdec_hit = False
                star_hit = False
                for tok in node.get_tokens():
                    if tok.kind != TokenKind.PUNCTUATION:
                        continue
                    s = tok.spelling
                    if not incdec_hit and s in _UNARY_PTR_OPS:
                        incdec_hit = True
                    elif not star_hit and s == "*":
                        star_hit = True
                    if incdec_hit and star_hit:
                        break
                if child_kind == TypeKind.POINTER:
                    if incdec_hit:
                        bump_vars(child)
                    if star_hit:
                        bump_vars(child)

        elif k == CursorKind.MEMBER_REF_EXPR:
            # p->m: bump base pointer variable
            has_arrow = any(tok.kind == TokenKind.PUNCTUATION and tok.spelling == "->" for tok in node.get_tokens())
            if has_arrow:
                children = _children(node)
                if children:
                    bump_vars(children[0])

        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return max(var_counts.values()) if var_counts else 0


def calculate_number_of_nested_control_structures(cursor):
    """
    Calculate the number of control structures nested within other control structures.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT,
    }

    nested_count = 0

    def contains_control_in_subtree(node):
        for child in _iter_relevant_children(node):
            try:
                if child.kind in control_kinds:
                    return True
            except (AttributeError, cindex.LibclangError):
                continue
            if contains_control_in_subtree(child):
                return True
        return False

    def visit(node):
        nonlocal nested_count
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in control_kinds:
            if contains_control_in_subtree(node):
                nested_count += 1
            return
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return nested_count


def calculate_maximum_nesting_level_of_control_structures(cursor):
    """
    Calculate the maximum nesting level of control structures in the given function cursor.

    Special handling for else-if chains: count them as a flat level (unchanged behavior).
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT,
    }

    max_depth = 0

    def visit(node, depth=0):
        nonlocal max_depth
        try:
            k = node.kind
        except (AttributeError, cindex.LibclangError):
            return

        if k == CursorKind.IF_STMT:
            new_depth = depth + 1
            if new_depth > max_depth:
                max_depth = new_depth

            children = _children(node)
            cond = children[0] if len(children) >= 1 else None
            then = children[1] if len(children) >= 2 else None
            els = children[2] if len(children) >= 3 else None

            if cond is not None:
                visit(cond, new_depth)
            if then is not None:
                visit(then, new_depth)
            if els is not None:
                if getattr(els, "kind", None) == CursorKind.IF_STMT:
                    visit(els, depth)  # flatten else-if
                else:
                    visit(els, new_depth)
            return

        if k in control_kinds - {CursorKind.IF_STMT}:
            new_depth = depth + 1
            if new_depth > max_depth:
                max_depth = new_depth
            for child in _iter_relevant_children(node):
                visit(child, new_depth)
            return

        for child in _iter_relevant_children(node):
            visit(child, depth)

    visit(cursor, 0)
    return max_depth


def calculate_maximum_of_control_dependent_control_structures(cursor):
    """
    Maximum number of control structures in the subtree of any single control structure.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT,
    }

    def count_control_in_subtree(node):
        try:
            count = 1 if node.kind in control_kinds else 0
        except (AttributeError, cindex.LibclangError):
            count = 0
        for child in _iter_relevant_children(node):
            count += count_control_in_subtree(child)
        return count

    max_count = 0

    def visit(node):
        nonlocal max_count
        try:
            if node.kind in control_kinds:
                subtree_count = count_control_in_subtree(node)
                if subtree_count > max_count:
                    max_count = subtree_count
        except (AttributeError, cindex.LibclangError):
            pass
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return max_count


def calculate_maximum_of_data_dependent_control_structures(cursor):
    """
    Maximum number of data-dependent control structures in the function.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT,
    }

    def collect_vars(subnode, var_set):
        try:
            k = subnode.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            try:
                ref = subnode.referenced
            except (AttributeError, ValueError, cindex.LibclangError):
                ref = None
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                var_set.add(subnode.spelling)
        for child in _iter_relevant_children(subnode):
            collect_vars(child, var_set)

    def find_conditional_node(control_node):
        children = _children(control_node)
        k = getattr(control_node, "kind", None)
        if k == CursorKind.IF_STMT:
            return children[0] if children else None
        if k == CursorKind.WHILE_STMT:
            return children[0] if children else None
        if k == CursorKind.FOR_STMT:
            return children[1] if len(children) >= 2 else None
        if k == CursorKind.DO_STMT:
            return children[1] if len(children) >= 2 else None
        if k == CursorKind.SWITCH_STMT:
            return children[0] if children else None
        if k == CursorKind.CXX_FOR_RANGE_STMT:
            return children[1] if len(children) >= 2 else None
        return None

    def process_control(node):
        cond = find_conditional_node(node)
        if cond is None:
            return None
        vars_set = set()
        collect_vars(cond, vars_set)
        return vars_set

    var_counts: Dict[str, int] = {}

    def visit(node):
        try:
            if node.kind in control_kinds:
                cond_vars = process_control(node)
                if cond_vars:
                    for v in cond_vars:
                        var_counts[v] = var_counts.get(v, 0) + 1
        except (AttributeError, cindex.LibclangError):
            pass
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return max(var_counts.values()) if var_counts else 0


def calculate_number_of_if_structures_without_else(cursor):
    """
    Number of if structures lacking an else branch.
    """
    count = 0

    def visit(node):
        nonlocal count
        try:
            if node.kind == CursorKind.IF_STMT:
                children = _children(node)
                if len(children) < 3:
                    count += 1
        except (AttributeError, cindex.LibclangError):
            pass
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return count


def calculate_number_of_variables_involved_in_control_predicates(cursor):
    """
    Count distinct variables used in the conditions of control structures.
    """
    control_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CXX_FOR_RANGE_STMT,
        CursorKind.SWITCH_STMT,
    }

    vars_in_conditions = set()

    def collect_vars(subnode):
        try:
            k = subnode.kind
        except (AttributeError, cindex.LibclangError):
            return
        if k in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            try:
                ref = subnode.referenced
            except (AttributeError, ValueError, cindex.LibclangError):
                ref = None
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                vars_in_conditions.add(subnode.spelling)
        for child in _iter_relevant_children(subnode):
            collect_vars(child)

    def process_control(node):
        cond = None
        children = _children(node)
        k = getattr(node, "kind", None)
        if k == CursorKind.IF_STMT:
            cond = children[0] if children else None
        elif k == CursorKind.WHILE_STMT:
            cond = children[0] if children else None
        elif k == CursorKind.FOR_STMT:
            cond = children[1] if len(children) >= 2 else None
        elif k == CursorKind.DO_STMT:
            cond = children[1] if len(children) >= 2 else None
        elif k == CursorKind.SWITCH_STMT:
            cond = children[0] if children else None
        elif k == CursorKind.CXX_FOR_RANGE_STMT:
            cond = children[1] if len(children) >= 2 else None
        if cond is not None:
            collect_vars(cond)

    def visit(node):
        try:
            if node.kind in control_kinds:
                process_control(node)
        except (AttributeError, cindex.LibclangError):
            pass
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return len(vars_in_conditions)
