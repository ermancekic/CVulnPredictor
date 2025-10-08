"""
leopard_metrics.py

Concrete implementations of metric calculations operating on Clang cursors.
These functions are imported and used by modules.calculate_metrics.
"""

import weakref

from clang import cindex
from clang.cindex import TokenKind, CursorKind, TypeKind
from typing import Dict, List, Optional, Tuple


_MacroDefinitions = Dict[str, bool]
_MacroExtents = List[Tuple[str, int, int, int, int]]
_MacroCacheEntry = Tuple[Optional[weakref.ReferenceType], Tuple[_MacroDefinitions, _MacroExtents]]
_MACRO_CACHE: Dict[int, _MacroCacheEntry] = {}
_MACRO_CACHE_ATTR = "_cvuln_macro_context"


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
    # Use an explicit stack to avoid hitting Python's recursion limit on large ASTs.
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
            for child in node.get_children():
                stack.append(child)
        except (AttributeError, cindex.LibclangError):
            continue


def _collect_system_macro_extents(
    cursor,
    macro_definitions: _MacroDefinitions,
    extents: _MacroExtents,
) -> None:
    # Mirror the iterative walk used for definitions to prevent deep recursion.
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
                if extent.start.file and extent.end.file:
                    extents.append(
                        (
                            extent.start.file.name,
                            extent.start.line,
                            extent.start.column,
                            extent.end.line,
                            extent.end.column,
                        )
                    )

        try:
            for child in node.get_children():
                stack.append(child)
        except (AttributeError, cindex.LibclangError):
            continue


def _is_within_macro_extent(cursor, macro_extents: _MacroExtents) -> bool:
    loc = cursor.location
    if not loc or not loc.file:
        return False

    file_name = loc.file.name
    line = loc.line
    col = loc.column

    for extent_file, start_line, start_col, end_line, end_col in macro_extents:
        if file_name != extent_file:
            continue
        if start_line == end_line:
            if line == start_line and start_col <= col <= end_col:
                return True
        else:
            if line == start_line and col >= start_col:
                return True
            if line == end_line and col <= end_col:
                return True
            if start_line < line < end_line:
                return True
    return False


def _get_macro_context(cursor) -> Optional[Tuple[_MacroDefinitions, _MacroExtents]]:
    tu = getattr(cursor, "translation_unit", None)
    if tu is None:
        return None

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

    info = (macro_definitions, macro_extents)

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


def _should_ignore_node(cursor):
    if _is_system_header_cursor(cursor):
        return True

    # Calls that originate in user code but target functions declared in system
    # headers (e.g. printf) should still be analysed so that their arguments
    # contribute to metrics.  Keep ignoring other node kinds that merely
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
    for child in cursor.get_children():
        if _should_ignore_node(child):
            continue
        yield child


def _children(cursor):
    return list(_iter_relevant_children(cursor))


def calculate_cyclomatic_complexity(cursor):
    """
    Cyclomatic complexity based on AST control-flow nodes.
    Counts one for function entry plus a point for each of:
      - If/For/While/Do statements
      - Case labels (switch)
      - Ternary conditional operator (?:)
      - C++ catch statements

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.
    Returns:
        int: Cyclomatic complexity (approximate McCabe number).
    """
    complexity = 1  # entry point
    decision_kinds = {
        CursorKind.IF_STMT,
        CursorKind.FOR_STMT,
        CursorKind.WHILE_STMT,
        CursorKind.DO_STMT,
        CursorKind.CASE_STMT,
    }
    
    CK_COND = getattr(CursorKind, 'CONDITIONAL_OPERATOR', None)
    CK_CATCH = getattr(CursorKind, 'CXX_CATCH_STMT', None)
    
    def visit(node):
        nonlocal complexity
        k = node.kind
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

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Total number of loop constructs (for, while, do, ranged-for).
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
        if node.kind in loop_kinds:
            count += 1
        for child in _iter_relevant_children(node):
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
        CursorKind.CXX_FOR_RANGE_STMT,
    }

    nested_count = 0

    def contains_loop_in_subtree(node):
        for child in _iter_relevant_children(node):
            if child.kind in loop_kinds:
                return True
            if contains_loop_in_subtree(child):
                return True
        return False

    def visit(node):
        nonlocal nested_count
        if node.kind in loop_kinds:
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

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum nesting depth of loops.
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
        if node.kind in loop_kinds:
            depth += 1
            max_depth = max(max_depth, depth)
        for child in _iter_relevant_children(node):
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

    def extract_vars(node):
        if node.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = node.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                callee_param_vars.add(node.spelling)
        for child in _iter_relevant_children(node):
            extract_vars(child)

    def visit(node):
        if node.kind == CursorKind.CALL_EXPR:
            args = list(node.get_arguments())
            for arg in args:
                extract_vars(arg)
        for child in _iter_relevant_children(node):
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
    # LEOPARD: restrict to valid pointer arithmetic operators
    binary_arithmetic_ops = {'+', '-'}            # pointer +/- integer, pointer - pointer
    compound_pointer_ops = {'+=', '-='}           # pointer += integer, pointer -= integer
    unary_pointer_ops = {'++', '--'}              # ++ptr, --ptr

    def visit(node, parent=None):
        nonlocal count
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                is_ptr_int_combo = ((lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER))
                is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                if is_ptr_int_combo:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in binary_arithmetic_ops:
                            count += 1
                            break
                elif is_ptr_ptr_combo and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '-':
                            count += 1
                            break
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in compound_pointer_ops:
                            count += 1
                            break
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                # ++p / --p on a pointer
                if child.type.kind == TypeKind.POINTER:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in unary_pointer_ops:
                            count += 1
                            break
                # *p (dereference) -> treated as pointer arithmetic by LEOPARD
                for tok in node.get_tokens():
                    if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '*':
                        # Only count if operand is a pointer
                        if child.type.kind == TypeKind.POINTER:
                            count += 1
                        break
        elif node.kind == CursorKind.MEMBER_REF_EXPR:
            # p->m (member access via pointer)
            for tok in node.get_tokens():
                if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '->':
                    count += 1
                    break
        for child in _iter_relevant_children(node):
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
    vars_involved = set()

    # Only collect variable identifiers (exclude field names from MEMBER_REF_EXPR)
    def collect_declref_vars(subnode):
        if subnode.kind == CursorKind.DECL_REF_EXPR:
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                vars_involved.add(subnode.spelling)
        for child in _iter_relevant_children(subnode):
            collect_declref_vars(child)

    # Only treat the following operators as true pointer arithmetic
    bin_ops_ptr_int = {'+', '-'}
    bin_ops_ptr_ptr = {'-'}
    compound_ops = {'+=', '-='}
    unary_ops = {'++', '--'}

    def _node_has_any_op(node, ops: set[str]) -> bool:
        for tok in node.get_tokens():
            if tok.kind == TokenKind.PUNCTUATION and tok.spelling in ops:
                return True
        return False

    def visit(node):
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind

                # pointer +/- integer
                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )
                # pointer - pointer
                is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)

                if is_ptr_int_combo and _node_has_any_op(node, bin_ops_ptr_int):
                    if lhs_kind == TypeKind.POINTER:
                        collect_declref_vars(lhs)
                    else:
                        collect_declref_vars(rhs)
                elif is_ptr_ptr_combo and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR and _node_has_any_op(node, bin_ops_ptr_ptr):
                    # Only subtraction of pointers is valid pointer arithmetic
                    collect_declref_vars(lhs)
                    collect_declref_vars(rhs)

        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2 and _node_has_any_op(node, compound_ops):
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_declref_vars(lhs)

        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                # ++p / --p
                if _node_has_any_op(node, unary_ops) and child.type.kind == TypeKind.POINTER:
                    collect_declref_vars(child)
                # *p (dereference)
                for tok in node.get_tokens():
                    if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '*':
                        if child.type.kind == TypeKind.POINTER:
                            collect_declref_vars(child)
                        break

        elif node.kind == CursorKind.MEMBER_REF_EXPR:
            # p->m: collect the base pointer variable (left-hand side)
            has_arrow = any(tok.kind == TokenKind.PUNCTUATION and tok.spelling == '->' for tok in node.get_tokens())
            if has_arrow:
                children = _children(node)
                if children:
                    # Heuristic: first child is the base expression; collect variables from it
                    collect_declref_vars(children[0])

        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return len(vars_involved)


def calculate_max_pointer_arithmetic_variable_is_involved_in(cursor):
    """
    Calculate the maximum number of pointer arithmetic operations a variable is involved in
    within the given function cursor.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Maximum number of pointer arithmetic operations for any single variable.
    """
    var_counts: dict[str, int] = {}

    def bump_vars(subnode):
        if subnode.kind == CursorKind.DECL_REF_EXPR:
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL):
                name = subnode.spelling
                var_counts[name] = var_counts.get(name, 0) + 1
        for child in _iter_relevant_children(subnode):
            bump_vars(child)

    bin_ops_ptr_int = {'+', '-'}
    bin_ops_ptr_ptr = {'-'}
    compound_ops = {'+=', '-='}
    unary_ops = {'++', '--'}

    def _node_has_any_op(node, ops: set[str]) -> bool:
        for tok in node.get_tokens():
            if tok.kind == TokenKind.PUNCTUATION and tok.spelling in ops:
                return True
        return False

    def visit(node):
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = _children(node)
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                is_ptr_int_combo = (
                    (lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER)
                )
                is_ptr_ptr_combo = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                if is_ptr_int_combo and _node_has_any_op(node, bin_ops_ptr_int):
                    if lhs_kind == TypeKind.POINTER:
                        bump_vars(lhs)
                    else:
                        bump_vars(rhs)
                elif is_ptr_ptr_combo and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR and _node_has_any_op(node, bin_ops_ptr_ptr):
                    bump_vars(lhs)
                    bump_vars(rhs)
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = _children(node)
            if len(children) == 2 and _node_has_any_op(node, compound_ops):
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    bump_vars(lhs)
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = _children(node)
            if len(children) == 1:
                child = children[0]
                # ++p / --p
                if _node_has_any_op(node, unary_ops) and child.type.kind == TypeKind.POINTER:
                    bump_vars(child)
                # *p (dereference)
                for tok in node.get_tokens():
                    if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '*':
                        if child.type.kind == TypeKind.POINTER:
                            bump_vars(child)
                        break
        elif node.kind == CursorKind.MEMBER_REF_EXPR:
            # p->m: bump base pointer variable
            has_arrow = any(tok.kind == TokenKind.PUNCTUATION and tok.spelling == '->' for tok in node.get_tokens())
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
        CursorKind.SWITCH_STMT,
    }

    nested_count = 0

    def contains_control_in_subtree(node):
        for child in _iter_relevant_children(node):
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
        for child in _iter_relevant_children(node):
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
        CursorKind.SWITCH_STMT,
    }

    max_depth = 0

    def visit(node, depth=0):
        nonlocal max_depth

        # Special handling for IF_STMT to flatten else-if chains:
        # In Clang's AST, an "else if" is represented as an IF_STMT in the else branch
        # of a preceding IF_STMT. We count that as the same nesting level as the first if.
        if node.kind == CursorKind.IF_STMT:
            new_depth = depth + 1
            if new_depth > max_depth:
                max_depth = new_depth

            children = _children(node)
            cond = children[0] if len(children) >= 1 else None
            then = children[1] if len(children) >= 2 else None
            els  = children[2] if len(children) >= 3 else None

            # Visit condition (does not affect nesting depth meaningfully)
            if cond is not None:
                visit(cond, new_depth)

            # Then-branch is nested under this if
            if then is not None:
                visit(then, new_depth)

            # Else-branch: if it's an IF_STMT (else-if), keep the same depth
            # so the whole chain stays flat; otherwise, it's nested under this if
            if els is not None:
                if els.kind == CursorKind.IF_STMT:
                    visit(els, depth)  # flatten else-if chain
                else:
                    visit(els, new_depth)
            return

        # Other control structures increase depth normally
        if node.kind in {
            CursorKind.FOR_STMT,
            CursorKind.WHILE_STMT,
            CursorKind.DO_STMT,
            CursorKind.CXX_FOR_RANGE_STMT,
            CursorKind.SWITCH_STMT,
        }:
            new_depth = depth + 1
            if new_depth > max_depth:
                max_depth = new_depth
            for child in _iter_relevant_children(node):
                visit(child, new_depth)
            return

        # Non-control nodes: propagate same depth
        for child in _iter_relevant_children(node):
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
        CursorKind.SWITCH_STMT,
    }

    def count_control_in_subtree(node):
        count = 1 if node.kind in control_kinds else 0
        for child in _iter_relevant_children(node):
            count += count_control_in_subtree(child)
        return count

    max_count = 0

    def visit(node):
        nonlocal max_count
        if node.kind in control_kinds:
            subtree_count = count_control_in_subtree(node)
            if subtree_count > max_count:
                max_count = subtree_count
        for child in _iter_relevant_children(node):
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
        CursorKind.SWITCH_STMT,
    }

    def collect_vars(subnode, var_set):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                var_set.add(subnode.spelling)
        for child in _iter_relevant_children(subnode):
            collect_vars(child, var_set)

    def find_conditional_node(control_node):
        children = _children(control_node)
        if control_node.kind == CursorKind.IF_STMT:
            return children[0] if children else None
        if control_node.kind == CursorKind.WHILE_STMT:
            return children[0] if children else None
        if control_node.kind == CursorKind.FOR_STMT:
            return children[1] if len(children) >= 2 else None
        if control_node.kind == CursorKind.DO_STMT:
            return children[1] if len(children) >= 2 else None
        if control_node.kind == CursorKind.SWITCH_STMT:
            return children[0] if children else None
        if control_node.kind == CursorKind.CXX_FOR_RANGE_STMT:
            return children[1] if len(children) >= 2 else None
        return None

    def process_control(node):
        cond = find_conditional_node(node)
        if cond is None:
            return
        vars_set = set()
        collect_vars(cond, vars_set)
        return vars_set

    var_counts = {}

    def visit(node):
        if node.kind in control_kinds:
            cond_vars = process_control(node)
            if cond_vars:
                for v in cond_vars:
                    var_counts[v] = var_counts.get(v, 0) + 1
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return max(var_counts.values()) if var_counts else 0


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
            children = _children(node)
            if len(children) < 3:
                count += 1
        for child in _iter_relevant_children(node):
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
        CursorKind.SWITCH_STMT,
    }

    vars_in_conditions = set()

    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                vars_in_conditions.add(subnode.spelling)
        for child in _iter_relevant_children(subnode):
            collect_vars(child)

    def process_control(node):
        cond = None
        children = _children(node)
        if node.kind == CursorKind.IF_STMT:
            cond = children[0] if children else None
        elif node.kind == CursorKind.WHILE_STMT:
            cond = children[0] if children else None
        elif node.kind == CursorKind.FOR_STMT:
            cond = children[1] if len(children) >= 2 else None
        elif node.kind == CursorKind.DO_STMT:
            cond = children[1] if len(children) >= 2 else None
        elif node.kind == CursorKind.SWITCH_STMT:
            cond = children[0] if children else None
        elif node.kind == CursorKind.CXX_FOR_RANGE_STMT:
            cond = children[1] if len(children) >= 2 else None
        if cond is not None:
            collect_vars(cond)

    def visit(node):
        if node.kind in control_kinds:
            process_control(node)
        for child in _iter_relevant_children(node):
            visit(child)

    visit(cursor)
    return len(vars_in_conditions)
