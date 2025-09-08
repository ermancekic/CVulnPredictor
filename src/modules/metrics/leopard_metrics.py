"""
leopard_metrics.py

Concrete implementations of metric calculations operating on Clang cursors.
These functions are imported and used by modules.calculate_metrics.
"""

from clang.cindex import TokenKind, CursorKind, TypeKind


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
        except Exception:
            continue
        if tok.kind == TokenKind.KEYWORD and s in ('if', 'for', 'while', 'case', 'catch'):
            complexity += 1
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
        CursorKind.CXX_FOR_RANGE_STMT,
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
        CursorKind.CXX_FOR_RANGE_STMT,
    }

    nested_count = 0

    def contains_loop_in_subtree(node):
        for child in node.get_children():
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
        CursorKind.CXX_FOR_RANGE_STMT,
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

    def extract_vars(node):
        if node.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = node.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                callee_param_vars.add(node.spelling)
        for child in node.get_children():
            extract_vars(child)

    def visit(node):
        if node.kind == CursorKind.CALL_EXPR:
            args = list(node.get_arguments())
            for arg in args:
                extract_vars(arg)
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
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                is_ptr_int_combo = ((lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER))
                is_ptr_ptr_sub = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                if is_ptr_int_combo:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in binary_arithmetic_ops:
                            count += 1
                            break
                elif is_ptr_ptr_sub and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling == '-':
                            count += 1
                            break
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
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
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                if child.type.kind == TypeKind.POINTER:
                    for tok in node.get_tokens():
                        if tok.kind == TokenKind.PUNCTUATION and tok.spelling in unary_pointer_ops:
                            count += 1
                            break
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
    vars_involved = set()

    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                vars_involved.add(subnode.spelling)
        for child in subnode.get_children():
            collect_vars(child)

    def visit(node):
        if node.kind == CursorKind.BINARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                is_ptr_int_combo = ((lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER) or
                                    (rhs_kind == TypeKind.POINTER and lhs_kind != TypeKind.POINTER))
                is_ptr_ptr_sub = (lhs_kind == TypeKind.POINTER and rhs_kind == TypeKind.POINTER)
                if is_ptr_int_combo:
                    if lhs_kind == TypeKind.POINTER:
                        collect_vars(lhs)
                    else:
                        collect_vars(rhs)
                elif is_ptr_ptr_sub and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR:
                    collect_vars(lhs)
                    collect_vars(rhs)
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_vars(lhs)
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                if child.type.kind == TypeKind.POINTER:
                    collect_vars(child)
        for child in node.get_children():
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
    var_counts = {}

    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                name = subnode.spelling
                if name not in var_counts:
                    var_counts[name] = 0
                var_counts[name] += 1
        for child in subnode.get_children():
            collect_vars(child)

    def visit(node):
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
                    if lhs_kind == TypeKind.POINTER:
                        collect_vars(lhs)
                    else:
                        collect_vars(rhs)
                elif is_ptr_ptr_sub and lhs.kind != CursorKind.BINARY_OPERATOR and rhs.kind != CursorKind.BINARY_OPERATOR:
                    collect_vars(lhs)
                    collect_vars(rhs)
        elif node.kind == CursorKind.COMPOUND_ASSIGNMENT_OPERATOR:
            children = list(node.get_children())
            if len(children) == 2:
                lhs, rhs = children
                lhs_kind = lhs.type.kind
                rhs_kind = rhs.type.kind
                if lhs_kind == TypeKind.POINTER and rhs_kind != TypeKind.POINTER:
                    collect_vars(lhs)
        elif node.kind == CursorKind.UNARY_OPERATOR:
            children = list(node.get_children())
            if len(children) == 1:
                child = children[0]
                if child.type.kind == TypeKind.POINTER:
                    collect_vars(child)
        for child in node.get_children():
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
        CursorKind.SWITCH_STMT,
    }

    max_depth = 0

    def visit(node, depth=0):
        nonlocal max_depth
        if node.kind in control_kinds:
            depth += 1
            max_depth = max(max_depth, depth)
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
        CursorKind.SWITCH_STMT,
    }

    def count_control_in_subtree(node):
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
        CursorKind.SWITCH_STMT,
    }

    def collect_vars(subnode, var_set):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                var_set.add(subnode.spelling)
        for child in subnode.get_children():
            collect_vars(child, var_set)

    def find_conditional_node(control_node):
        children = list(control_node.get_children())
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
        for child in node.get_children():
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
            children = list(node.get_children())
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
        CursorKind.SWITCH_STMT,
    }

    vars_in_conditions = set()

    def collect_vars(subnode):
        if subnode.kind in (CursorKind.DECL_REF_EXPR, CursorKind.MEMBER_REF_EXPR):
            ref = subnode.referenced
            if ref is not None and ref.kind in (CursorKind.VAR_DECL, CursorKind.PARM_DECL, CursorKind.FIELD_DECL):
                vars_in_conditions.add(subnode.spelling)
        for child in subnode.get_children():
            collect_vars(child)

    def process_control(node):
        cond = None
        children = list(node.get_children())
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
        for child in node.get_children():
            visit(child)

    visit(cursor)
    return len(vars_in_conditions)