from clang.cindex import TokenKind, CursorKind, TypeKind

def calculate_loc(cursor):
    """
    Calculate lines of code (excluding comments and blanks) for a function cursor.

    Counts distinct source lines within the function's own file and lexical line range.
    This avoids attributing macro-definition locations (possibly in other lines/files)
    to the function, which can drastically inflate counts in amalgamated sources.

    Args:
        cursor (cindex.Cursor): Clang cursor for the function or method.

    Returns:
        int: Number of distinct non-comment, non-blank lines in the function body.
    """
    tu = cursor.translation_unit

    # Function's lexical file + line range
    start = cursor.extent.start
    end = cursor.extent.end
    func_file = getattr(start, "file", None)
    start_line = getattr(start, "line", None)
    end_line = getattr(end, "line", None)

    if func_file is None or start_line is None or end_line is None:
        # Fallback to a conservative count based on token lines without file filtering
        tokens = tu.get_tokens(extent=cursor.extent)
        lines = set()
        for tok in tokens:
            if tok.kind == TokenKind.COMMENT:
                continue
            try:
                if not (tok.spelling or "").strip():
                    continue
            except Exception:
                continue
            lines.add(tok.location.line)
        return len(lines)

    # Filter tokens to those spelled in the same file and within the function's line span
    tokens = tu.get_tokens(extent=cursor.extent)
    lines = set()
    for tok in tokens:
        if tok.kind == TokenKind.COMMENT:
            continue
        # Cheap skip for empty spellings (defensive)
        try:
            if not (tok.spelling or "").strip():
                continue
        except Exception:
            continue

        loc = tok.location
        tfile = getattr(loc, "file", None)
        tline = getattr(loc, "line", None)
        if tfile is None or tline is None:
            continue

        # Only count lines in the same physical file and inside [start_line, end_line]
        if tfile == func_file and start_line <= tline <= end_line:
            lines.add(tline)

    return len(lines)

def _in_extent(parent, child):
    """True if the child's extent is fully inside the parent's extent (same file + offsets)."""
    ps, pe = parent.extent.start, parent.extent.end
    cs, ce = child.extent.start, child.extent.end
    # If libclang provides no file (e.g., for builtins), allow it:
    if ps.file is None or cs.file is None or pe.file is None or ce.file is None:
        return True
    if ps.file != cs.file or pe.file != ce.file:
        return False
    return (cs.offset >= ps.offset) and (ce.offset <= pe.offset)


def calculate_basic_block_count(cursor):
    """
    AST-based approximation of basic blocks for a function cursor.
    Start with 1 (entry block) and add blocks for:
      - if-then (+1) and optional else (+1)
      - for/while/do (+1)
      - case/default/label (+1 per occurrence)
      - try/catch (if available, +1 each)
      - ternary (?:) (+1)
    """
    CASE_STMT         = CursorKind.CASE_STMT
    DEFAULT_STMT      = CursorKind.DEFAULT_STMT
    LABEL_STMT        = CursorKind.LABEL_STMT
    IF_STMT           = CursorKind.IF_STMT
    FOR_STMT          = CursorKind.FOR_STMT
    WHILE_STMT        = CursorKind.WHILE_STMT
    DO_STMT           = CursorKind.DO_STMT
    SWITCH_STMT       = CursorKind.SWITCH_STMT
    # Get optional kinds robustly (depends on Clang version)
    COND_OP        = getattr(CursorKind, "CONDITIONAL_OPERATOR", None)
    CXX_TRY_STMT   = getattr(CursorKind, "CXX_TRY_STMT", None)
    CXX_CATCH_STMT = getattr(CursorKind, "CXX_CATCH_STMT", None)

    blocks = 1  # entry block

    def visit(node):
        nonlocal blocks
        if not _in_extent(cursor, node):
            return

        k = node.kind

        if k == IF_STMT:
            # then-branch
            blocks += 1
            # else present? Typically: children = (cond, then, [else])
            kids = [c for c in node.get_children() if _in_extent(cursor, c)]
            if len(kids) >= 3:
                blocks += 1

        elif k in (FOR_STMT, WHILE_STMT, DO_STMT):
            blocks += 1

        elif k in (CASE_STMT, DEFAULT_STMT, LABEL_STMT):
            blocks += 1

        elif k == SWITCH_STMT:
            # Cases (CASE/DEFAULT) are counted separately; don't add here
            pass

        elif COND_OP is not None and k == COND_OP:
            # ternary ?: usually produces two branches; count conservatively +1
            blocks += 1

        elif CXX_TRY_STMT is not None and k == CXX_TRY_STMT:
            blocks += 1
        elif CXX_CATCH_STMT is not None and k == CXX_CATCH_STMT:
            blocks += 1

        for ch in node.get_children():
            visit(ch)

    # only traverse the function body
    for child in cursor.get_children():
        visit(child)

    return max(1, blocks)


def calculate_procedure_calls_count(cursor):
    """
    Count procedure/function calls within the function cursor.
    Considers CALL_EXPR and (where available) C++ special cases.
    """
    call_kinds = { CursorKind.CALL_EXPR }
    # Optionally include, depending on Clang version:
    for name in (
        "CXX_MEMBER_CALL_EXPR",
        "CXX_OPERATOR_CALL_EXPR",
        "OBJC_MESSAGE_EXPR",
        "CXX_CONSTRUCT_EXPR",
        "CXX_NEW_EXPR",
        "CXX_DELETE_EXPR",
    ):
        k = getattr(CursorKind, name, None)
        if k is not None:
            call_kinds.add(k)

    count = 0

    def visit(node):
        nonlocal count
        if not _in_extent(cursor, node):
            return
        if node.kind in call_kinds:
            count += 1
        for ch in node.get_children():
            visit(ch)

    # only traverse within the function
    for child in cursor.get_children():
        visit(child)

    return count
