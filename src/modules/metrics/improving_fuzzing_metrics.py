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