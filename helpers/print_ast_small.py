#!/usr/bin/env python3
"""
print_ast_small.py — Dump the Clang AST for a C file as JSON.

Usage examples:
  - Simplified, readable AST for just the given source file (default):
      python print_ast_small.py path/to/file.c

  - Full raw Clang JSON AST (can be very large):
      python print_ast_small.py path/to/file.c --raw

Notes:
  - The script prefers the bundled Clang at ./LLVM-21.1.2-Linux-X64/bin/clang
    if present, otherwise falls back to `clang` on PATH. You can override
    with --clang /path/to/clang.
  - The simplified output keeps only key fields (kind, name, type, loc, range)
    and by default filters nodes to those originating in the provided source file.
"""

from __future__ import annotations

import argparse
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
from typing import Any, Dict, List, Optional


def resolve_clang_path(cli_override: Optional[str]) -> str:
    """Pick a clang binary path.

    Preference order:
      1) --clang argument if provided
      2) Bundled path: ./LLVM-21.1.2-Linux-X64/bin/clang
      3) `clang` from PATH
    """
    if cli_override:
        return cli_override

    bundled = Path(__file__).resolve().parent / "LLVM-21.1.2-Linux-X64" / "bin" / "clang"
    if bundled.exists() and os.access(bundled, os.X_OK):
        return str(bundled)

    clang_in_path = shutil.which("clang")
    if clang_in_path:
        return clang_in_path

    # Last resort: clang-21 in PATH
    clang21 = shutil.which("clang-21")
    if clang21:
        return clang21

    raise FileNotFoundError(
        "No clang found. Provide --clang or ensure clang is in PATH."
    )


def run_clang_ast_dump(clang: str, src: Path, std: str = "c11") -> str:
    """Run clang to get the JSON AST dump for the source file."""
    cmd = [
        clang,
        "-x",
        "c",
        "-Xclang",
        "-ast-dump=json",
        "-fsyntax-only",
        f"-std={std}",
        str(src),
    ]
    # Capture stdout/stderr for error reporting. The JSON lands in stdout.
    try:
        proc = subprocess.run(
            cmd,
            check=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
    except subprocess.CalledProcessError as e:
        sys.stderr.write("Failed to run clang for AST dump.\n")
        sys.stderr.write(f"Command: {' '.join(cmd)}\n")
        if e.stdout:
            sys.stderr.write("=== STDOUT ===\n")
            sys.stderr.write(e.stdout + "\n")
        if e.stderr:
            sys.stderr.write("=== STDERR ===\n")
            sys.stderr.write(e.stderr + "\n")
        raise SystemExit(e.returncode)

    return proc.stdout


def _pick_typename(node: Dict[str, Any]) -> Optional[str]:
    t = node.get("type")
    if isinstance(t, dict):
        if isinstance(t.get("qualType"), str):
            return t.get("qualType")  # simplest form
        if isinstance(t.get("desugaredQualType"), str):
            return t.get("desugaredQualType")
    return None


def _loc_short(loc: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(loc, dict):
        return {}
    out: Dict[str, Any] = {}
    for k in ("file", "line", "col"):
        v = loc.get(k)
        if v is not None:
            out[k] = v
    return out


def _range_short(rng: Dict[str, Any]) -> Dict[str, Any]:
    if not isinstance(rng, dict):
        return {}
    out: Dict[str, Any] = {}
    b = rng.get("begin")
    e = rng.get("end")
    if isinstance(b, dict):
        out["begin"] = _loc_short(b)
    if isinstance(e, dict):
        out["end"] = _loc_short(e)
    return out


def _node_loc_file(node: Dict[str, Any]) -> Optional[str]:
    loc = node.get("loc")
    if isinstance(loc, dict):
        f = loc.get("file")
        if isinstance(f, str):
            return f
    # Fallback: the begin of range may hold the file
    rng = node.get("range")
    if isinstance(rng, dict):
        begin = rng.get("begin")
        if isinstance(begin, dict):
            f = begin.get("file")
            if isinstance(f, str):
                return f
    return None


def simplify_ast(
    node: Dict[str, Any],
    source_file: Optional[str],
    keep_all_descendants: bool = False,
) -> Optional[Dict[str, Any]]:
    """Create a small, readable version of a Clang AST node.

    - Keeps: kind, name, type (qualType), loc(line/col/file), range(begin/end line/col/file)
    - Recurses into children under key `inner`.
    - Filters nodes to those located in `source_file` if provided. If a node has
      children in the source file, it is kept to preserve tree structure.
    """
    if not isinstance(node, dict):
        return None

    kind = node.get("kind")
    if not isinstance(kind, str):
        return None

    name = node.get("name") if isinstance(node.get("name"), str) else None
    type_name = _pick_typename(node)

    inner = node.get("inner", [])

    # Heuristic to keep function definitions (not just prototypes),
    # which helps include user code even if clang didn't attach filename.
    has_compound_body = False
    if isinstance(inner, list):
        for ch in inner:
            if isinstance(ch, dict) and ch.get("kind") == "CompoundStmt":
                has_compound_body = True
                break

    # Decide if this node should be kept
    if keep_all_descendants:
        keep_for_file = True
    else:
        keep_for_file = True
        if source_file:
            node_file = _node_loc_file(node)
            keep_for_file = (node_file == source_file)
            if not keep_for_file and kind == "FunctionDecl" and has_compound_body:
                keep_for_file = True

    # Recurse into children. If this node is kept, force-keep descendants so
    # that children of children are also shown.
    children_out: List[Dict[str, Any]] = []
    if isinstance(inner, list):
        for ch in inner:
            simplified = simplify_ast(ch, source_file, keep_all_descendants=keep_for_file)
            if simplified is not None:
                children_out.append(simplified)

    # If not kept by itself, keep if any child survived (to preserve structure)
    if not keep_for_file and children_out:
        keep_for_file = True

    if not keep_for_file:
        return None

    out: Dict[str, Any] = {"kind": kind}
    if name is not None:
        out["name"] = name
    if type_name is not None:
        out["type"] = type_name
    if children_out:
        out["children"] = children_out
    return out


def main() -> None:
    p = argparse.ArgumentParser(description="Print the Clang AST for a C file as JSON.")
    p.add_argument("c_file", type=Path, help="Path to the C source file")
    p.add_argument("--clang", dest="clang", help="Path to clang binary")
    p.add_argument(
        "--std",
        default="c11",
        help="C language standard to use (default: c11)",
    )
    p.add_argument(
        "--raw",
        action="store_true",
        help="Print raw Clang JSON AST (no simplification)",
    )
    p.add_argument(
        "--out",
        type=Path,
        help="Optional output file to write JSON (defaults to stdout)",
    )
    args = p.parse_args()

    src = args.c_file.resolve()
    if not src.exists():
        sys.stderr.write(f"Source file not found: {src}\n")
        raise SystemExit(2)

    try:
        clang_path = resolve_clang_path(args.clang)
    except FileNotFoundError as e:
        sys.stderr.write(str(e) + "\n")
        raise SystemExit(2)

    raw_json = run_clang_ast_dump(clang_path, src, std=args.std)

    # Output destination
    if args.raw:
        if args.out:
            args.out.parent.mkdir(parents=True, exist_ok=True)
            args.out.write_text(raw_json, encoding="utf-8")
        else:
            sys.stdout.write(raw_json)
        return

    # Simplify to make the AST easier to understand
    try:
        ast_obj = json.loads(raw_json)
    except json.JSONDecodeError as e:
        sys.stderr.write(f"Failed to parse Clang JSON output: {e}\n")
        raise SystemExit(3)

    simplified = simplify_ast(ast_obj, source_file=str(src))
    # If simplification resulted in nothing (e.g., headers only), fall back to raw
    if simplified is None:
        simplified = {"note": "No nodes matched the source file; showing raw AST.", "raw": ast_obj}

    json_out = json.dumps(simplified, indent=2, ensure_ascii=False)

    if args.out:
        args.out.parent.mkdir(parents=True, exist_ok=True)
        args.out.write_text(json_out, encoding="utf-8")
    else:
        sys.stdout.write(json_out + "\n")


if __name__ == "__main__":
    main()
