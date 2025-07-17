"""
print_ast.py

Utility to print the Clang AST nodes of a C/C++ source file.
Provides detailed printing for binary operators and general AST traversal.
"""

import sys
import os
clang_path   = os.path.abspath(os.path.join(os.getcwd(), "llvm-project-llvmorg-20.1.8", "clang", "bindings", "python"))
sys.path.insert(0, clang_path)

from clang import cindex
from clang.cindex import TokenKind, CursorKind, TypeKind

libclang_path =  os.path.abspath(os.path.join(os.getcwd(), "LLVM-20.1.8-Linux-X64", "lib", "libclang.so"))
cindex.Config.set_library_file(libclang_path)
cindex.Config.set_compatibility_check(False)

cindex.Config.set_library_path(libclang_path)


def print_node(node, indent=0):
    """
    Recursively print AST nodes with indentation. Special handling for binary operators.

    Args:
        node (cindex.Cursor): The AST cursor node to print.
        indent (int): Current indentation level for pretty output.

    Returns:
        None
    """
    prefix = '  ' * indent

    # Spezialfall: BINARY_OPERATOR
    if node.kind == CursorKind.BINARY_OPERATOR:
        # Alle direkten Kinder sammeln (erwartet: links und rechts)
        children = list(node.get_children())
        if len(children) == 2:
            left, right = children

            # Aus den Tokens des BINARY_OPERATOR-Knotens das Operator-Zeichen extrahieren.
            # Heuristik: erstes Token vom TokenKind.PUNCTUATION, das kein "(" oder ")" ist.
            op_token = None
            for tok in node.get_tokens():
                if tok.kind == TokenKind.PUNCTUATION and tok.spelling not in ('(', ')', '{', '}', '[', ']', ';'):
                    op_token = tok.spelling
                    break

            # Ausgabezeile für diesen BINARY_OPERATOR:
            line = (
                f"{prefix}"
                f"{node.kind.name:20}  "  # z.B. "BINARY_OPERATOR     "
                f"[Type: {node.type.spelling!r} ({node.type.kind.name})]  "
                f"  <- left={left.kind.name!r}:{left.spelling!r}  "
                f"operator={op_token!r}  "
                f"right={right.kind.name!r}:{right.spelling!r}"
            )
            print(line)

            # Rekursiv in die linke und rechte Teil-Expression hinein
            print_node(left, indent + 1)
            print_node(right, indent + 1)
            return
        # Falls aus irgendeinem Grund nicht genau zwei Kinder (selten), ab hier normal weitermachen

    # Allgemeine Ausgabe für alle anderen Knoten
    line = (
        f"{prefix}"
        f"{node.kind.name:20}  {node.spelling!r}  "
        f"[type.spelling={node.type.spelling!r}  type.kind={node.type.kind.name}]"
    )
    print(line)

    # Rekursion in alle Kinder
    for child in node.get_children():
        print_node(child, indent + 1)


def main():
    """
    Parse the given C source file and print its AST using print_node.

    Args:
        None

    Returns:
        None
    """
    if len(sys.argv) != 2:
        print("Usage: python3 print_ast.py <pfad_zu_c_datei>")
        sys.exit(1)

    source_file = sys.argv[1]
    index = cindex.Index.create()
    tu = index.parse(source_file, args=['-std=c11'])
    if not tu:
        print("Fehler beim Parsen.")
        sys.exit(1)

    print_node(tu.cursor)


if __name__ == "__main__":
    main()
