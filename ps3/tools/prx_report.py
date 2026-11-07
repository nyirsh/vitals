#!/usr/bin/env python3
"""Lists a decrypted PRX's exports and imports, with names where names/ knows them:

    tools/prx_report.py module.prx [--library cellSsl] [--imports] [--exports]"""

import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from nids import load_names  # noqa: E402
from prx import Prx  # noqa: E402


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("module")
    parser.add_argument("--library", help="only this library")
    parser.add_argument("--exports", action="store_true", help="exports only")
    parser.add_argument("--imports", action="store_true", help="imports only")
    arguments = parser.parse_args()
    names = load_names()
    prx = Prx(arguments.module)
    name, attributes, version, toc, *_ = prx.info()
    print(f"{name} attributes={attributes:#x} version={version[0]}.{version[1]} toc={toc:#x}")
    show_exports = arguments.exports or not arguments.imports
    show_imports = arguments.imports or not arguments.exports
    if show_exports:
        for library, functions, variables, entries in prx.exports():
            if arguments.library and library != arguments.library:
                continue
            known = sum(1 for n, _a in entries[:functions] if n in names)
            print(f"export {library or '(module)'}: {functions} functions ({known} named), {variables} variables")
            for n, address in entries[:functions]:
                print(f"  {n:08X} {address:08X} {names.get(n, '?')}")
    if show_imports:
        for library, entries in prx.imports():
            if arguments.library and library != arguments.library:
                continue
            known = sum(1 for n, _s in entries if n in names)
            print(f"import {library}: {len(entries)} functions ({known} named)")
            for n, stub in entries:
                print(f"  {n:08X} {stub:08X} {names.get(n, '?')}")


if __name__ == "__main__":
    main()
