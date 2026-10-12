"""
Package-level entry point.

The plan puts the CLI at scanner/src/__main__.py, but `python -m scanner`
resolves scanner/__main__.py - Python will not descend into src/ looking for
one. This shim bridges the two so both invocations share one implementation:

    python -m scanner scan <target>
    python scanner/src/__main__.py scan <target>

The real module is loaded by file path under a private name. A plain
`from __main__ import main` cannot work: when this file *is* __main__, that
resolves back to itself.
"""

import importlib.util
import sys
from pathlib import Path

_SRC = Path(__file__).resolve().parent / "src"
if str(_SRC) not in sys.path:
    sys.path.insert(0, str(_SRC))

_spec = importlib.util.spec_from_file_location("ecdat_scanner_cli", _SRC / "__main__.py")
_cli = importlib.util.module_from_spec(_spec)
sys.modules["ecdat_scanner_cli"] = _cli
_spec.loader.exec_module(_cli)

if __name__ == "__main__":
    raise SystemExit(_cli.main())
