"""Root conftest: make both the ai-service and channels packages importable.

The repo is a multi-service monorepo without a single installable package, so we
put each service root on sys.path rather than forcing an install step just to run
tests.
"""
import sys
from pathlib import Path

ROOT = Path(__file__).parent
for path in (ROOT / "ai-service", ROOT / "channels", ROOT):
    p = str(path)
    if p not in sys.path:
        sys.path.insert(0, p)
