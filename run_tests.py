#!/usr/bin/env python3
"""Run the offline check suite without going through the CLI.

    python3 run_tests.py            # all checks
    python3 run_tests.py -v         # list every check as it passes

Equivalent to ``python3 aws_network_mapper.py --self-test``.
"""

import os
import sys

ROOT = os.path.dirname(os.path.abspath(__file__))
for path in (os.path.join(ROOT, "src"), ROOT):
    if path not in sys.path:
        sys.path.insert(0, path)

from tests.suite import run_self_test  # noqa: E402

if __name__ == "__main__":
    sys.exit(run_self_test(verbose="-v" in sys.argv or "--verbose" in sys.argv))
