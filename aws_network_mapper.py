#!/usr/bin/env python3
"""Entry point for the AWS network mapper.

Runs straight from a clone with no install step, which is what the CloudShell
usage in the README relies on:

    git clone <repo> && cd aws-network-mapper
    python3 aws_network_mapper.py --all-regions --out ./aws-network-map

The real package lives in ``src/aws_network_mapper``. If you have installed the
project, ``python3 -m aws_network_mapper`` and the ``aws-network-mapper``
console script work too.
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "src"))

from aws_network_mapper.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
