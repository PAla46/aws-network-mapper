#!/usr/bin/env python3
"""Entry point for the AWS network mapper.

Usage in AWS CloudShell:
    git clone <repo> && cd aws-network-mapper
    python3 aws_network_mapper.py --all-regions --out ./aws-network-map
"""

import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from nm.cli import main  # noqa: E402

if __name__ == "__main__":
    sys.exit(main())
