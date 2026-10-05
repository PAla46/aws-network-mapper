"""Allow ``python3 -m aws_network_mapper`` once the package is installed."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
