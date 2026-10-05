"""Allow ``python3 -m mapper`` once the package is installed."""

import sys

from .cli import main

if __name__ == "__main__":
    sys.exit(main())
