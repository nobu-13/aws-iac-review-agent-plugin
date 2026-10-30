"""Entry point: ``python3 -m iacreview.remediation``."""

import sys

from iacreview.remediation.cli import main

if __name__ == "__main__":
    sys.exit(main())
