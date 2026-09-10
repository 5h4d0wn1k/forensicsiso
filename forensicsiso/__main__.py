"""Allow `python -m forensicsiso`."""
import sys

from forensicsiso.cli import main

if __name__ == "__main__":
    sys.exit(main() or 0)