import os
import sys

# `python -m aibom_engine` puts the current folder, often the repository being scanned, first on the import path.
if sys.path and os.path.normcase(os.path.abspath(sys.path[0] or os.curdir)) == os.path.normcase(os.getcwd()):
    del sys.path[0]

from .cli import main  # noqa: E402

main()
