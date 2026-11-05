#!/bin/sh
# Same as: python scripts/fetch_repos.py   (kept for convenience)
exec python3 "$(dirname "$0")/fetch_repos.py" "$@"
