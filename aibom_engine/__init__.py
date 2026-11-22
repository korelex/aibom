"""AI-BOM engine prototype (option D): finds the AI parts of an app and proves each one."""
__version__ = "0.5.0"

# How long a scan reads files before it stops and says so. 600 seconds: on a Windows machine the antivirus checks each newly downloaded
# file the first time it is opened, which took four minutes for a 12,000-file repository whose scan itself takes 45 seconds. A small
# repository still takes seconds; the limit only bounds a scan that would otherwise run on.
MAX_SECONDS = 600
