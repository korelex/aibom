"""The line between aibom and the repository it scans, which is untrusted.

Three rules, kept here so every part of the scan follows the same ones:
  run     programs are found on absolute PATH folders only, never in the current or the scanned folder
  read    only regular files inside the scanned folder: no links, junctions, pipes, or paths that climb out
  write   never through a link, a junction or a second name of another file
"""
import os
import stat

IS_WINDOWS = os.name == "nt"
LINK_TAGS = (0xA0000003, 0xA000000C)   # junction (mount point) and symlink; cloud-drive placeholders are not links


class SourceError(Exception):
    """A problem with the source that the user can fix. The message is written for a person."""


def is_within(path, folder):
    """Is `path` the folder or inside it? Compares the text of absolute paths and touches nothing."""
    path, folder = os.path.normcase(os.path.abspath(path)), os.path.normcase(os.path.abspath(folder))
    try:
        return os.path.commonpath([path, folder]) == folder
    except ValueError:  # another drive
        return False


def search_path(avoid=None):
    """The PATH folders a program may come from: absolute ones, outside `avoid`."""
    keep = []
    for folder in os.environ.get("PATH", "").split(os.pathsep):
        folder = folder.strip('"')
        if folder and os.path.isabs(folder) and not (avoid and is_within(folder, avoid)):
            keep.append(folder)
    return keep


def find_program(name, avoid=None):
    """The absolute path of a program, or None. shutil.which is not used: on Windows it looks in the current folder first."""
    if os.path.basename(name) != name:
        return None
    names = [name]
    if IS_WINDOWS and os.path.splitext(name)[1].lower() not in (".exe", ".com"):
        names = [name + ".exe", name + ".com"]  # not .bat or .cmd: those run through cmd.exe, which reads the arguments as commands
    for folder in search_path(avoid):
        for n in names:
            path = os.path.join(folder, n)
            if os.path.isfile(path) and os.access(path, os.X_OK):
                return os.path.abspath(path)
    return None


def child_env(avoid=None):
    """The environment for a program aibom starts, so that what it starts in turn is not taken from the current folder either."""
    env = dict(os.environ)
    env["PATH"] = os.pathsep.join(search_path(avoid))
    env["NoDefaultCurrentDirectoryInExePath"] = "1"
    return env


def is_link(path):
    """A symlink, or a Windows junction (which os.path.islink does not report and os.walk follows)."""
    if os.path.islink(path):
        return True
    if not IS_WINDOWS:
        return False
    try:
        return getattr(os.lstat(path), "st_reparse_tag", 0) in LINK_TAGS
    except OSError:
        return False


def plain_file(path):
    """The lstat of a regular file that is not a link, else None."""
    try:
        st = os.lstat(path)
    except OSError:
        return None
    if not stat.S_ISREG(st.st_mode) or (IS_WINDOWS and getattr(st, "st_reparse_tag", 0) in LINK_TAGS):
        return None
    return st


def inside_path(root, rel):
    """The path of `rel` under `root` when it stays inside and passes through no link, else None. A path that leaves is
    refused before it is touched: on Windows just looking at \\\\host\\share signs in to that host."""
    text = str(rel).replace("\\", "/") if IS_WINDOWS else str(rel)
    if not text or "\x00" in text or text.startswith("/") or (IS_WINDOWS and ":" in text):
        return None
    rel = os.path.normpath(text)
    parts = rel.split(os.sep)
    if parts[0] == ".." or os.path.isabs(rel):
        return None
    path = root
    for part in parts:
        if part != ".":
            path = os.path.join(path, part)
            if is_link(path):
                return None
    return path


def inside_file(root, rel):
    """The path of the regular file `rel` inside `root`, else None."""
    path = inside_path(root, rel)
    return path if path and plain_file(path) else None


def output_path(path, scanned=None):
    """`path` made absolute, after making sure that no part of it below the current or the scanned folder is a link.
    Links above those folders (/tmp on macOS, a linked home folder) belong to the user and are left alone."""
    path = os.path.abspath(path)
    for base in (os.getcwd(), scanned):
        if not base or not is_within(path, base):
            continue
        step = os.path.abspath(base)
        for part in os.path.relpath(path, step).split(os.sep):
            if part == ".":
                continue
            step = os.path.join(step, part)
            if is_link(step):
                raise SourceError(f"{step} is a link, and aibom does not write through links. Delete it, or choose another output folder.")
    return path


def output_file(path):
    """`path` made absolute, when writing to it can change only that file."""
    path = output_path(path)
    if os.path.lexists(path):
        st = plain_file(path)
        if st is None or st.st_nlink > 1:
            raise SourceError(f"{path} is a link or not a regular file, and aibom does not write through those. Delete it, or choose another output folder.")
    return path


def open_output(path, **how):
    """open(path, "w") for a file aibom writes."""
    how.setdefault("encoding", "utf-8")
    return open(output_file(path), "w", **how)
