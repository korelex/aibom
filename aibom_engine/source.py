"""Turn whatever was typed into a folder to scan: a local folder, or a link to a git repository.

Accepted:  a folder on disk | https://github.com/owner/repo | github.com/owner/repo | owner/repo
           https://github.com/owner/repo/tree/branch/sub/folder | git@github.com:owner/repo.git | file:///path/to/repo"""
import os
import re
import shutil
import stat
import subprocess
import tempfile
from urllib.parse import quote

from . import safety
from .safety import SourceError


SHORT = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
HOSTS = ("github.com/", "gitlab.com/", "bitbucket.org/")


def parse(arg):
    a = str(arg).strip().strip("\"'")
    if os.path.isdir(a):
        p = os.path.abspath(a)
        return {"kind": "local", "path": p, "name": os.path.basename(p.rstrip("/\\")) or "app", "source": p}
    m = re.match(r"^git@([^:]+):(.+?)(?:\.git)?/?$", a)
    if m:
        return {"kind": "git", "url": a, "branch": "", "subpath": "", "name": m.group(2).split("/")[-1], "source": a}
    url = a
    if url.startswith(HOSTS):
        url = "https://" + url
    elif SHORT.match(url) and not os.path.exists(url):
        url = "https://github.com/" + url
    if not re.match(r"^(https?|file)://", url):
        raise SourceError(f"I could not find a folder or a git link called '{a}'. Give me a folder on this computer, or a link like https://github.com/owner/repo")
    url = url.split("#")[0].split("?")[0].rstrip("/")
    branch = subpath = ""
    m = re.match(r"^(https?://[^/]+/[^/]+/[^/]+?)(?:/-)?/(?:tree|blob)/([^/]+)(?:/(.*))?$", url)
    if m:
        url, branch, subpath = m.group(1), m.group(2), (m.group(3) or "")
        if "/blob/" in a and "." in os.path.basename(subpath):  # a link to one file: scan its folder
            subpath = os.path.dirname(subpath)
    if url.endswith(".git"):
        url = url[:-4]
    name = url.rstrip("/").split("/")[-1] or "app"
    return {"kind": "git", "url": url, "branch": branch, "subpath": subpath, "name": name, "source": a}


def friendly_git_error(stderr, url):
    low = (stderr or "").lower()
    if "remote branch" in low and "not found" in low:
        return "That branch does not exist in the repository. Check the link, or leave the branch out to use the default one."
    if any(k in low for k in ("could not resolve host", "unable to access", "failed to connect", "timed out", "network is unreachable", "temporary failure in name resolution", "ssl")):
        return "I could not reach the internet. Check the connection, or scan a folder that is already on this computer."
    if any(k in low for k in ("not found", "does not exist", "authentication failed", "could not read username", "terminal prompts disabled", "repository not found", "permission denied", "access denied")):
        return f"I could not open {url}. The link may be wrong, or the repository is private. For a private repository, download the code yourself and scan the folder."
    first = next((ln for ln in (stderr or "").splitlines() if ln.strip()), "no details")
    return f"git could not download the repository ({first.strip()[:150]}). You can download the code yourself and scan the folder."


def _remove_readonly(func, path, _exc):
    os.chmod(path, stat.S_IWRITE)
    func(path)


def cleanup(path):
    shutil.rmtree(path, onerror=_remove_readonly)


def fetch(src, timeout=180):
    """Download a git source into a fresh temporary folder. Returns (folder_to_scan, temp_folder_to_delete)."""
    if safety.find_program("git") is None:
        raise SourceError("git is not installed on this computer, so I cannot download the repository. Install git from git-scm.com, or scan a folder you already have.")
    tmp = tempfile.mkdtemp(prefix="aibom-")
    try:
        return _clone(src, tmp, timeout), tmp
    except BaseException:  # any failure, and Ctrl-C during the download: the caller never gets tmp, so delete it here
        try:
            cleanup(tmp)
        except OSError:
            pass
        raise


def _clone(src, tmp, timeout):
    dest = os.path.join(tmp, src["name"])
    git = safety.find_program("git")
    cmd = [git, "clone", "--quiet", "--depth", "1", "--single-branch"] + (["--branch", src["branch"]] if src["branch"] else []) + [src["url"], dest]
    env = dict(safety.child_env(), GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never", GIT_ASKPASS="echo")  # never wait for a password in a live demo
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env, cwd=tmp)  # not the current folder, whose git config is untrusted
    except subprocess.TimeoutExpired:
        raise SourceError(f"Downloading took longer than {timeout} seconds, so I stopped. The repository may be very large or the connection slow. Try again, or scan a folder you already have.")
    if r.returncode != 0:
        raise SourceError(friendly_git_error(r.stderr, src["url"]))
    try:  # remember exactly which version was scanned, so links point at the same lines
        src["commit"] = subprocess.run([git, "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30, env=env, cwd=tmp).stdout.strip()
    except Exception:
        src["commit"] = ""
    return folder_in_clone(dest, src["subpath"])


def folder_in_clone(dest, subpath):
    """The folder to scan in a downloaded repository. A sub-folder must be really there, not a link or a path out of it."""
    if not subpath:
        return dest
    root = safety.inside_path(dest, subpath)
    if not root or not os.path.isdir(root):
        raise SourceError(f"The repository downloaded, but it has no folder called '{subpath}'.")
    return root


class Linker:
    """Builds a link to the exact line of a file on GitHub, GitLab or Bitbucket for the version that was scanned."""

    def __init__(self, url="", commit="", subpath=""):
        self.url = re.sub(r"^(https?://)[^/]*@", r"\1", (url or "").rstrip("/"))  # a token in a remote must not reach the results
        if self.url.endswith(".git"):
            self.url = self.url[:-4]
        self.commit = commit or ""
        self.subpath = (subpath or "").strip("/")
        m = re.match(r"^https://(github\.com|gitlab\.com|bitbucket\.org)/[^/]+/[^/]+$", self.url)
        self.host = m.group(1) if m else ""

    @property
    def ok(self):
        return bool(self.host and self.commit)

    def url_for(self, file, line=0):
        if not self.ok or not file:
            return ""
        path = quote((self.subpath + "/" if self.subpath else "") + file.lstrip("/"), safe="/")
        if self.host == "github.com":
            return f"{self.url}/blob/{self.commit}/{path}" + (f"#L{line}" if line else "")
        if self.host == "gitlab.com":
            return f"{self.url}/-/blob/{self.commit}/{path}" + (f"#L{line}" if line else "")
        return f"{self.url}/src/{self.commit}/{path}" + (f"#lines-{line}" if line else "")

    def to_dict(self):
        return {"source_url": self.url, "source_commit": self.commit, "source_subpath": self.subpath}

    @classmethod
    def from_manifest(cls, info):
        return cls(info.get("source_url", ""), info.get("source_commit", ""), info.get("source_subpath", ""))

    @classmethod
    def for_saved_app(cls, app):
        """The saved test apps: look the repository and version up in benchmark/repos.json."""
        import json
        p = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "benchmark", "repos.json")
        try:
            with open(p, encoding="utf-8") as f:
                for r in json.load(f)["repos"]:
                    if r["name"] == app:
                        return cls(r["url"], r["commit"])
        except (OSError, KeyError, ValueError):
            pass
        return cls()


GIT_SAFE = ("--no-pager", "-c", "core.fsmonitor=false", "-c", "core.hooksPath=" + os.devnull)
GIT_REDIRECTS = {"GIT_DIR", "GIT_WORK_TREE", "GIT_INDEX_FILE", "GIT_OBJECT_DIRECTORY", "GIT_COMMON_DIR"}
# The settings that decide whether a file counts as changed. Each takes one of a few words, so none can name a program.
GIT_PLAIN_SETTINGS = {"core.autocrlf": ("true", "false", "input"), "core.eol": ("lf", "crlf", "native"), "core.filemode": ("true", "false"),
                      "core.ignorecase": ("true", "false"), "core.symlinks": ("true", "false"), "core.longpaths": ("true", "false"),
                      "core.precomposeunicode": ("true", "false")}


def _git_env(folder):
    env = {k: v for k, v in safety.child_env(avoid=folder).items() if k.upper() not in GIT_REDIRECTS}
    env.update(GIT_OPTIONAL_LOCKS="0", GIT_NO_LAZY_FETCH="1", GIT_ALLOW_PROTOCOL="", GIT_TERMINAL_PROMPT="0")  # read only, no network
    return env


def _run_git(git, env, *args):
    """git's output, or None when it failed."""
    r = subprocess.run([git, *GIT_SAFE, *args], capture_output=True, encoding="utf-8", errors="replace", timeout=30, env=env, cwd=os.path.dirname(git))
    return r.stdout.strip() if r.returncode == 0 else None


def _unchanged(git, env, path, top, commit):
    """Is the working folder the same as its commit? `git status` runs whatever the folder's .git/config and hooks name
    (fsmonitor, filters, hooks), so it runs in an empty git folder that borrows only the index and the objects."""
    def ask(*args):
        return _run_git(git, env, "-C", path, *args) or ""

    def where(name):
        got = ask("rev-parse", "--git-path", name)
        return os.path.normpath(os.path.join(path, got)) if got else ""

    index, objects, exclude = where("index"), where("objects"), where("info/exclude")
    if not safety.plain_file(index) or not os.path.isdir(objects):
        return False
    with tempfile.TemporaryDirectory(prefix="aibom-git-") as own:
        for folder in ("objects", "refs", "info"):
            os.mkdir(os.path.join(own, folder))
        with open(os.path.join(own, "HEAD"), "w", newline="\n") as f:
            f.write(commit + "\n")
        with open(os.path.join(own, "config"), "w", newline="\n") as f:
            f.write("[core]\n\trepositoryformatversion = 0\n\tbare = false\n")
            for key, words in GIT_PLAIN_SETTINGS.items():
                value = ask("config", "--get", key).lower()
                if value in words:
                    f.write("\t%s = %s\n" % (key.split(".")[1], value))
        shutil.copy2(index, os.path.join(own, "index"))  # copy2: git compares times with the index file's own
        if safety.plain_file(exclude):
            shutil.copy2(exclude, os.path.join(own, "info", "exclude"))
        changed = _run_git(git, dict(env, GIT_OBJECT_DIRECTORY=objects), "--git-dir=" + own, "--work-tree=" + top, "-C", top,
                           "status", "--porcelain", "--untracked-files=normal", "--ignore-submodules=all")
    return changed == ""  # None (git could not tell) is not "unchanged"


def linker_for_git_folder(path):
    """A folder that is a git clone knows its own web address and version, so lines can link to the website.
    No link is made when the folder has uncommitted changes, because the line numbers might not match the website."""
    try:
        path = os.path.abspath(path)
        git = safety.find_program("git", avoid=path)
        if not git:
            return Linker()
        env = _git_env(path)

        def ask(*args):
            return _run_git(git, env, "-C", path, *args) or ""

        top = ask("rev-parse", "--show-toplevel")
        # core.worktree in the folder's config can point anywhere, so the top must be a real clone around the scanned folder.
        if not top or not os.path.exists(os.path.join(top, ".git")) or not safety.is_within(os.path.realpath(path), os.path.realpath(top)):
            return Linker()
        remote = ask("remote", "get-url", "origin")
        m = re.match(r"^git@([^:]+):(.+?)(?:\.git)?/?$", remote)
        if m:
            remote = "https://%s/%s" % (m.group(1), m.group(2))
        commit = ask("rev-parse", "HEAD")
        links = Linker(remote, commit, ask("rev-parse", "--show-prefix"))
        if links.ok and re.fullmatch(r"[0-9a-f]{40}", commit) and _unchanged(git, env, path, top, commit):
            return links
        return Linker()
    except (OSError, ValueError, subprocess.SubprocessError):
        return Linker()
