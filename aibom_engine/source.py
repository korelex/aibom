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


class SourceError(Exception):
    """A problem with the source that the user can fix. The message is written for a person."""


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
    if shutil.which("git") is None:
        raise SourceError("git is not installed on this computer, so I cannot download the repository. Install git from git-scm.com, or scan a folder you already have.")
    tmp = tempfile.mkdtemp(prefix="aibom-")
    dest = os.path.join(tmp, src["name"])
    cmd = ["git", "clone", "--quiet", "--depth", "1", "--single-branch"] + (["--branch", src["branch"]] if src["branch"] else []) + [src["url"], dest]
    env = dict(os.environ, GIT_TERMINAL_PROMPT="0", GCM_INTERACTIVE="never", GIT_ASKPASS="echo")  # never wait for a password in a live demo
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)
    except subprocess.TimeoutExpired:
        cleanup(tmp)
        raise SourceError(f"Downloading took longer than {timeout} seconds, so I stopped. The repository may be very large or the connection slow. Try again, or scan a folder you already have.")
    if r.returncode != 0:
        cleanup(tmp)
        raise SourceError(friendly_git_error(r.stderr, src["url"]))
    try:  # remember exactly which version was scanned, so links point at the same lines
        src["commit"] = subprocess.run(["git", "-C", dest, "rev-parse", "HEAD"], capture_output=True, text=True, timeout=30).stdout.strip()
    except Exception:
        src["commit"] = ""
    root = os.path.join(dest, src["subpath"]) if src["subpath"] else dest
    if not os.path.isdir(root):
        cleanup(tmp)
        raise SourceError(f"The repository downloaded, but it has no folder called '{src['subpath']}'.")
    return root, tmp


class Linker:
    """Builds a link to the exact line of a file on GitHub, GitLab or Bitbucket for the version that was scanned."""

    def __init__(self, url="", commit="", subpath=""):
        self.url = (url or "").rstrip("/")
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


def _git(path, *args):
    r = subprocess.run(["git", "-C", path] + list(args), capture_output=True, text=True, timeout=30)
    return r.stdout.strip() if r.returncode == 0 else ""


def linker_for_git_folder(path):
    """A folder that is a git clone knows its own web address and version, so lines can link to the website.
    No link is made when the folder has uncommitted changes, because the line numbers might not match the website."""
    try:
        if shutil.which("git") is None or not _git(path, "rev-parse", "--show-toplevel"):
            return Linker()
        if _git(path, "status", "--porcelain"):
            return Linker()
        remote = _git(path, "remote", "get-url", "origin")
        m = re.match(r"^git@([^:]+):(.+?)(?:\.git)?/?$", remote)
        if m:
            remote = "https://%s/%s" % (m.group(1), m.group(2))
        return Linker(remote, _git(path, "rev-parse", "HEAD"), _git(path, "rev-parse", "--show-prefix"))
    except (OSError, subprocess.SubprocessError):
        return Linker()
