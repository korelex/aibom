"""Turn the report into a PDF with a web browser that is already installed (Chrome, Edge or Chromium), run without a window.

aibom has no PDF library of its own: the report is laid out as a web page, and the browser's own print engine writes the PDF.
That adds no dependency, and the PDF looks exactly like the page. When no browser is found the message says how to get the same
file by hand (open report.html, Print, Save as PDF).
"""
import os
import subprocess
import sys
import tempfile

from . import safety
from .safety import SourceError

WINDOWS = [r"%ProgramFiles%\Google\Chrome\Application\chrome.exe", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe",
           r"%LocalAppData%\Google\Chrome\Application\chrome.exe", r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe",
           r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"]
MACOS = ["/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge",
         "/Applications/Chromium.app/Contents/MacOS/Chromium"]
LINUX = ["google-chrome", "google-chrome-stable", "chromium", "chromium-browser", "microsoft-edge", "microsoft-edge-stable", "chrome"]


def find_browser():
    """The path of a Chrome-family browser, or None. AIBOM_BROWSER names one explicitly."""
    chosen = os.environ.get("AIBOM_BROWSER")
    if chosen:
        return os.path.abspath(chosen) if os.path.isfile(chosen) else safety.find_program(chosen)
    if os.name == "nt":
        for path in WINDOWS:
            path = os.path.expandvars(path)
            if os.path.isabs(path) and os.path.isfile(path):  # an unset variable would leave a relative path
                return path
    elif sys.platform == "darwin":
        for path in MACOS:
            if os.path.isfile(path):
                return path
    for name in LINUX:
        found = safety.find_program(name)
        if found:
            return found
    return None


def print_to_pdf(html_text, pdf_path, browser=None, timeout=180):
    """Write `html_text` as a PDF at `pdf_path`. Raises SourceError with what to do when it cannot."""
    browser = browser or find_browser()
    if not browser:
        raise SourceError("No Chrome, Edge or Chromium was found to make the PDF. Open report.html in a browser and use Print, Save as PDF "
                          "(the page prints cleanly), or set AIBOM_BROWSER to the browser's path.")
    with tempfile.TemporaryDirectory(prefix="aibom-pdf-") as tmp:
        page = os.path.join(tmp, "report.html")
        with open(page, "w", encoding="utf-8") as f:
            f.write(html_text)
        out = safety.output_file(pdf_path)
        os.makedirs(os.path.dirname(out), exist_ok=True)
        if os.path.exists(out):
            os.remove(out)
        cmd = [browser, "--headless=new", "--disable-gpu", "--no-pdf-header-footer", "--no-first-run", "--disable-extensions",
               "--user-data-dir=" + os.path.join(tmp, "profile"), "--print-to-pdf=" + out, "file:///" + page.replace(os.sep, "/").lstrip("/")]
        if hasattr(os, "geteuid") and os.geteuid() == 0:  # a container running as root: Chromium refuses to start its sandbox there
            cmd.insert(1, "--no-sandbox")
        try:
            done = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=safety.child_env())
        except subprocess.TimeoutExpired:
            raise SourceError("The browser did not finish making the PDF in %d seconds. Try again, or print report.html from a browser." % timeout)
        except OSError as e:
            raise SourceError("The browser could not be started (%s). Open report.html in a browser and use Print, Save as PDF." % e)
        ok = os.path.isfile(out) and os.path.getsize(out) > 1000
        if ok:
            with open(out, "rb") as f:
                ok = f.read(5) == b"%PDF-"
        if not ok:
            raise SourceError("The browser ran but did not write a PDF (exit %s). Open report.html in a browser and use Print, Save as PDF. %s"
                              % (done.returncode, (done.stderr or "").strip()[-200:]))
    return out
