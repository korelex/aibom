"""Colour and layout for a terminal.

Everything pretty is drawn here, and only when a person is looking at a terminal. In a pipe, in CI, with NO_COLOR, with
`--plain` or AIBOM_PLAIN, or on a "dumb" terminal, aibom prints the plain text it always printed, so a script or a saved log
never contains escape codes or characters that depend on the font.

The palette is the one every screen shares: a severity has one colour everywhere (critical = solid red badge, high = red,
medium = yellow, low = cyan, unknown = dim), and the evidence that code uses a package has one too (called = green,
imported = yellow, declared = dim).
"""
import os
import sys

from rich.console import Console
from rich.style import Style
from rich.text import Text

_plain = False
_override = None

SEVERITIES = ("critical", "high", "medium", "low", "unknown")
SEVERITY = {  # label, the style of a badge, the style of a dot or a word
    "critical": ("CRITICAL", "bold white on red3", "bold bright_red"),
    "high": ("HIGH", "bold bright_red on grey11", "red"),
    "medium": ("MEDIUM", "bold yellow on grey11", "yellow"),
    "low": ("LOW", "bold cyan on grey11", "cyan"),
    "unknown": ("UNKNOWN", "dim on grey11", "dim"),
}
EVIDENCE = {"called": "green", "imported": "yellow", "declared": "dim"}
ACCENT = "cyan"


def set_plain(on=True):
    """Never be pretty (the `--plain` option)."""
    global _plain
    _plain = bool(on)


def pretty(stream=None):
    """Whether to draw colour and boxes: only on a terminal, and only when nobody has asked for plain text."""
    if _plain or os.environ.get("NO_COLOR") or os.environ.get("AIBOM_PLAIN") or os.environ.get("TERM", "").lower() == "dumb":
        return False
    try:
        return bool((stream if stream is not None else sys.stdout).isatty())
    except (AttributeError, ValueError):
        return False


def use_console(console):
    """Draw on this console (the tests record what is drawn); None goes back to the real terminal."""
    global _override
    _override = console


def console():
    """The console to draw on. Created each time so it follows the current stdout; data is never read as markup."""
    return _override or Console(highlight=False, markup=False, emoji=False)


def text(*parts):
    """A Text from (string, style) pairs and plain strings."""
    return Text.assemble(*parts)


def link(label, url):
    """A clickable label in terminals that support links (Windows Terminal, iTerm2, VS Code); plain text elsewhere."""
    return Text(str(label), style=Style(link=url)) if url else Text(str(label))


def severity_label(severity):
    return SEVERITY.get(severity, SEVERITY["unknown"])[0]


def badge(severity):
    """` CRITICAL ` as a coloured chip."""
    label, chip, _ = SEVERITY.get(severity, SEVERITY["unknown"])
    return Text(" %s " % label, style=chip)


def dot(severity):
    return Text("●", style=SEVERITY.get(severity, SEVERITY["unknown"])[2])


def severity_counts(counts, skip_zero=False):
    """`● 2 critical   ● 18 high ...`"""
    parts = []
    for sev in SEVERITIES:
        n = counts.get(sev, 0)
        if sev == "unknown" and not n:
            continue
        if skip_zero and not n:
            continue
        if parts:
            parts.append("   ")
        parts += [dot(sev), " %d %s" % (n, sev)]
    return Text.assemble(*parts)


def bar_widths(counts, width=40):
    """How many characters each severity gets in a bar `width` wide: in proportion, every severity that has findings gets at
    least one, and the widths add up to exactly `width`."""
    keys = [s for s in SEVERITIES if counts.get(s, 0)]
    total = sum(counts[s] for s in keys)
    if not total or width < len(keys):
        return {}
    widths = {s: max(1, int(width * counts[s] / total)) for s in keys}
    while sum(widths.values()) > width:  # the minimum of one can overshoot: take from the widest
        widths[max(widths, key=widths.get)] -= 1
    rest = sorted(keys, key=lambda s: (width * counts[s] / total) % 1, reverse=True)
    i = 0
    while sum(widths.values()) < width:
        widths[rest[i % len(rest)]] += 1
        i += 1
    return widths


def severity_bar(counts, width=40):
    """A stacked bar of the severities, worst first."""
    out = []
    for sev, w in sorted(bar_widths(counts, width).items(), key=lambda kv: SEVERITIES.index(kv[0])):
        out.append(Text("█" * w, style=SEVERITY[sev][2] if sev != "unknown" else "grey50"))
    return Text.assemble(*out)


def level_text(level, declared=True):
    """`called`, `imported` or `declared` in the colour of the evidence; a star when the package is not in a dependency file."""
    return Text(level + ("" if declared else " *"), style=EVIDENCE.get(level, "dim"))


WORDMARK = ("┌─┐┬┌┐ ┌─┐┌┬┐",
            "├─┤│├┴┐│ ││││",
            "┴ ┴┴└─┘└─┘┴ ┴")


def banner(version, data_line=""):
    """The wordmark with what the tool is, its version and the dates of its data."""
    lines = [Text(WORDMARK[0], style=ACCENT) + Text("   AI-BOM for your code", style="bold"),
             Text(WORDMARK[1], style=ACCENT) + Text("   finds the AI models and AI packages in an app, and proves each with a line of code", style="dim"),
             Text(WORDMARK[2], style=ACCENT) + Text("   v%s%s" % (version, "  ·  " + data_line if data_line else ""), style="dim")]
    return Text("\n").join(lines)
