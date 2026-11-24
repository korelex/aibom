"""The last step before anything is written or printed: no key value leaves the scan.

`redact` masks a credential inside a quoted line of code. A key can also BE a name: typed where a model name goes, used as a
file or setting name, part of a package name, and then lower-cased into an id. So the results as a whole are cleaned here,
in one place, rather than in each detector.

Two kinds of value are hidden: text in a well-known key format, and any value a detector judged to be a credential in this
scan (those are held in memory only, to be matched, and are never saved). Each distinct value becomes `hidden-key-N`, so two
different keys stay two different things and no id or path collides.

The scanned repository chooses those judged values, so they are trusted with little: they never rename a field, never drop a
name from the results, and are searched for only when they cannot be a word of aibom's own ("critical", "left_out"). Cleaning
runs after everything is decided, so it cannot change a flag or a verdict either.
"""
import re
from urllib.parse import quote

from .credentials import FORMATS, entropy, made_of_words
from .ids import slug

# Stricter than redact's patterns, because this also runs over paths and names: task-manager-running-in-production holds
# "sk-manager-running-in-production" and is not a key.
MORE_FORMATS = (r"gh[pousr]_[A-Za-z0-9]{36,}", r"github_pat_[A-Za-z0-9_]{40,}", r"xox[baprs]-[0-9]{6,}-[A-Za-z0-9-]{10,}",
                r"sk-(?=[A-Za-z]*[0-9])[A-Za-z0-9]{32,}", r"eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")
SHAPE = re.compile("(?<![A-Za-z0-9])(?:" + "|".join([p for _, _, p, _ in FORMATS] + list(MORE_FORMATS)) + ")(?![A-Za-z0-9])")
MIN_ENTROPY = 2.5                     # below it a value is xxxx or 0000, which hides nothing
SHORTEST = 8                          # a shorter value is too likely to be a word
CUT_LENGTHS = (80, 140, 200)          # where detectors cut the text they quote; a key there can be left half
SHORTEST_CUT = 6


def key_shaped(text):
    """The values in `text` that have a key's format. A placeholder word does not exempt one: real keys hold "xxx" by chance."""
    found = []
    for m in SHAPE.finditer(text):
        value = m.group(0)
        if entropy(value) >= MIN_ENTROPY and not made_of_words(value):
            found.append(value)
    return found


def _forms(value):
    """The ways one value is spelt in results: as written, as in a package name, as in an id, as in a URL."""
    forms = {value, slug(value), quote(value, safe="/"), quote(value, safe="")}
    for joiner in "-_.":
        forms.add(re.sub(r"[-_.]+", joiner, value.lower()))
    return {f for f in forms if len(f) >= SHORTEST}


def _searchable(value):
    """Can this value be searched for everywhere? It needs a digit, or to be a long run of mixed-case letters: no word of the
    reports' own (a severity, a tier, a field) is either."""
    if len(value) < SHORTEST:
        return False
    return any(c.isdigit() for c in value) or (len(value) >= 16 and value.isalpha() and value != value.lower() and value != value.upper())


def _strings(data):
    if isinstance(data, str):
        yield data
    elif isinstance(data, dict):
        for key, value in data.items():
            yield from _strings(key)
            yield from _strings(value)
    elif isinstance(data, (list, tuple)):
        for value in data:
            yield from _strings(value)


class Hider:
    def __init__(self, values=()):
        self.values = {v for v in values if isinstance(v, str) and _searchable(v)}

    def is_key(self, name):
        """Is this name a key, or does it hold one? Then it is not the name of a model."""
        return bool(key_shaped(str(name)))

    def clean(self, data):
        """`data` with every key value replaced. When there is none, `data` itself."""
        texts = list(_strings(data))
        everything = "\n".join(texts)
        shaped = set(key_shaped(everything))
        values = self.values | shaped
        if not values:
            return data
        low = everything.lower()
        numbers, spelt, in_fields = {}, {}, set()
        ends = [t for t in texts if len(t) in CUT_LENGTHS]
        for value in sorted(values):
            present = [f for f in _forms(value) if f.lower() in low]
            halves = []
            for text in ends:
                for size in range(min(len(value) - 1, len(text)), SHORTEST_CUT - 1, -1):
                    if text.endswith(value[:size]):
                        halves.append(value[:size])
                        break
            if not present and not halves:
                continue
            label = numbers.setdefault(value.lower(), "hidden-key-%d" % (len(numbers) + 1))
            for form in present:
                spelt[form.lower()] = (label, False)
                if value in shaped:
                    in_fields.add(form.lower())
            for half in halves:
                spelt.setdefault(half.lower(), (label, True))
        if not spelt:
            return data
        # Longest first. A whole value must stand as a word of its own; a half counts only at the end of a cut text.
        parts = [r"(?<![A-Za-z0-9])" + re.escape(form) + (r"\Z" if half else r"(?![A-Za-z0-9])")
                 for form, (_, half) in sorted(spelt.items(), key=lambda item: -len(item[0]))]
        pattern = re.compile("|".join(parts), re.I)

        def change(text, field=False):
            def hidden(m):
                found = m.group(0).lower()
                label, half = spelt.get(found, ("hidden-key", False))
                if (field and found not in in_fields) or (half and len(text) not in CUT_LENGTHS):
                    return m.group(0)
                return label
            return pattern.sub(hidden, text)

        return _replace(data, change)


def _replace(data, change):
    if isinstance(data, str):
        return change(data)
    if isinstance(data, dict):
        return {change(k, True) if isinstance(k, str) else k: _replace(v, change) for k, v in data.items()}
    if isinstance(data, list):
        return [_replace(v, change) for v in data]
    if isinstance(data, tuple):
        return tuple(_replace(v, change) for v in data)
    return data


def hide(data):
    """Clean text or saved results that come without a scan's own values, by format alone."""
    return Hider().clean(data)
