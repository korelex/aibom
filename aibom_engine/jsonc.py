"""Read JSON that people write by hand, and remember the line of every key.

Editors accept comments and trailing commas in their settings files (`// a note`, `/* a note */`, `{"a": 1,}`), and a
scanner has to read those files as the editor does, so the standard `json` module is not enough. A line number is what
lets a finding say exactly where in a file something is.

`loads(text)` returns the value. Every object comes back as a `Node`, a dict that also knows `.lines`: {key: the 1-based
line the key is on}. Nothing is executed or evaluated; a file that is not JSON raises `JsoncError` with the line.
"""
import bisect
import json
import re
from json.decoder import scanstring

MAX_DEPTH = 100  # a hostile file of nothing but "[" must not crash the scan
_NUMBER = re.compile(r"-?(?:0|[1-9]\d*)(?:\.\d+)?(?:[eE][+-]?\d+)?")
_SPACE = " \t\r\n﻿"
_LITERALS = {"true": True, "false": False, "null": None}


class JsoncError(ValueError):
    def __init__(self, message, line):
        super().__init__(f"{message} (line {line})")
        self.line = line


class Node(dict):
    """A JSON object that remembers the line each key is on."""

    def __init__(self):
        super().__init__()
        self.lines = {}


class _Reader:
    def __init__(self, text):
        self.text = text
        self.starts = [0] + [m.end() for m in re.finditer("\n", text)]
        self.i = 0

    def line(self, pos=None):
        return bisect.bisect_right(self.starts, self.i if pos is None else pos)

    def fail(self, message):
        raise JsoncError(message, self.line())

    def skip(self):
        """Move past white space and comments."""
        t, n = self.text, len(self.text)
        while self.i < n:
            c = t[self.i]
            if c in _SPACE:
                self.i += 1
            elif t.startswith("//", self.i):
                end = t.find("\n", self.i)
                self.i = n if end < 0 else end + 1
            elif t.startswith("/*", self.i):
                end = t.find("*/", self.i + 2)
                if end < 0:
                    self.fail("a comment is never closed")
                self.i = end + 2
            else:
                return

    def value(self, depth):
        if depth > MAX_DEPTH:
            self.fail("nested too deeply")
        self.skip()
        if self.i >= len(self.text):
            self.fail("the file ends where a value was expected")
        c = self.text[self.i]
        if c == "{":
            return self.obj(depth)
        if c == "[":
            return self.arr(depth)
        if c == '"':
            return self.string()
        m = _NUMBER.match(self.text, self.i)
        if m:
            self.i = m.end()
            raw = m.group(0)
            return float(raw) if any(x in raw for x in ".eE") else int(raw)
        for word, val in _LITERALS.items():
            if self.text.startswith(word, self.i):
                self.i += len(word)
                return val
        self.fail(f"unexpected {c!a}")

    def string(self):
        try:
            s, end = scanstring(self.text, self.i + 1, True)
        except json.JSONDecodeError as e:
            self.fail(f"a string is not valid: {e.msg}")
        self.i = end
        return s

    def obj(self, depth):
        node = Node()
        self.i += 1
        while True:
            self.skip()
            if self.i >= len(self.text):
                self.fail("an object is never closed")
            if self.text[self.i] == "}":
                self.i += 1
                return node
            if self.text[self.i] != '"':
                self.fail("a key must be a quoted string")
            key_line = self.line()
            key = self.string()
            self.skip()
            if self.i >= len(self.text) or self.text[self.i] != ":":
                self.fail("a ':' is missing after a key")
            self.i += 1
            node[key] = self.value(depth + 1)
            node.lines[key] = key_line
            self.skip()
            if self.i < len(self.text) and self.text[self.i] == ",":
                self.i += 1
            elif self.i < len(self.text) and self.text[self.i] == "}":
                continue
            else:
                self.fail("a ',' or '}' is missing")

    def arr(self, depth):
        out = []
        self.i += 1
        while True:
            self.skip()
            if self.i >= len(self.text):
                self.fail("a list is never closed")
            if self.text[self.i] == "]":
                self.i += 1
                return out
            out.append(self.value(depth + 1))
            self.skip()
            if self.i < len(self.text) and self.text[self.i] == ",":
                self.i += 1
            elif self.i < len(self.text) and self.text[self.i] == "]":
                continue
            else:
                self.fail("a ',' or ']' is missing")


def loads(text):
    r = _Reader(text)
    value = r.value(0)
    r.skip()
    if r.i < len(text):
        r.fail("text after the end of the value")
    return value
