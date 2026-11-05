"""Finder A: look for known AI model names in every file that can hold one.
Idea: scanners look for SDK calls, but model names also sit in UI lists, defaults and config files.

Two ways to match:
  1. The name as written: gpt-4o-mini, anthropic:claude-3-opus, openai/gpt-4o.
  2. A constant that spells the name: GPT_4_O_MINI, Gpt4oMini. Squash it to letters and digits (gpt4omini)
     and compare with the squashed dictionary names. The result is marked 'inferred' later,
     because the name is worked out from an identifier, not written out."""
import json
import os
import re
import time

from ..finding import Finding
from ..merge import VENDORS
from ..triage import read_lines

SCAN = {"code", "config", "manifest", "notebook", "test", "docs", "data"}
IDENT_SCAN = {"code", "config", "notebook", "test"}
TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:/-]*[A-Za-z0-9]")
IDENT = re.compile(r"(?<![A-Za-z0-9_\-])(?<!\d\.)[A-Za-z][A-Za-z0-9_]{5,}(?![A-Za-z0-9_\-])(?!\.\d)")  # Class.CONSTANT is fine; llama3 inside llama3.1 or llama3-8b is not
KNOWLEDGE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "..", "knowledge", "model_names.json")


def load_names(path=KNOWLEDGE):
    with open(path, encoding="utf-8") as f:
        return json.load(f)["names"]


def squash(s):
    return re.sub(r"[^a-z0-9]", "", s.lower())


def build_squash_index(names):
    """squashed text -> dictionary name. Prefer the hyphenated, shorter spelling."""
    idx = {}
    for n in sorted(names):
        s = squash(n)
        if len(s) < 6:
            continue
        cur = idx.get(s)
        rank = lambda x: (("-" in x), ("." in x), -len(x))   # hyphenated first, then dotted (the official spelling), then shorter
        if cur is None or rank(n) > rank(cur):
            idx[s] = n
    return idx


def candidates(token):
    """A token like 'anthropic:claude-3-opus' or 'openai/gpt-4o' can hide a model name after a separator.
    The part after a separator counts only when the part before it is a known provider or vendor
    (so 'results/gpt-4o-mini' is a folder, not a model)."""
    out = {token}
    for sep in ("/", ":"):
        if sep in token:
            head, tail = token.rsplit(sep, 1)
            last = re.split(r"[/:]", head)[-1].lower().replace("_", "-")
            if last in VENDORS:
                out.add(tail)
    if ":" in token:
        out.add(token.split(":")[0])
    return out


def run(root, files, names=None, deadline=None):
    names = names or load_names()
    squashed = build_squash_index(names)
    found, seen = [], set()
    for fi in files:
        if fi.category not in SCAN:
            continue
        if deadline and time.time() > deadline:
            break
        for ln, line in enumerate(read_lines(root, fi), 1):
            if len(line) > 800:
                continue
            for m in TOKEN.finditer(line):
                tok = m.group(0)
                for c in candidates(tok):
                    if c in names and (c, fi.path, ln) not in seen:
                        seen.add((c, fi.path, ln))
                        found.append(Finding("dictionary", "model", c, fi.path, ln, names[c].get("provider", ""), fi.category, line.strip()[:140], m.start() + max(tok.find(c), 0)))
            if fi.category in IDENT_SCAN:
                for m in IDENT.finditer(line):
                    t = m.group(0)
                    if "_" not in t and not any(ch.isdigit() for ch in t):
                        continue
                    canon = squashed.get(squash(t))
                    if canon and (canon, fi.path, ln) not in seen:
                        seen.add((canon, fi.path, ln))
                        found.append(Finding("dictionary", "model", canon, fi.path, ln, "identifier:" + t, fi.category, line.strip()[:140], m.start()))
    return found
