"""Builds knowledge/model_names.json from LiteLLM's public model list (MIT license, (c) 2023 Berri AI).
Run again any time to refresh the list:  python scripts/build_dictionary.py [path-to-litellm-json]"""
import json
import os
import sys
import time
import urllib.request

URL = "https://raw.githubusercontent.com/BerriAI/litellm/main/model_prices_and_context_window.json"
HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "..", "knowledge", "model_names.json")


def usable(n):
    """Drop very generic words: need 5+ characters and a digit or a hyphen."""
    return len(n) >= 5 and (any(c.isdigit() for c in n) or "-" in n)


def main():
    if len(sys.argv) > 1:
        data = json.load(open(sys.argv[1], encoding="utf-8"))
        src = sys.argv[1]
    else:
        data = json.load(urllib.request.urlopen(URL, timeout=60))
        src = URL
    names = {}
    for key, v in data.items():
        if key == "sample_spec":
            continue
        for n in {key, key.split("/")[-1]}:
            if usable(n) and n not in names:
                names[n] = {"provider": v.get("litellm_provider", ""), "mode": v.get("mode", "")}
    out = {"meta": {"source": src, "license": "MIT, Copyright (c) 2023 Berri AI (LiteLLM)", "built": time.strftime("%Y-%m-%d"),
                    "entries_in_source": len(data) - 1, "names": len(names)}, "names": names}
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, indent=0, sort_keys=True)
    print("wrote", os.path.abspath(OUT), "-", len(names), "names")


if __name__ == "__main__":
    main()
