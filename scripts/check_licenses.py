"""Check curated model licenses against the license each Hugging Face repo declares (network; for maintainers).

Usage:  python scripts/check_licenses.py
Exit 0 when every curated model with a `hugging_face_id` matches what its repo declares, 1 otherwise.
A repo that cannot be read (removed, gated or offline) is reported, because its entry can no longer be verified.
"""
import json
import os
import sys
import urllib.request

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
CURATED = os.path.join(ROOT, "aibom_engine", "knowledge", "curated.json")

# Hugging Face license id (or license_name for license: other) -> our license id in curated.json
HF_TO_OURS = {
    "apache-2.0": "apache-2.0", "mit": "mit", "cc-by-nc-4.0": "cc-by-nc-4.0", "gemma": "gemma",
    "llama2": "llama2", "llama3": "llama3", "llama3.1": "llama3.1", "llama3.2": "llama3.2", "llama3.3": "llama3.3",
    "openrail": "openrail", "openrail++": "openrail++", "mrl": "mistral-research", "qwen": "qwen",
    "tongyi-qianwen-license-agreement": "tongyi-qianwen", "deepseek": "deepseek",
    "stabilityai-ai-community": "stabilityai-ai-community", "flux-1-dev-non-commercial-license": "flux-1-dev-non-commercial",
}


def declared(repo_id):
    url = f"https://huggingface.co/api/models/{repo_id}"
    req = urllib.request.Request(url, headers={"User-Agent": "aibom-license-check"})
    with urllib.request.urlopen(req, timeout=20) as resp:
        payload = json.loads(resp.read().decode("utf-8"))
    card = payload.get("cardData") or {}
    lic = card.get("license")
    if lic == "other":
        lic = card.get("license_name") or "other"
    if isinstance(lic, list):
        lic = lic[0] if lic else None
    if lic is None:
        # Some repos (for example DeepSeek-V3) ship the model license as a file instead of card metadata.
        files = [s.get("rfilename", "") for s in payload.get("siblings") or []]
        if "LICENSE-MODEL" in files:
            return "LICENSE-MODEL file"
    return lic


def main():
    with open(CURATED, encoding="utf-8") as fh:
        models = json.load(fh)["curated_models"]
    problems = 0
    for key, cm in sorted(models.items()):
        repo = cm.get("hugging_face_id")
        if not repo:
            continue
        try:
            theirs = declared(repo)
        except Exception as exc:  # noqa: BLE001 - report and keep going
            print(f"UNREADABLE  {repo}: {exc}")
            problems += 1
            continue
        expected = HF_TO_OURS.get(theirs)
        if cm.get("license_basis") == "license file" and theirs == "LICENSE-MODEL file":
            print(f"ok (file)   {repo}: {cm['license']} (read from the repo's LICENSE-MODEL)")
        elif expected == cm.get("license"):
            print(f"ok          {repo}: {cm['license']}")
        else:
            print(f"MISMATCH    {repo}: curated {cm.get('license')!r}, repo declares {theirs!r}")
            problems += 1
    print(f"\n{problems} problem(s)")
    sys.exit(1 if problems else 0)


if __name__ == "__main__":
    main()
