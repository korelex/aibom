"""Identifiers shared by the scan and the AI-BOM, so a flag can name the exact component it is about."""


def slug(s):
    return "".join(c if c.isalnum() or c in "-._" else "-" for c in str(s).lower())
