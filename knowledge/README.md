# Knowledge files
- `model_names.json`: known AI model names, built from LiteLLM's model list (MIT license, Copyright (c) 2023 Berri AI).
  Refresh with `python scripts/build_dictionary.py`. Names shorter than 5 characters, or with no digit and no hyphen, are dropped to avoid ordinary words.
