# Stress test: scanning from links

Checks that it does not crash and is fast enough. It does not measure accuracy (no answer keys for these repos).

| Link | What it tests | Result | Total seconds | Scan seconds | Used directly | Only listed | Left out | Note |
|---|---|---|---|---|---|---|---|---|
| openai/openai-cookbook | Python + notebooks, large | ok | 83 | 19.5 | 80 | 1 | 73 |  |
| huggingface/transformers | Python, very large, thousands of model names | ok | 106 | 95.46 | 373 | 31 | 464 |  |
| langchain-ai/langchain | Python monorepo | ok | 21 | 15.94 | 88 | 216 | 53 |  |
| ollama/ollama | Go, large | ok | 14 | 10.04 | 76 | 45 | 40 |  |
| microsoft/semantic-kernel | C#, very large | ok | 37 | 31.23 | 113 | 26 | 32 |  |
| BerriAI/litellm | Python, the source of our dictionary | ok | 146 | 125.63 | 284 | 239 | 856 |  |
| pallets/flask | Python, no AI at all | ok | 3 | 0.61 | 0 | 0 | 0 |  |
| octocat/Hello-World | tiny, almost no code | ok | 2 | 0.06 | 0 | 0 | 0 |  |
| langchain-ai/open_deep_research/tree/main/src/legacy | link to one folder | ok | 3 | 0.49 | 8 | 0 | 2 |  |
| octocat/this-repo-does-not-exist-12345 | broken link (should fail politely) | polite error | 2 | - | 0 | 0 | 0 | Problem: I could not open https://github.com/octocat/this-repo-does-not-exist-12345. The link may be wrong, or |
| not a link | nonsense input (should fail politely) | polite error | 2 | - | 0 | 0 | 0 | Problem: I could not find a folder or a git link called 'not a link'. Give me a folder on this computer, or a  |
