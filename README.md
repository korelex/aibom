# aibom

**Know what AI is in your code.**

aibom scans a repository and builds an AI Bill of Materials: every model,
AI SDK, agent framework, MCP server, vector database and dataset your code
depends on, with the file and line where each one is used.

It also flags the obvious risks: unpinned model versions, pickle-based model
files that can execute code, unpinned MCP servers, hardcoded AI provider keys,
and models with non-commercial or restricted licenses.

- **Standards-based:** outputs CycloneDX 1.6 ML-BOM, SARIF, JSON and Markdown
- **Private by default:** runs fully offline, with no telemetry; your code never leaves your machine
- **CI-ready:** a GitHub Action and exit codes to fail builds on risky AI changes

    pipx install aibom
    aibom scan .

Built and maintained by [Korelex](https://korelex.ai), an AI security company.
