"""Which project a dependency file or a line of code belongs to :
the repository's own packages, which manifests a lockfile installs, code with no manifest of its own, folders that look
vendored, and lockfiles that hold several versions of one package."""
import json
import unittest

from test_packages import Case


def names(result):
    return {(c["name"], c["version"]) for c in result["packages"] if not c["left_out"]}


class OwnWorkspacePackages(Case):
    files = {
        "package.json": json.dumps({"name": "@acme/servers", "workspaces": ["src/*"],
                                    "dependencies": {"@modelcontextprotocol/server-memory": "*"}}, indent=2),
        "src/memory/package.json": json.dumps({"name": "@modelcontextprotocol/server-memory",
                                               "dependencies": {"@modelcontextprotocol/sdk": "^1.0.0"}}, indent=2),
        "src/memory/index.ts": 'import { McpServer } from "@modelcontextprotocol/sdk/server/mcp.js";\nnew McpServer({});\n',
    }

    def test_the_repositorys_own_packages_are_not_dependencies(self):
        got = {n for n, _ in names(self.result)}
        self.assertNotIn("@modelcontextprotocol/server-memory", got)
        self.assertIn("@modelcontextprotocol/sdk", got)


class LockfileCoversOnlyItsMembers(Case):
    files = {
        "app/package.json": json.dumps({"name": "app", "dependencies": {"openai": "^4.0.0"}}, indent=2),
        "app/pnpm-workspace.yaml": "packages:\n  - \".\"\n",
        "app/pnpm-lock.yaml": "lockfileVersion: '9.0'\nimporters:\n  .:\n    dependencies:\n      openai:\n        specifier: ^4.0.0\n        version: 4.104.0\n"
                              "packages:\n  openai@4.104.0:\n    resolution: {integrity: sha512-x}\n",
        "app/src/oss/package.json": json.dumps({"name": "app-oss", "dependencies": {"openai": "^4.28.0"}}, indent=2),
        "app/src/oss/llm.ts": 'import OpenAI from "openai";\nconst client = new OpenAI();\n',
        "mono/package.json": json.dumps({"name": "mono", "workspaces": ["packages/*"]}, indent=2),
        "mono/package-lock.json": json.dumps({"lockfileVersion": 3, "packages": {
            "": {"name": "mono", "workspaces": ["packages/*"]},
            "packages/a": {"name": "a", "dependencies": {"ai": "^4.0.0"}},
            "node_modules/ai": {"version": "4.3.1"}}}, indent=2),
        "mono/packages/a/package.json": json.dumps({"name": "a", "dependencies": {"ai": "^4.0.0"}}, indent=2),
    }

    def test_a_nested_manifest_nothing_installs_from_keeps_its_range(self):
        self.assertIn(("openai", ""), names(self.result))         # app/src/oss: not a member of app's pnpm project
        self.assertIn(("openai", "4.104.0"), names(self.result))  # app itself

    def test_node_walks_up_to_the_installed_version(self):
        # app/src/oss/llm.ts is loaded with the version installed for app, as Node would resolve it
        installed = next(c for c in self.result["packages"] if c["name"] == "openai" and c["version"] == "4.104.0")
        self.assertEqual(installed["evidence_level"], "called")
        nested = next(c for c in self.result["packages"] if c["name"] == "openai" and c["version"] == "")
        self.assertEqual(nested["evidence_level"], "declared")

    def test_a_workspace_member_gets_the_lockfiles_version(self):
        self.assertIn(("ai", "4.3.1"), names(self.result))
        self.assertNotIn(("ai", ""), names(self.result))


class CodeWithoutItsOwnManifest(Case):
    files = {
        "crews/a/pyproject.toml": '[project]\nname = "a"\ndependencies = ["crewai>=0.1"]\n',
        "crews/a/uv.lock": 'version = 1\n[[package]]\nname = "a"\nversion = "0.1.0"\nsource = { editable = "." }\n'
                           'dependencies = [{ name = "crewai" }]\n[[package]]\nname = "crewai"\nversion = "0.152.0"\n',
        "crews/a/main.py": "from crewai import Agent\nAgent()\n",
        "notebooks/demo.ipynb": json.dumps({"cells": [{"cell_type": "code", "source": ["from crewai import Agent\n", "Agent()\n"]}],
                                            "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1),
        "plugin/pyproject.toml": '[project]\nname = "plugin"\ndependencies = ["requests"]\n',
        "plugin/llm.py": "from crewai import Agent\nAgent()\n",
    }

    def test_each_file_gets_its_own_projects_version_or_none(self):
        got = {(c["name"], c["version"]): c for c in self.result["packages"] if c["name"] == "crewai"}
        self.assertEqual(set(got), {("crewai", "0.152.0"), ("crewai", "")})
        self.assertEqual({i["file"] for i in got[("crewai", "0.152.0")]["imports"]}, {"crews/a/main.py"})
        # the notebook folder has no manifest; plugin/ has one that does not list crewai: neither borrows 0.152.0
        self.assertEqual({i["file"] for i in got[("crewai", "")]["imports"]}, {"notebooks/demo.ipynb", "plugin/llm.py"})
        self.assertFalse(got[("crewai", "")]["declared"])


class ThirdPartyFolders(Case):
    files = {
        "third_party/Pinecone/rag.py": "from pinecone import Pinecone\nPinecone()\n",
        "third_party/libvec/LICENSE": "MIT License\n",
        "third_party/libvec/requirements.txt": "chromadb==0.5.0\n",
        "vendor/x/requirements.txt": "qdrant-client==1.9.0\n",
    }

    def test_vendored_only_where_copied_code_brings_a_license(self):
        by = {c["name"]: c["left_out"] for c in self.result["packages"]}
        self.assertEqual(by["pinecone"], "")            # integration code that happens to be called third_party
        self.assertEqual(by["chromadb"], "vendored")    # a copied library with its license
        self.assertEqual(by["qdrant-client"], "vendored")  # vendor/ is always vendored


class SeveralLockedVersions(Case):
    files = {
        "pyproject.toml": '[tool.poetry]\nname = "x"\n[tool.poetry.dependencies]\npython = "^3.9"\nredisvl = ">=0.1.0,<1.0.0"\n',
        "poetry.lock": '[[package]]\nname = "redisvl"\nversion = "0.3.6"\n\n[[package]]\nname = "redisvl"\nversion = "0.17.0"\n',
        "store.py": "from redisvl.index import SearchIndex\nSearchIndex.from_dict({})\n",
    }

    def test_a_range_joins_every_version_the_lockfile_installs(self):
        got = {c["version"] for c in self.result["packages"] if c["name"] == "redisvl"}
        self.assertEqual(got, {"0.3.6", "0.17.0"})  # no third, versionless duplicate


class LazyJavaScriptImports(Case):
    files = {
        "package.json": json.dumps({"name": "x", "dependencies": {"@pinecone-database/pinecone": "^8", "@zilliz/milvus2-sdk-node": "^3",
                                                                   "weaviate-client": "^3", "@google-cloud/aiplatform": "^6", "chromadb": "^3"}}, indent=2),
        "pinecone.ts": 'const sdk = await loadPeer("@pinecone-database/pinecone", "Pinecone", () => import("@pinecone-database/pinecone"));\n'
                       'this.client = new sdk.Pinecone({ apiKey });\n',
        "vertex.ts": 'const aiplatform: typeof import("@google-cloud/aiplatform") = await loadPeer(\n  "@google-cloud/aiplatform",\n'
                     '  "Vertex",\n  () => import("@google-cloud/aiplatform"),\n);\nconst client = new aiplatform.PredictionServiceClient({});\n',
        "milvus.ts": 'const sdk = require("@zilliz/milvus2-sdk-node");\nconst MilvusClient = sdk.MilvusClient;\nconst c = new MilvusClient({});\n',
        "weaviate.ts": 'const sdk = await loadPeer("weaviate-client", "W", () => import("weaviate-client"));\nconst weaviate = sdk.default;\n'
                       'await weaviate.connectToLocal({});\n',
        "chroma.ts": 'import("chromadb").then(({ ChromaClient }) => new ChromaClient({}));\n',
    }

    def test_each_lazy_form_is_followed_to_the_call(self):
        levels = {c["name"]: c["evidence_level"] for c in self.result["packages"]}
        for name in ("@pinecone-database/pinecone", "@google-cloud/aiplatform", "@zilliz/milvus2-sdk-node", "weaviate-client", "chromadb"):
            self.assertEqual(levels[name], "called", name)


class NewCallRules(Case):
    files = {
        "requirements.txt": "mcp==2.3.0\nlangchain-nvidia-ai-endpoints==1.0.4\ncrewai-tools==1.6.1\nvoyageai==0.3.5\n",
        "server.py": "from mcp.server import MCPServer\nserver = MCPServer('x')\n",
        "llm.py": "from langchain_nvidia_ai_endpoints import ChatNVIDIA\nllm = ChatNVIDIA(model='m')\n",
        "tools.py": "from crewai_tools import SerperDevTool\nsearch = SerperDevTool()\n",
        "embed.py": "import voyageai\nvo = voyageai.Client()\n",
        "package.json": json.dumps({"name": "y", "dependencies": {"@modelcontextprotocol/server": "^2", "@ai-sdk/react": "^4", "@ai-sdk/gateway": "^4"}}, indent=2),
        "mcp.ts": 'import { McpServer } from "@modelcontextprotocol/server";\nconst s = new McpServer({ name: "x" });\n',
        "chat.tsx": 'import { useChat } from "@ai-sdk/react";\nconst c = useChat({});\n',
        "gw.ts": 'import { createGateway } from "@ai-sdk/gateway";\nconst g = createGateway({});\n',
    }

    def test_entry_points_found_in_the_benchmark_are_calls(self):
        levels = {c["name"]: c["evidence_level"] for c in self.result["packages"]}
        for name in ("mcp", "langchain-nvidia-ai-endpoints", "crewai-tools", "voyageai", "@modelcontextprotocol/server", "@ai-sdk/react", "@ai-sdk/gateway"):
            self.assertEqual(levels.get(name), "called", name)


if __name__ == "__main__":
    unittest.main()
