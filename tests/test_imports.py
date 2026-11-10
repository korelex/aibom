"""Imports in live code (M2.2): Python through its own parser, JavaScript/TypeScript by pattern with comments removed."""
import json
import unittest

from test_packages import Case, by_name


class PythonImports(Case):
    files = {
        "requirements.txt": "openai==1.30.0\nopenai-agents==0.1.0\n",
        "app/main.py": '''
            """This module talks to models. Example: import anthropic"""  # a docstring is not an import
            import os
            # import cohere
            from openai import OpenAI
            from langchain_community.vectorstores import Chroma
            from llama_index.llms.openai import OpenAI as LlamaOpenAI
            from langchain_groq import ChatGroq
            from google.genai import types
            from . import helpers
            from .agents import planner
            import agents

            def lazy():
                import transformers
            ''',
        "app/agents/__init__.py": "",
        "tools/broken.py": "print 'this is python 2'\nimport mistralai\n",
        "tests/test_main.py": "import anthropic\n",
        "docs/example.py": "import cohere\n",
    }

    def names(self):
        return {c["name"]: c for c in self.result["packages"]}

    def test_imports_are_found_with_their_line(self):
        openai = self.pkg("openai")
        self.assertEqual(openai["evidence_level"], "imported")
        self.assertEqual([(i["file"], i["line"]) for i in openai["imports"]], [("app/main.py", 4)])

    def test_submodules_and_families(self):
        names = self.names()
        self.assertIn("langchain-community", names)
        self.assertIn("llama-index-llms-openai", names)
        self.assertIn("langchain-groq", names)
        self.assertIn("google-genai", names)
        self.assertIn("transformers", names)  # an import inside a function still counts

    def test_comments_docstrings_and_relative_imports_do_not_count(self):
        names = self.names()
        self.assertNotIn("cohere", [n for n, c in names.items() if not c["left_out"]])
        self.assertNotIn("anthropic", [n for n, c in names.items() if not c["left_out"]])

    def test_a_file_that_is_not_python_3_still_gives_its_imports(self):
        self.assertEqual(self.pkg("mistralai")["imports"][0]["file"], "tools/broken.py")

    def test_imports_in_tests_and_docs_are_left_out_with_the_reason(self):
        self.assertEqual(self.pkg("anthropic")["left_out"], "test")
        self.assertEqual(self.pkg("cohere")["left_out"], "docs")

    def test_a_declared_package_with_a_generic_import_name_counts(self):
        # "agents" is declared (openai-agents), so the import counts even though app/agents/ exists.
        self.assertEqual(self.pkg("openai-agents")["evidence_level"], "imported")

    def test_imported_but_not_declared(self):
        groq = self.pkg("langchain-groq")
        self.assertFalse(groq["declared"])
        self.assertEqual(groq["version"], "")


class LlamaIndexNaming(Case):
    files = {
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["llama-index-storage-index-store-postgres>=0.4"]\n',
        "app.py": """
            from llama_index.storage.index_store.postgres import PostgresIndexStore
            from llama_index.storage.kvstore.postgres import PostgresKVStore
            from llama_index.llms.openai.base import OpenAI
            from llama_index.vector_stores.qdrant import QdrantVectorStore
            """,
    }

    def test_integration_packages_are_named_from_the_module_path(self):
        names = {c["name"] for c in self.result["packages"]}
        self.assertIn("llama-index-storage-index-store-postgres", names)  # declared, so preferred
        self.assertIn("llama-index-storage-kvstore-postgres", names)      # storage integrations are one level deeper
        self.assertIn("llama-index-llms-openai", names)                   # a submodule of the integration
        self.assertIn("llama-index-vector-stores-qdrant", names)
        self.assertNotIn("llama-index-storage-index-store", names)


class FamilyModuleAloneInAFile(Case):
    files = {
        "pyproject.toml": '[project]\nname = "x"\ndependencies = ["llama-index-workflows>=1", "llama-index-instrumentation>=0.1"]\n',
        "groq_only.py": "from langchain_groq import ChatGroq\n",
        "tracing.py": "from llama_index_instrumentation import get_dispatcher\n",
        "events.py": "from workflows.events import Event\n",
    }

    def test_a_file_whose_only_ai_import_is_a_family_module_is_read(self):
        names = {c["name"] for c in self.result["packages"]}
        self.assertIn("langchain-groq", names)
        self.assertIn("llama-index-instrumentation", names)  # llama_index_<x> written with underscores
        self.assertIn("llama-index-workflows", names)       # its module is called "workflows"


class GenericNameThatIsTheProjectsOwn(Case):
    files = {
        "llm.py": "def ask(): ...\n",
        "main.py": "import llm\nimport agents\n",
        "agents/__init__.py": "",
    }

    def test_a_local_module_is_not_reported_as_an_ai_package(self):
        self.assertEqual(self.result["packages"], [])


class SharedImportName(Case):
    files = {
        "requirements.txt": "pinecone-client==3.0.0\n",
        "main.py": "import pinecone\n",
    }

    def test_the_declared_package_wins(self):
        self.assertEqual(self.pkg("pinecone-client")["evidence_level"], "imported")
        self.assertNotIn("pinecone", {c["name"] for c in self.result["packages"]})


class Notebook(Case):
    files = {
        "notebooks/demo.ipynb": json.dumps({"cells": [
            {"cell_type": "markdown", "source": ["import anthropic is how you start"]},
            {"cell_type": "code", "source": ["!pip install openai\n", "from openai import OpenAI\n", "client = OpenAI()\n"]},
        ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1),
    }

    def test_code_cells_only_with_the_line_in_the_file(self):
        openai = self.pkg("openai")
        hit = openai["imports"][0]
        with open(f"{self.repo.tmp.name}/{hit['file']}", encoding="utf-8") as fh:
            self.assertIn("from openai import OpenAI", fh.read().split("\n")[hit["line"] - 1])
        self.assertNotIn("anthropic", {c["name"] for c in self.result["packages"]})


class JavaScriptImports(Case):
    files = {
        "package.json": json.dumps({"dependencies": {"openai": "^4.0.0", "@langchain/core": "^0.2.0"}}, indent=2),
        "src/app.ts": """
            import OpenAI from "openai";
            import { ChatPromptTemplate } from "@langchain/core/prompts";
            import type { Message } from '@anthropic-ai/sdk';
            export { streamText } from "ai";
            import "@ai-sdk/openai";
            const cohere = require('cohere-ai');
            const lazy = await import("@mistralai/mistralai");
            // import { Pinecone } from "@pinecone-database/pinecone";
            /* import Groq from "groq-sdk"; */
            import { helper } from "./helper";
            import { Button } from "@/components/button";
            import {
              ChatOpenAI,
            } from "@langchain/openai";
            """,
        "src/app.test.ts": 'import Anthropic from "@anthropic-ai/sdk";\n',
    }

    def test_every_import_form(self):
        names = {c["name"] for c in self.result["packages"] if not c["left_out"]}
        for expected in ("openai", "@langchain/core", "@anthropic-ai/sdk", "ai", "@ai-sdk/openai", "cohere-ai", "@mistralai/mistralai",
                         "@langchain/openai"):
            self.assertIn(expected, names)

    def test_commented_out_imports_do_not_count(self):
        names = {c["name"] for c in self.result["packages"]}
        self.assertNotIn("@pinecone-database/pinecone", names)
        self.assertNotIn("groq-sdk", names)

    def test_subpath_imports_belong_to_the_package_and_lines_are_right(self):
        core = self.pkg("@langchain/core")
        self.assertEqual((core["evidence_level"], core["imports"][0]["line"]), ("imported", 2))
        # a multi-line import: the line that names the package ('} from "@langchain/openai"'), so the proof shows it
        self.assertEqual(self.pkg("@langchain/openai")["imports"][0]["line"], 14)

    def test_an_import_in_a_test_does_not_raise_the_level(self):
        sdk = self.pkg("@anthropic-ai/sdk")
        self.assertEqual(sdk["evidence_level"], "imported")  # src/app.ts imports it too
        self.assertEqual({i["left_out"] for i in sdk["imports"]}, {"", "test"})


if __name__ == "__main__":
    unittest.main()
