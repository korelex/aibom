"""Calls in live code (M2.3): a call counts only when an AI import in the same file bound the name being called."""
import json
import os
import unittest

import yaml

from aibom_engine.db import load_db, lookup_package
from aibom_engine.packages.calls import RULES_PATH, Rules, load_rules
from test_packages import Case, by_name


def calls(component):
    return [(c["file"], c["line"], c["rule"]) for c in component["calls"]]


class RequiredPythonCalls(Case):
    """Every call the M2 task list names, in the shapes real code writes them."""
    files = {
        "requirements.txt": "openai==1.30.0\nboto3==1.34.0\nlangchain-openai==0.1.0\n",
        "app/llm.py": """
            from openai import OpenAI, AzureOpenAI
            import anthropic
            from langchain_openai import ChatOpenAI
            from langchain_anthropic import ChatAnthropic

            client = OpenAI()
            azure = AzureOpenAI(api_version="2024-02-01")
            claude = anthropic.Anthropic()
            chat = ChatOpenAI(model="gpt-4o")
            sonnet = ChatAnthropic(model="claude-sonnet-4-5")
            """,
        "app/agents.py": """
            from crewai import Agent, Crew, Task
            from langgraph.prebuilt import create_react_agent
            from langgraph.graph import StateGraph

            researcher = Agent(role="researcher", goal="g", backstory="b")
            crew = Crew(agents=[researcher], tasks=[Task(description="d", agent=researcher)])
            agent = create_react_agent(model, tools=[])
            graph = StateGraph(dict)
            """,
        "app/store.py": """
            from langchain_community.vectorstores import Chroma
            from pinecone import Pinecone
            from qdrant_client import QdrantClient
            from transformers import AutoTokenizer, AutoModelForCausalLM

            db = Chroma.from_documents(docs, embedding)
            pc = Pinecone(api_key="x")
            qdrant = QdrantClient(url="http://localhost:6333")
            tok = AutoTokenizer.from_pretrained("gpt2")
            model = AutoModelForCausalLM.from_pretrained("gpt2")
            """,
        "app/bedrock.py": """
            import json
            import boto3

            class Bedrock:
                def __init__(self):
                    self.client = boto3.client("bedrock-runtime", region_name="us-east-1")
                    self.s3 = boto3.client("s3")

                def ask(self, prompt):
                    self.s3.put_object(Bucket="b", Key="k", Body=prompt)
                    return self.client.invoke_model(modelId="anthropic.claude-3-haiku-20240307-v1:0", body=json.dumps({}))
            """,
    }

    def test_llm_clients(self):
        self.assertEqual(calls(self.pkg("openai")), [("app/llm.py", 6, "openai.client"), ("app/llm.py", 7, "openai.client")])
        self.assertEqual(calls(self.pkg("anthropic")), [("app/llm.py", 8, "anthropic.client")])
        self.assertEqual(calls(self.pkg("langchain-openai")), [("app/llm.py", 9, "langchain.chat-models")])
        self.assertEqual(calls(self.pkg("langchain-anthropic")), [("app/llm.py", 10, "langchain.anthropic")])

    def test_agents(self):
        self.assertEqual([c[1] for c in calls(self.pkg("crewai"))], [5, 6, 6])  # Agent, Crew and the Task inside it
        self.assertEqual([c[1] for c in calls(self.pkg("langgraph"))], [7, 8])

    def test_vector_stores_and_model_loading(self):
        self.assertEqual(calls(self.pkg("langchain-community")), [("app/store.py", 6, "langchain.community")])
        self.assertEqual(calls(self.pkg("pinecone")), [("app/store.py", 7, "pinecone.client")])
        self.assertEqual(calls(self.pkg("qdrant-client")), [("app/store.py", 8, "qdrant.client")])
        self.assertEqual([c[1] for c in calls(self.pkg("transformers"))], [9, 10])

    def test_every_package_with_a_live_call_is_at_the_called_level(self):
        for c in self.result["packages"]:
            self.assertEqual(c["evidence_level"], "called", c["name"])
        self.assertEqual(self.result["summary"]["ai_called"], len(self.result["packages"]))

    def test_bedrock_through_boto3(self):
        boto3 = self.pkg("boto3")
        self.assertEqual((boto3["version"], boto3["declared"], boto3["services"]), ("1.34.0", True, ["Amazon Bedrock"]))
        self.assertEqual((boto3["category"], boto3["vendor"]), ("llm_sdk", "Amazon Web Services"))
        got = [(c["line"], c["operation"]) for c in boto3["calls"]]
        self.assertEqual(got, [(6, ""), (11, "invoke_model")])  # the S3 client and its put_object are not AI


class BotoWithoutBedrock(Case):
    files = {
        "requirements.txt": "boto3==1.34.0\n",
        "app.py": 'import boto3\ns3 = boto3.client("s3")\nddb = boto3.Session().client(service_name="dynamodb")\n',
    }

    def test_boto3_is_not_an_ai_package_when_it_calls_no_ai_service(self):
        self.assertEqual(self.result["packages"], [])


class BedrockUndeclaredWithSession(Case):
    files = {
        "app.py": """
            import boto3
            session = boto3.Session(profile_name="dev")
            runtime = session.client(service_name="bedrock-runtime")
            reply = runtime.converse(modelId="amazon.nova-lite-v1:0", messages=[])
            """,
    }

    def test_session_clients_and_converse(self):
        boto3 = self.pkg("boto3")
        self.assertFalse(boto3["declared"])
        self.assertEqual([(c["line"], c["operation"]) for c in boto3["calls"]], [(3, ""), (4, "converse")])


class MonorepoWithTwoVersions(Case):
    """Two services pin different versions; each file's import and call belong to its own service's version."""
    files = {
        "chat/requirements.txt": "openai==1.30.0\nboto3==1.40.0\n",
        "chat/app.py": 'import boto3\nfrom openai import OpenAI\nOpenAI()\nboto3.client("bedrock-runtime")\n',
        "export/requirements.txt": "openai==1.10.0\nboto3==1.34.0\n",
        "export/job.py": 'import boto3\nimport openai\nboto3.client("s3")\n',
    }

    def test_evidence_goes_to_the_nearest_project(self):
        self.assertEqual(self.pkg("openai", "1.30.0")["evidence_level"], "called")
        self.assertEqual([i["file"] for i in self.pkg("openai", "1.30.0")["imports"]], ["chat/app.py"])
        self.assertEqual([i["file"] for i in self.pkg("openai", "1.10.0")["imports"]], ["export/job.py"])
        self.assertEqual(self.pkg("openai", "1.10.0")["evidence_level"], "imported")

    def test_only_the_boto3_that_calls_bedrock_is_reported(self):
        self.assertEqual([c["version"] for c in self.result["packages"] if c["name"] == "boto3"], ["1.40.0"])


class NamesThatAreNotTheSdk(Case):
    files = {
        "requirements.txt": "crewai==0.80.0\nopenai==1.30.0\n",
        "app/main.py": """
            import openai
            from openai import OpenAI
            from crewai import Crew, Agent

            class Agent:            # the project's own class replaces the name crewai's import bound
                pass

            def OpenAI():           # and its own function
                return None

            a = Agent()
            b = OpenAI()
            # c = openai.OpenAI()
            text = "openai.OpenAI()"
            """,
        "app/other.py": "from mylib import Agent, Pinecone\nAgent()\nPinecone()\n",
    }

    def test_only_names_bound_by_an_ai_import_count(self):
        self.assertEqual(self.pkg("openai")["calls"], [])
        self.assertEqual(self.pkg("openai")["evidence_level"], "imported")
        self.assertEqual(self.pkg("crewai")["calls"], [])
        self.assertNotIn("pinecone", {c["name"] for c in self.result["packages"]})


class AliasesAndRebinding(Case):
    files = {
        "app.py": """
            import openai as oa
            import google.generativeai as genai
            from google import genai as gg
            from anthropic import Anthropic as Client

            Factory = oa.OpenAI
            first = Factory()
            second = Client()
            model = genai.GenerativeModel("gemini-1.5-flash")
            google_client = gg.Client()

            Factory = dict
            not_openai = Factory()
            """,
    }

    def test_aliases_and_assignments_are_followed(self):
        self.assertEqual([c["line"] for c in self.pkg("openai")["calls"]], [7])  # line 13 is Factory after it was rebound
        self.assertEqual([c["line"] for c in self.pkg("anthropic")["calls"]], [8])
        self.assertEqual([c["line"] for c in self.pkg("google-generativeai")["calls"]], [9])
        self.assertEqual([c["line"] for c in self.pkg("google-genai")["calls"]], [10])

    def test_from_google_import_genai_is_an_import_of_google_genai(self):
        self.assertEqual(self.pkg("google-genai")["imports"][0]["module"], "google.genai")


class SubclassesAndFamilies(Case):
    files = {
        "store.py": """
            from llama_index.vector_stores.qdrant import QdrantVectorStore
            from llama_index.embeddings.openai import OpenAIEmbedding
            from tiktoken import get_encoding

            class PatchedStore(QdrantVectorStore):
                pass

            def get_encoding():          # the project's own function with tiktoken's name
                return None

            store = PatchedStore(client=None, collection_name="docs")
            embed = OpenAIEmbedding(model="text-embedding-3-small")
            enc = get_encoding()
            """,
        "models.ts": "import { createMistral } from '@ai-sdk/mistral';\nconst m = createMistral({ apiKey })('mistral-large');\n",
    }

    def test_a_subclass_of_an_sdk_class_counts_as_that_class(self):
        self.assertEqual([c["line"] for c in self.pkg("llama-index-vector-stores-qdrant")["calls"]], [11])

    def test_family_rules_credit_the_imported_integration(self):
        self.assertEqual([c["line"] for c in self.pkg("llama-index-embeddings-openai")["calls"]], [12])
        self.assertEqual([c["line"] for c in self.pkg("@ai-sdk/mistral")["calls"]], [2])

    def test_a_local_function_with_an_sdk_name_is_not_the_sdk(self):
        self.assertEqual(self.pkg("tiktoken")["evidence_level"], "imported")


class CallsInTestsAreLeftOut(Case):
    files = {
        "requirements.txt": "anthropic==0.30.0\n",
        "src/app.py": "import anthropic\n",
        "tests/test_app.py": "import anthropic\nclient = anthropic.Anthropic()\n",
    }

    def test_a_call_in_a_test_does_not_raise_the_level(self):
        sdk = self.pkg("anthropic")
        self.assertEqual(sdk["evidence_level"], "imported")
        self.assertEqual([(c["file"], c["left_out"]) for c in sdk["calls"]], [("tests/test_app.py", "test")])


class NotebookCalls(Case):
    files = {
        "demo.ipynb": json.dumps({"cells": [
            {"cell_type": "code", "source": ["!pip install chromadb\n", "import chromadb\n"]},
            {"cell_type": "markdown", "source": ["chromadb.Client() is how you start"]},
            {"cell_type": "code", "source": ["client = chromadb.PersistentClient(path='db')\n"]},
        ], "metadata": {}, "nbformat": 4, "nbformat_minor": 5}, indent=1),
    }

    def test_names_carry_across_cells_and_lines_are_in_the_file(self):
        chroma = self.pkg("chromadb")
        self.assertEqual(len(chroma["calls"]), 1)
        hit = chroma["calls"][0]
        with open(os.path.join(self.repo.tmp.name, hit["file"]), encoding="utf-8") as fh:
            self.assertIn("chromadb.PersistentClient", fh.read().split("\n")[hit["line"] - 1])


class JavaScriptCalls(Case):
    files = {
        "package.json": json.dumps({"dependencies": {"openai": "^4", "ai": "^4", "@ai-sdk/openai": "^1"}}, indent=2),
        "src/app.ts": """
            import OpenAI, { AzureOpenAI } from "openai";
            import { generateText, type CoreMessage } from "ai";
            import { openai as provider } from "@ai-sdk/openai";
            import * as lg from "@langchain/langgraph";
            import { ChatAnthropic } from "@langchain/anthropic";
            const { Pinecone } = require("@pinecone-database/pinecone");
            import ollama from "ollama";

            const client = new OpenAI();
            const azure = new AzureOpenAI({ apiVersion: "2024-02-01" });
            const { text } = await generateText({ model: provider("gpt-4o"), prompt: "hi" });
            const graph = new lg.StateGraph<State>(annotation);
            const claude = new ChatAnthropic({ model: "claude-sonnet-4-5" });
            const pc = new Pinecone();
            const reply = await ollama.chat({ model: "llama3.2", messages: [] });
            // const commented = new OpenAI();
            const s = "new OpenAI()";
            function generateTextLike() {}
            """,
        "src/local.ts": 'import { Agent } from "./agent";\nconst a = new Agent();\n',
    }

    def test_every_call_form(self):
        self.assertEqual([c["line"] for c in self.pkg("openai")["calls"]], [9, 10])
        self.assertEqual([c["line"] for c in self.pkg("ai")["calls"]], [11])
        self.assertEqual([c["line"] for c in self.pkg("@ai-sdk/openai")["calls"]], [11])
        self.assertEqual([c["line"] for c in self.pkg("@langchain/langgraph")["calls"]], [12])
        self.assertEqual([c["line"] for c in self.pkg("@langchain/anthropic")["calls"]], [13])
        self.assertEqual([c["line"] for c in self.pkg("@pinecone-database/pinecone")["calls"]], [14])
        self.assertEqual([c["line"] for c in self.pkg("ollama")["calls"]], [15])


class JavaScriptVectorDatabases(Case):
    """The JavaScript forms of these vector databases, which had only Python rules before."""
    files = {
        "package.json": json.dumps({"dependencies": {"@zilliz/milvus2-sdk-node": "^2.3.5", "weaviate-client": "^3.9.0",
                                                     "@lancedb/lancedb": "0.30.0", "@datastax/astra-db-ts": "^0.1.3"}}, indent=2),
        "milvus.js": 'const {\n  MilvusClient,\n} = require("@zilliz/milvus2-sdk-node");\nconst client = new MilvusClient({ address: "x" });\n',
        "weaviate.js": 'const { default: weaviate } = require("weaviate-client");\nconst c = await weaviate.connectToCustom({ httpHost: "x" });\n',
        "lance.js": 'const lancedb = require("@lancedb/lancedb");\nconst db = await lancedb.connect("./data");\n',
        "astra.js": 'const { AstraDB: AstraClient } = require("@datastax/astra-db-ts");\nconst client = new AstraClient("token", "url");\n',
    }

    def test_each_client_is_called(self):
        for name, line in (("@zilliz/milvus2-sdk-node", 4), ("weaviate-client", 2), ("@lancedb/lancedb", 2), ("@datastax/astra-db-ts", 2)):
            pkg = self.pkg(name)
            self.assertEqual((pkg["evidence_level"], [c["line"] for c in pkg["calls"]]), ("called", [line]), name)
            self.assertEqual(pkg["category"], "vector_db")


class RuleFile(unittest.TestCase):
    def test_every_rule_names_a_package_in_the_catalogue(self):
        with open(RULES_PATH, encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
        label = {"pypi": "PyPI", "npm": "npm"}
        families = {f["prefix"] for f in load_db().get("package_families", {}).values()}
        for rule in data["rules"]:
            pkg = rule["package"]
            if "family" in pkg:
                self.assertIn(pkg["family"], families, rule["id"])
            else:
                self.assertTrue(lookup_package(label[pkg["ecosystem"]], pkg["name"]), rule["id"])
            self.assertTrue(rule.get("what"), rule["id"])

    def test_bad_rules_are_refused_with_the_reason(self):
        with self.assertRaisesRegex(ValueError, "unique id"):
            Rules({"rules": [{"id": "a", "package": {"ecosystem": "pypi", "name": "x"}, "python": ["x.y"]},
                             {"id": "a", "package": {"ecosystem": "pypi", "name": "x"}, "python": ["x.z"]}]}, "t")
        with self.assertRaisesRegex(ValueError, "needs package"):
            Rules({"rules": [{"id": "a", "package": {"ecosystem": "cargo", "name": "x"}, "python": ["x.y"]}]}, "t")
        with self.assertRaisesRegex(ValueError, "no python or javascript"):
            Rules({"rules": [{"id": "a", "package": {"ecosystem": "pypi", "name": "x"}}]}, "t")

    def test_wildcards(self):
        rules = load_rules()
        self.assertEqual(rules.match("python", "transformers.AutoModel.from_pretrained")["id"], "transformers.load")
        self.assertEqual(rules.match("python", "autogen_agentchat.agents.CodeExecutorAgent")["id"], "autogen.agents")
        self.assertIsNone(rules.match("python", "langchain_community.vectorstores.Chroma().similarity_search"))
        # classes: true -- a public class or its class method counts, a helper function does not
        self.assertEqual(rules.match("python", "llama_index.embeddings.openai.OpenAIEmbedding")["id"], "llamaindex.integrations")
        self.assertEqual(rules.match("python", "langchain_community.vectorstores.Chroma.from_documents")["id"], "langchain.community")
        self.assertIsNone(rules.match("python", "llama_index.llms.openai.utils.to_openai_message_dicts"))
        self.assertIsNone(rules.match("python", "langchain_community.vectorstores.utils.filter_complex_metadata"))


if __name__ == "__main__":
    unittest.main()
