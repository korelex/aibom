from openai import OpenAI
from anthropic import Anthropic
import chromadb
import pinecone
from langchain_community.vectorstores import Chroma

OPENAI_KEY = "sk-proj-REPLACE_ME_NOT_A_REAL_KEY"

openai_client = OpenAI(api_key=OPENAI_KEY)
anthropic_client = Anthropic()
DEFAULT_MODEL = "gpt-4o-mini"


def chat(messages):
    first = openai_client.chat.completions.create(
        model="gpt-4o",
        messages=messages,
    )
    second = openai_client.embeddings.create(
        model="text-embedding-3-small",
        input="hello",
    )
    third = anthropic_client.messages.create(
        model="claude-3-5-sonnet-20240620",
        max_tokens=256,
        messages=messages,
    )
    return first, second, third


def vector_store():
    return Chroma(), chromadb.Client(), pinecone.Pinecone()
