"""Who makes a model, and what kind of model it is, worked out from the name.
LiteLLM's 'provider' says where a model can be rented (azure, bedrock, deepinfra), not who made it,
so the maker comes from this short table of model families. Anything not in the table is left blank on purpose."""
import re

VENDOR_PREFIX = {"openai": "OpenAI", "anthropic": "Anthropic", "google": "Google", "meta-llama": "Meta", "meta": "Meta", "mistralai": "Mistral AI", "mistral": "Mistral AI",
                 "cohere": "Cohere", "ibm": "IBM", "deepseek-ai": "DeepSeek", "deepseek": "DeepSeek", "qwen": "Alibaba", "microsoft": "Microsoft", "nvidia": "NVIDIA",
                 "moonshotai": "Moonshot AI", "xai": "xAI", "amazon": "Amazon", "ai21": "AI21 Labs", "sentence-transformers": "sentence-transformers", "baai": "BAAI",
                 "tjake": "tjake (community)", "intfloat": "intfloat", "cross-encoder": "sentence-transformers"}
FAMILIES = [
    (r"^(gpt|chatgpt|o[134](\b|-)|text-embedding|text-davinci|davinci|babbage|whisper|dall-e|tts-|omni-moderation|text-moderation|gpt-oss)", "OpenAI"),
    (r"^claude", "Anthropic"),
    (r"^(gemini|gemma|palm|text-bison|chat-bison|textembedding-gecko|imagen|veo)", "Google"),
    (r"^(llama|codellama|llava)", "Meta"),
    (r"^(mistral|mixtral|codestral|pixtral|ministral|voxtral|magistral|devstral)", "Mistral AI"),
    (r"^(command|embed-|rerank-multilingual|rerank-english)", "Cohere"),
    (r"^grok", "xAI"), (r"^deepseek", "DeepSeek"), (r"^(qwen|qwq)", "Alibaba"), (r"^(sonar|pplx)", "Perplexity"),
    (r"^(nova|titan)", "Amazon"), (r"^phi-?\d", "Microsoft"), (r"^kimi", "Moonshot AI"), (r"^(voyage|rerank-lite|rerank-2)", "Voyage AI"),
    (r"^granite", "IBM"), (r"^glm", "Zhipu AI"), (r"^minimax", "MiniMax"), (r"^jamba", "AI21 Labs"), (r"^(nomic)", "Nomic AI"),
    (r"^(all-minilm|bge-)", "open source (sentence-transformers / BAAI)"),
]
BEDROCK = re.compile(r"^(?:us\.|eu\.|apac\.|global\.)?(anthropic|amazon|meta|mistral|cohere|deepseek|openai|ai21)\.(.+)$")


def maker_of(name):
    n = name.lower()
    m = BEDROCK.match(n)
    if m:
        return VENDOR_PREFIX.get(m.group(1), "")
    if "/" in n:
        head = n.split("/")[0]
        if head in VENDOR_PREFIX:
            return VENDOR_PREFIX[head]
    for rx, vendor in FAMILIES:
        if re.search(rx, n):
            return vendor
    return ""


def type_of(name, litellm_mode=""):
    n = name.lower()
    for words, label in ((("embed",), "embedding model"), (("whisper", "transcribe"), "speech-to-text model"), (("tts",), "text-to-speech model"),
                         (("rerank", "cross-encoder", "colbert"), "reranking model"), (("moderation",), "moderation model"), (("dall-e", "image", "imagen"), "image model")):
        if any(w in n for w in words):
            return label
    return {"chat": "chat model", "responses": "chat model", "completion": "text model", "realtime": "realtime voice model", "video_generation": "video model"}.get(litellm_mode, "")
