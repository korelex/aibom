from transformers import AutoModelForCausalLM

local_model = AutoModelForCausalLM.from_pretrained(
    "meta-llama/Llama-2-7b-hf",
    trust_remote_code=True,
)

SDXL = "stabilityai/stable-diffusion-xl-base-1.0"
