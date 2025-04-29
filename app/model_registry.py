import os
import json
import torch
from transformers import pipeline, AutoModelForCausalLM, AutoTokenizer, logging as hf_logging

# Load Hugging Face token securely
HF_TOKEN = None
config_path = os.path.join(os.path.dirname(__file__), "..", "config", "config.json")
if os.path.exists(config_path):
    try:
        with open(config_path, "r") as f:
            config = json.load(f)
            HF_TOKEN = config.get("hf_token")
    except Exception as e:
        print(f"[Config Error] Could not read config.json: {e}")
else:
    print("[Config Warning] config/config.json not found. Hugging Face token will not be used.")

# Optional: Silence model warnings
hf_logging.set_verbosity_error()

class ModelRegistry:
    def __init__(self):
        self.models = {}

    def load_model(self, name, model_id):
        print(f"🔍 Loading model '{name}' from '{model_id}'...")
        try:
            model_args = {
                "trust_remote_code": True,
                "torch_dtype": torch.float16,
                "device_map": "auto",  # Automatically fit the model onto available GPU
            }
            tokenizer_args = {
                "trust_remote_code": True,
            }
            pipeline_args = {
                "task": "text-generation",
                #"device": 0,
                "max_new_tokens": 512,
            }

            if HF_TOKEN:
                model_args["token"] = HF_TOKEN
                tokenizer_args["token"] = HF_TOKEN

            if os.path.isdir(model_id):
                # Local model
                model = AutoModelForCausalLM.from_pretrained(model_id, **model_args)
                tokenizer = AutoTokenizer.from_pretrained(model_id, **tokenizer_args)
            else:
                # Download from HuggingFace
                model = AutoModelForCausalLM.from_pretrained(model_id, **model_args)
                tokenizer = AutoTokenizer.from_pretrained(model_id, **tokenizer_args)

            pipe = pipeline(
                **pipeline_args,
                model=model,
                tokenizer=tokenizer
            )
            self.models[name] = pipe
            print(f"✅ Model '{name}' loaded successfully.")
        except Exception as e:
            print(f"❌ Error loading '{name}': {e}")

    def list_models(self):
        return list(self.models.keys())

    def get_model(self, name):
        return self.models.get(name)
