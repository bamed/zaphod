import os
import json
import logging
from transformers import pipeline, AutoModelForCausalLM, AutoTokenizer, logging as hf_logging

# Setup logging
logging.basicConfig(level=logging.INFO)
hf_logging.set_verbosity_info()

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

class ModelRegistry:
    def __init__(self):
        self.models = {}

    def load_model(self, name, model_id):
        print(f"Loading model {name} from {model_id}...")
        try:
            # Shared load settings
            load_kwargs = {
                "trust_remote_code": True,
                "cache_dir": "./model_cache",
                "offload_folder": "./offload",
                "use_safetensors": True,
                "device_map": "auto",
            }
            # Determine if local or remote
            is_local = os.path.isdir(model_id)
            

            if is_local:
                files = os.listdir(model_id)
                if not any(f.endswith(('.safetensors', '.bin')) for f in files):
                    raise FileNotFoundError(
                        f"No model.safetensors or pytorch_model.bin found in {model_id}."
                    )

                model = AutoModelForCausalLM.from_pretrained(
                    model_id,
                    trust_remote_code=True,
                    token=HF_TOKEN if not is_local else None,
                )
                tokenizer = AutoTokenizer.from_pretrained(model_id, **load_kwargs)
                model = AutoModelForCausalLM.from_pretrained(model_id, **load_kwargs)
                
                pipe = pipeline(
                    "text-generation",
                    model=model,
                    tokenizer=tokenizer,
                    device=0,  # CUDA
                )
                self.models[name] = pipe
                print(f"Model {name} loaded successfully.")
                
            else:
                # Remote from Hugging Face
                tokenizer = AutoTokenizer.from_pretrained(model_id, token=HF_TOKEN, **load_kwargs)
                model = AutoModelForCausalLM.from_pretrained(model_id, token=HF_TOKEN, **load_kwargs)

            pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=0,  # CUDA
            )
            self.models[name] = pipe
            print(f"Model {name} loaded successfully.")

        except Exception as e:
            print(f"Error loading {name}: {e}")
        

            # Extra: If local, check if model.safetensors or pytorch_model.bin exists
            if is_local:
                files = os.listdir(model_id)
                if not any(f.endswith(('.safetensors', '.bin')) for f in files):
                    raise FileNotFoundError(
                        f"No model.safetensors or pytorch_model.bin found in {model_id}."
                    )

            model = AutoModelForCausalLM.from_pretrained(
                model_id,
                trust_remote_code=True,
                token=HF_TOKEN if not is_local else None,
            )
            tokenizer = AutoTokenizer.from_pretrained(
                model_id,
                trust_remote_code=True,
                token=HF_TOKEN if not is_local else None,
            )

            pipe = pipeline(
                "text-generation",
                model=model,
                tokenizer=tokenizer,
                device=0,  # CUDA
            )
            self.models[name] = pipe
            print(f"Model {name} loaded successfully.")

        except Exception as e:
            print(f"Error loading {name}: {e}")

    def list_models(self):
        return list(self.models.keys())




    def list_models(self):
        return list(self.models.keys())

    def get_model(self, name):
        return self.models.get(name)
