import json
import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from model_registry import ModelRegistry

app = FastAPI(title="ZAPHOD - Zenith of Assisted Program Handling and Objective Decompilation")
registry = ModelRegistry()

# Config: Which models to load at startup
models_to_load = {
    "default": "deepseek-ai/deepseek-coder-1.3b-instruct"  # Smallish, works on 4GB VRAM
}

for name, model_id in models_to_load.items():
    try:
        registry.load_model(name, model_id)
    except Exception as e:
        print(f"Error loading {name}: {e}")

def parse_function_name(model_output):
    """
    Given raw model output from the LLM, attempt to parse a valid JSON object and extract the function name.
    """
    try:
        text = model_output[0]['generated_text'].strip()

        # Find all JSON-looking chunks
        json_candidates = re.findall(r'\{.*?\}', text, re.DOTALL)
        if not json_candidates:
            print("[Parser Warning] No JSON object detected.")
            return "unknown_function"

        # Prefer the LAST json chunk (usually the real answer)
        for json_text in reversed(json_candidates):
            try:
                parsed = json.loads(json_text)
                if "name" in parsed and isinstance(parsed["name"], str):
                    return parsed["name"].strip().replace(" ", "_").lower()
            except Exception as e_inner:
                print(f"[Parser Inner Error] {e_inner}")
                continue

        print("[Parser Warning] No valid JSON with 'name' field found.")
        return "unknown_function"

    except Exception as e:
        print(f"[Parser Error] {e}")
        return "unknown_function"

class GenerateRequest(BaseModel):
    model_name: str
    prompt: str
    max_length: int = 100

class AnalyzeRequest(BaseModel):
    model_name: str
    function_code: str
    max_length: int = 100

class RenameFunctionRequest(BaseModel):
    model_name: str
    function_code: str
    max_length: int = 50

@app.post("/generate")
def generate_text(req: GenerateRequest):
    generator = registry.get_model(req.model_name)
    if not generator:
        raise HTTPException(status_code=404, detail="Model not loaded")
    output = generator(req.prompt, max_new_tokens=req.max_length)
    return {"result": output[0]['generated_text']}

@app.post("/analyze")
def analyze_function(req: AnalyzeRequest):
    generator = registry.get_model(req.model_name)
    if not generator:
        raise HTTPException(status_code=404, detail="Model not loaded")
    wrapped_prompt = f"Summarize the following function in simple English:\n{req.function_code}"
    output = generator(wrapped_prompt, max_new_tokens=req.max_length)
    return {"summary": output[0]['generated_text']}

@app.post("/rename_function")
def rename_function(req: RenameFunctionRequest):
    generator = registry.get_model(req.model_name)
    if not generator:
        raise HTTPException(status_code=404, detail="Model not loaded")

    prompt = (
        "You are an AI system that ONLY outputs JSON responses.\n"
        "Given the following C code, suggest a new short function name.\n"
        "Respond ONLY in this format (no other text, no explanations):\n"
        '{"name": "new_function_name"}\n'
        "C code:\n"
        f"{req.function_code}\n"
        "Respond ONLY with the JSON object, nothing else."
    )

    print("\n=== Prompt Sent to Model ===")
    print(prompt)
    print("=============================\n")

    output = generator(prompt, max_new_tokens=req.max_length)

    print("\n=== Raw Model Response ===")
    print(output)
    print("===========================\n")

    new_name = parse_function_name(output)

    return {"new_name": new_name}

@app.get("/models")
def list_models():
    return {"available_models": registry.list_models()}
