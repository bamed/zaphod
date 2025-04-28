import json
import re
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
from model_registry import ModelRegistry

app = FastAPI(title="ZAPHOD - Zenith of Assisted Program Handling and Objective Decompilation")
registry = ModelRegistry()

# Config: Which models to load at startup
models_to_load = {
    "default": "mistralai/Mistral-7B-Instruct-v0.3"
}

for name, model_id in models_to_load.items():
    try:
        registry.load_model(name, model_id)
    except Exception as e:
        print(f"Error loading {name}: {e}")

def parse_function_summary(model_output):
    try:
        text = model_output[0]['generated_text'].strip()

        # Find all JSON-looking blocks
        json_blocks = re.findall(r'\{.*?\}', text, re.DOTALL)

        if not json_blocks:
            print("[Parser Warning] No JSON blocks found.")
            return "No summary available."

        # Try to parse all JSON blocks, keep the last one that successfully parses
        last_good_summary = "No summary available."
        for block in json_blocks:
            try:
                parsed = json.loads(block)
                if "summary" in parsed:
                    last_good_summary = parsed["summary"].strip()
            except Exception:
                continue  # Ignore broken blocks

        return last_good_summary

    except Exception as e:
        print(f"[Parser Error] {e}")
        return "No summary available."

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

class DetectAlgorithmRequest(BaseModel):
    model_name: str
    function_code: str
    max_length: int = 150

class ChatRequest(BaseModel):
    model_name: str
    message: str
    function_code: str = ""

@app.post("/chat")
async def chat(req: ChatRequest):
    user_prompt = req.message.lower()

    if "rename" in user_prompt and req.function_code:
        from server import RenameFunctionRequest
        rename_req = RenameFunctionRequest(
            model_name=req.model_name,
            function_code=req.function_code
        )
        result = rename_function(rename_req)
        return {"action": "rename_function", "result": result}

    elif "analyze" in user_prompt and req.function_code:
        from server import AnalyzeRequest
        analyze_req = AnalyzeRequest(
            model_name=req.model_name,
            function_code=req.function_code
        )
        result = analyze_function(analyze_req)
        return {"action": "analyze_function", "result": result}

    elif "algorithm" in user_prompt and req.function_code:
        from server import DetectAlgorithmRequest
        detect_req = DetectAlgorithmRequest(
            model_name=req.model_name,
            function_code=req.function_code
        )
        result = detect_algorithm(detect_req)
        return {"action": "detect_algorithm", "result": result}

    else:
        return {"response": "Sorry, I didn't understand your request."}

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
    wrapped_prompt = (
        "You are an expert reverse engineer.\n"
        "Given the following C function, write a detailed English explanation of what it does.\n\n"
        "Return ONLY a JSON object in this format:\n"
        "{\n"
        '  "summary": "<a detailed but concise explanation of the function>"\n'
        "}\n\n"
        "If unsure, still return a best-effort explanation.\n"
        "Code:\n\n"
        f"{req.function_code}\n\n"
        "Respond ONLY with the JSON, nothing else."
    )


    print("\n=== Prompt Sent to Model ===")
    print(wrapped_prompt)
    print("=============================\n")

    output = generator(wrapped_prompt, max_new_tokens=req.max_length)

    print("\n=== Raw Model Response ===")
    print(output)
    print("===========================\n")

    summary = parse_function_summary(output)

    return {"summary": summary}


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

@app.post("/detect_algorithm")
def detect_algorithm(req: DetectAlgorithmRequest):
    generator = registry.get_model(req.model_name)
    if not generator:
        raise HTTPException(status_code=404, detail="Model not loaded")

    # Build the clean prompt
    prompt = (
        "You are an expert reverse engineer.\n"
        "Given the following C function, detect if it matches a known algorithm.\n\n"
        "Return ONLY a JSON object in this format:\n"
        "{\n"
        "  \"algorithm_detected\": \"<algorithm name or 'unknown'>\",\n"
        "  \"confidence\": \"<low, medium, high>\",\n"
        "  \"notes\": \"<short explanation>\"\n"
        "}\n\n"
        "If the algorithm is unknown, set \"algorithm_detected\" to \"unknown\".\n"
        "Code:\n"
        f"{req.function_code}\n"
        "Respond ONLY with the JSON, no other text."
    )
    # Debug log
    print("\n=== Prompt Sent to Model ===")
    print(prompt)
    print("=============================\n")

    output = generator(prompt, max_new_tokens=req.max_length)

    print("\n=== Raw Model Response ===")
    print(output)
    print("===========================\n")

    try:
        text = output[0]['generated_text'].strip()

        # Extract the LAST JSON object (not the first!)
        last_brace = text.rfind('{')
        if last_brace == -1:
            raise ValueError("No JSON found in model output.")

        open_braces = 0
        end_brace = None
        for i in range(last_brace, len(text)):
            if text[i] == '{':
                open_braces += 1
            elif text[i] == '}':
                open_braces -= 1
                if open_braces == 0:
                    end_brace = i
                    break

        if end_brace is None:
            raise ValueError("Incomplete JSON structure in output.")

        json_text = text[last_brace:end_brace+1]
        result = json.loads(json_text)

        # Return clean structured response
        return {
            "algorithm_detected": result.get("algorithm_detected", "unknown"),
            "confidence": result.get("confidence", "unknown"),
            "notes": result.get("notes", "")
        }

    except Exception as e:
        print(f"[Parser Error] {e}")
        raise HTTPException(status_code=500, detail="Failed to parse model output.")

@app.get("/models")
def list_models():
    return {"available_models": registry.list_models()}
