#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath 
#@toolbar 

import json
import sys

from ghidra.app.decompiler import DecompInterface
from java.net import URL
from java.io import BufferedReader, InputStreamReader, OutputStreamWriter

API_URL = "http://localhost:8000/detect_algorithm"  # <-- adjust to match your server address

def extract_json(text):
    """Extracts the last JSON object from a text blob."""
    last_json_start = text.rfind('{')
    if last_json_start == -1:
        raise ValueError("No JSON object found in response.")

    open_braces = 0
    end_pos = -1

    for i in range(last_json_start, len(text)):
        if text[i] == '{':
            open_braces += 1
        elif text[i] == '}':
            open_braces -= 1
            if open_braces == 0:
                end_pos = i
                break

    if end_pos == -1:
        raise ValueError("Incomplete JSON object found.")

    json_str = text[last_json_start:end_pos + 1]
    return json_str


# Decompiler setup
decomp = DecompInterface()
decomp.openProgram(currentProgram)

func = getFunctionContaining(currentAddress)
if func is None:
    print("No function found at the current cursor location.")
    exit()

func_name = func.getName()
try:
    print(u"\n--- Analyzing Function: {} ---".format(func_name))
except:
    print("\n--- Analyzing Function (name could not be printed due to encoding) ---")

# Decompile
res = decomp.decompileFunction(func, 30, monitor)
if not res.decompileCompleted():
    print("Failed to decompile {}".format(func_name))
    exit()

decompiled_code = res.getDecompiledFunction().getC()

try:
    # Send POST request
    url = URL(API_URL)
    conn = url.openConnection()
    conn.setDoOutput(True)
    conn.setRequestMethod("POST")
    conn.setRequestProperty("Content-Type", "application/json")

    payload = json.dumps({
        "model_name": "default",
        "function_code": decompiled_code,
        "max_length": 500
    })

    writer = OutputStreamWriter(conn.getOutputStream())
    writer.write(payload)
    writer.flush()
    writer.close()

    reader = BufferedReader(InputStreamReader(conn.getInputStream()))
    response = ""
    line = reader.readLine()
    while line:
        response += line
        line = reader.readLine()
    reader.close()

    # Extract and parse JSON
    json_text = extract_json(response)
    data = json.loads(json_text)

    algorithm = data.get("algorithm_detected", "unknown")
    confidence = data.get("confidence", "unknown")
    notes = data.get("notes", "none")

    print("Algorithm Detected: {}".format(algorithm))
    print("Confidence: {}".format(confidence))
    print("Notes: {}".format(notes))
    func.setComment(notes)

except Exception as e:
    print("Request failed: {}".format(e))
    print("Raw server response was:\n{}".format(response))
