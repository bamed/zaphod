#@author bamed
#@category ZAPHOD
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
from java.net import URL
from java.nio.charset import StandardCharsets
import json
import re

SERVER_URL = "http://localhost:8000/analyze"

def decompileFunction(func):
    if func is None:
        return None
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 60, monitor)
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    else:
        return None

def extract_last_json_block(text):
    try:
        matches = list(re.finditer(r'\{.*?\}', text, re.DOTALL))
        for match in reversed(matches):
            try:
                return json.loads(match.group())
            except Exception:
                continue
    except Exception as e:
        print("Regex parsing failed: {}".format(e))
    return None

currentFunction = getFunctionContaining(currentAddress)
if currentFunction is None:
    print("No function selected.")
    exit()

decompiled = decompileFunction(currentFunction)
if not decompiled:
    print("Unable to decompile function.")
    exit()

# Sanitize
decompiled = ''.join(c if 31 < ord(c) < 127 else ' ' for c in decompiled)
if len(decompiled) > 5000:
    decompiled = decompiled[:5000]

# Payload
payload = {
    "model_name": "default",
    "function_code": decompiled,
    "max_length": 100
}
payload_bytes = json.dumps(payload).encode('utf-8')

try:
    url = URL(SERVER_URL)
    connection = url.openConnection()
    connection.setRequestMethod("POST")
    connection.setDoOutput(True)
    connection.setRequestProperty("Content-Type", "application/json")
    connection.getOutputStream().write(payload_bytes)

    response_code = connection.getResponseCode()
    if response_code == 200:
        input_stream = connection.getInputStream()
        response_text = ''.join([chr(b) for b in input_stream.readAllBytes()])
        print("Raw response:\n{}".format(response_text))  # DEBUG LOG

        parsed = extract_last_json_block(response_text)
        if parsed and "summary" in parsed:
            summary = parsed["summary"]
            currentFunction.setComment(summary)
            print("Inserted summary: {}".format(summary))
        else:
            print("Failed to parse valid summary JSON.")
    else:
        print("Error analyzing function: HTTP {}".format(response_code))

except Exception as e:
    print("Exception during summarization: {}".format(str(e)))
