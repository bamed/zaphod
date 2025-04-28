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

SERVER_URL = "http://localhost:8000/analyze"

# Decompile current function
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

currentFunction = getFunctionContaining(currentAddress)
if currentFunction is None:
    print("No function selected.")
    exit()

decompiled = decompileFunction(currentFunction)
if not decompiled:
    print("Unable to decompile function.")
    exit()

# Optional: truncate very large decompiled functions to avoid server issues
# Sanitize non-printable characters
decompiled = ''.join(c if 31 < ord(c) < 127 else ' ' for c in decompiled)

# Trim very large decompiled functions
if len(decompiled) > 5000:
    decompiled = decompiled[:5000]


# Prepare JSON payload
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
        response_json = json.loads(response_text)
        summary = response_json['summary']
        currentFunction.setComment(response_text)
        print("Inserted summary: {}".format(summary))
    else:
        print("Error analyzing function: HTTP {}".format(response_code))

except Exception as e:
    print("Exception during summarization: {}".format(str(e)))
