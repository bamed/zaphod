#@author
#@category MCP
#@keybinding
#@menupath
#@toolbar

from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from java.net import URL
import json

SERVER_URL = "http://localhost:8000/rename_function"

def decompileFunction(func):
    decomplib = DecompInterface()
    decomplib.openProgram(currentProgram)
    res = decomplib.decompileFunction(func, 60, monitor)
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    else:
        return None

def getNewName(decompiled_code):
    payload = {
        "model_name": "default",
        "function_code": decompiled_code,
        "max_length": 20
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
            return response_json['new_name']
        else:
            print("Error from server: HTTP {}".format(response_code))
            return None

    except Exception as e:
        print("Exception during rename: {}".format(str(e)))
        return None

# === MAIN SCRIPT START ===

functionManager = currentProgram.getFunctionManager()
functions = functionManager.getFunctions(True)  # True = forward order

renamed_count = 0
total_functions = 0

for func in functions:
    if monitor.isCancelled():
        print("Operation cancelled.")
        break

    total_functions += 1

    # Skip external libraries, etc.
    if func.isExternal():
        continue

    decompiled = decompileFunction(func)
    if not decompiled:
        continue

    new_name = getNewName(decompiled)
    if new_name:
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            renamed_count += 1
            print("Renamed: {} -> {}".format(func.getName(), new_name))
        except Exception as e:
            print("Failed to rename function at {}: {}".format(func.getEntryPoint(), e))

print("\nBatch renaming complete.")
print("Renamed {} out of {} functions.".format(renamed_count, total_functions))
