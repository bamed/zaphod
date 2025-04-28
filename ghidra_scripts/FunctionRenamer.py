#@author bamed
#@category ZAPHOD
#@keybinding
#@menupath
#@toolbar
# Imports
from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
from ghidra.program.model.symbol import SourceType
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
        "max_length": 200
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
            print(response_text)
            response_json = json.loads(response_text)
            return response_json['new_name']
        else:
            print("Error renaming function: HTTP {}".format(response_code))
            return None

    except Exception as e:
        print("Exception during rename: {}".format(str(e)))
        return None

# === MAIN SCRIPT START ===

# <--- THIS IS WHAT WAS MISSING ---> #
currentFunction = getFunctionContaining(currentAddress)
if currentFunction is None:
    print("No function selected.")
    exit()

decompiled = decompileFunction(currentFunction)

if decompiled:
    new_name = getNewName(decompiled)
    if new_name:
        currentFunction.setName(new_name, SourceType.USER_DEFINED)
        print("Renamed function to: {}".format(new_name))
    else:
        print("Failed to get new name from server.")
else:
    print("Failed to decompile function.")
