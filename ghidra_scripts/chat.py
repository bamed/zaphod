#@author
#@category ZAPHOD
#@keybinding
#@menupath
#@toolbar

import json
import re

try:
    from ghidra.util.task import ConsoleTaskMonitor
except ImportError:
    pass

from ghidra.program.model.listing import FunctionManager
from ghidra.app.decompiler import DecompInterface

from java.io import BufferedReader, InputStreamReader, OutputStreamWriter
from java.net import HttpURLConnection, URL

SERVER_URL = "http://localhost:8000/chat"
MODEL_NAME = "default"

def post_chat_message(prompt, function_code=None):
    try:
        url = URL(SERVER_URL)
        conn = url.openConnection()
        conn.setRequestMethod("POST")
        conn.setRequestProperty("Content-Type", "application/json")
        conn.setDoOutput(True)

        payload = {
            "prompt": prompt,
            "model_name": MODEL_NAME
        }

        if function_code:
            payload["function_code"] = function_code

        writer = OutputStreamWriter(conn.getOutputStream())
        writer.write(json.dumps(payload))
        writer.flush()
        writer.close()

        response = conn.getResponseCode()
        if response == 200:
            reader = BufferedReader(InputStreamReader(conn.getInputStream()))
            result = ""
            line = reader.readLine()
            while line:
                result += line
                line = reader.readLine()
            reader.close()
            return json.loads(result)
        else:
            print("Error: HTTP {}".format(response))
            return None

    except Exception as e:
        print("Request failed:", e)
        return None

def decompile_current_function():
    currentProgram = getCurrentProgram()
    function = getFunctionContaining(currentAddress)
    if function is None:
        print("No function selected.")
        return None

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(function, 30, ConsoleTaskMonitor())
    return res.getDecompiledFunction().getC()

def main():
    prompt = askString("Zaphod Chat", "Enter your command:")
    function_code = decompile_current_function()

    if not function_code:
        print("No function code found.")
        return

    result = post_chat_message(prompt, function_code)
    if not result:
        print("No result.")
        return

    print("\n=== ZAPHOD Response ===")
    print("Action:", result.get("action"))
    print("Result:", result.get("result"))

main()

