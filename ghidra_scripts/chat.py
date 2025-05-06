#@author bamed
#@category ZAPHOD
#@keybinding
#@menupath Tools.ZAPHOD.Chat with Function
#@toolbar

import json
import re
from ghidra.program.model.listing import FunctionManager
from ghidra.app.decompiler import DecompInterface
from zaphod_config import make_api_request

try:
    from ghidra.util.task import ConsoleTaskMonitor
except ImportError:
    pass

def decompile_current_function():
    currentProgram = getCurrentProgram()
    function = getFunctionContaining(currentAddress)
    if function is None:
        print("No function selected.")
        return None

    ifc = DecompInterface()
    ifc.openProgram(currentProgram)
    res = ifc.decompileFunction(function, 30, ConsoleTaskMonitor())
    
    if res.decompileCompleted():
        return res.getDecompiledFunction().getC()
    return None

def chat_with_function(prompt, function_code):
    try:
        payload = {
            "prompt": prompt,
            "model_name": "default",
            "function_code": function_code,
            "max_length": 1000  # reasonable default
        }

        response = make_api_request("/chat", payload)
        return response

    except Exception as e:
        print("Chat request failed: %s" % str(e))
        return None

def main():
    # Get user's prompt
    prompt = askString("Zaphod Chat", "Enter your question about the current function:")
    if not prompt:
        print("Operation cancelled.")
        return

    # Get the decompiled function code
    function_code = decompile_current_function()
    if not function_code:
        print("No function code found.")
        return

    print("\nSending request to Zaphod...")
    
    # Make the request
    result = chat_with_function(prompt, function_code)
    
    if not result:
        print("No response received.")
        return

    # Display the response
    print("\n=== ZAPHOD Response ===")
    if 'summary' in result:
        print(result['summary'])
    elif isinstance(result, dict):
        for key, value in result.items():
            print("%s: %s" % (key, value))
    else:
        print(result)

if __name__ == '__main__':
    main()