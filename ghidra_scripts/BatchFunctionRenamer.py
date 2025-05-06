#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath Tools.ZAPHOD.Batch Rename Functions
#@toolbar

from ghidra.program.model.listing import FunctionManager
from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from zaphod_config import make_api_request

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
    try:
        response = make_api_request("/rename_function", payload)
        if response and 'new_name' in response:
            return response['new_name']
        return None
    except Exception as e:
        print("Exception during rename: %s" % str(e))
        return None

# === MAIN SCRIPT START ===

functionManager = currentProgram.getFunctionManager()
functions = functionManager.getFunctions(True)  # True = forward order

renamed_count = 0
total_functions = 0

print("Starting batch rename operation...")

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
            print("Renamed: %s -> %s" % (func.getName(), new_name))
        except Exception as e:
            print("Failed to rename function at %s: %s" % (func.getEntryPoint(), str(e)))

print("\nBatch renaming complete.")
print("Renamed %d out of %d functions." % (renamed_count, total_functions))