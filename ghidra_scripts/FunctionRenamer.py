#@author 
#@category ZAPHOD
#@keybinding 
#@menupath Tools.ZAPHOD.Rename Function
#@toolbar 

from ghidra.program.model.symbol import SourceType
from ghidra.app.decompiler import DecompInterface
from zaphod_config import make_api_request

def decompile_function(func):
    """Decompiles the given function and returns its code."""
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    
    result = decompiler.decompileFunction(func, 30, monitor)
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def get_suggested_name(decompiled_code):
    """Gets a suggested name for the function from the API."""
    try:
        payload = {
            "model_name": "default",
            "function_code": decompiled_code,
            "max_length": 50,
            "prompt": "Give only a single valid C function name (no quotes, no explanation) that describes what this function does:\n\n"
        }
        
        response = make_api_request("/rename_function", payload)
        if response and "new_name" in response:
            return response["new_name"]
        return None
        
    except Exception as e:
        print("Failed to get suggested name: %s" % str(e))
        return None

def main():
    # Get current function
    func = getFunctionContaining(currentAddress)
    if func is None:
        print("No function found at current address.")
        return

    current_name = func.getName()
    
    # Ignore external functions
    if func.isExternal():
        print("Cannot rename external function: %s" % current_name)
        return
    
    print("Analyzing function: %s" % current_name)
    
    # Get decompiled code
    decompiled_code = decompile_function(func)
    if not decompiled_code:
        print("Failed to decompile function.")
        return
        
    # Get suggested name from API
    print("Getting suggested name from Zaphod...")
    new_name = get_suggested_name(decompiled_code)
    
    if not new_name:
        print("Failed to get suggested name.")
        return
        
    # Ask user to confirm the rename
    if askYesNo("Rename Function", 
                "Rename '%s' to '%s'?" % (current_name, new_name)):
        try:
            func.setName(new_name, SourceType.USER_DEFINED)
            print("Function renamed successfully to: %s" % new_name)
        except Exception as e:
            print("Failed to rename function: %s" % str(e))
    else:
        print("Operation cancelled by user.")

if __name__ == '__main__':
    main()