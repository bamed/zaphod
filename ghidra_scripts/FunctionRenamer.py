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
            "max_length": 50
        }
        
        response = make_api_request("/rename_function", payload)
        if response and "new_name" in response:
            # Extract just the function name if it's in quotes or a code-like format
            suggested_name = response["new_name"]
            
            # If response contains multiple words or explanation, try to extract just the name
            if "`" in suggested_name:
                # Extract name between backticks
                name_match = suggested_name.split("`")[1]
                suggested_name = name_match
            elif "'" in suggested_name or '"' in suggested_name:
                # Extract name between quotes
                import re
                name_match = re.search(r'[\'\"]([\w_]+)[\'\"]', suggested_name)
                if name_match:
                    suggested_name = name_match.group(1)
            
            # Ensure name only contains valid characters
            suggested_name = ''.join(c for c in suggested_name if c.isalnum() or c == '_')
            
            # Ensure name starts with a letter or underscore
            if suggested_name and not suggested_name[0].isalpha() and suggested_name[0] != '_':
                suggested_name = 'func_' + suggested_name
                
            return suggested_name if suggested_name else None
            
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