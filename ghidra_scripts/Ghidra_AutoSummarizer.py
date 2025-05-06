#@author bamed
#@category ZAPHOD
#@keybinding
#@menupath Tools.ZAPHOD.Summarize Function
#@toolbar

from ghidra.program.model.listing import Function
from ghidra.app.decompiler import DecompInterface
from zaphod_config import make_api_request

def decompile_function(func):
    """Decompiles the given function and returns its code."""
    if func is None:
        return None
        
    decompiler = DecompInterface()
    decompiler.openProgram(currentProgram)
    result = decompiler.decompileFunction(func, 60, monitor)
    
    if result.decompileCompleted():
        return result.getDecompiledFunction().getC()
    return None

def sanitize_code(code):
    """Sanitizes the decompiled code for API transmission."""
    if not code:
        return None
        
    # Remove non-printable characters
    sanitized = ''.join(c if 31 < ord(c) < 127 else ' ' for c in code)
    
    # Truncate if too long
    if len(sanitized) > 5000:
        sanitized = sanitized[:5000]
        
    return sanitized

def get_function_summary(code):
    try:
        payload = {
            "model_name": "default",
            "function_code": code,
            "max_length": 100
        }
        response = make_api_request("/analyze", payload)
        if response and "summary" in response:
            return response["summary"]
        return None
    except Exception as e:
        print("Failed to get function summary: %s" % str(e))
        return None

def main():
    # Get current function
    current_function = getFunctionContaining(currentAddress)
    if current_function is None:
        print("No function selected.")
        return
        
    print("Analyzing function: %s" % current_function.getName())
    
    # Decompile the function
    decompiled_code = decompile_function(current_function)
    if not decompiled_code:
        print("Unable to decompile function.")
        return
        
    # Sanitize the code
    sanitized_code = sanitize_code(decompiled_code)
    if not sanitized_code:
        print("Error in code sanitization.")
        return
        
    # Get the summary
    print("Getting summary from Zaphod...")
    summary = get_function_summary(sanitized_code)
    
    if summary:
        try:
            # Add the summary as a comment
            current_function.setComment(summary)
            print("\nSummary added as function comment:")
            print(summary)
        except Exception as e:
            print("Failed to set function comment: %s" % str(e))
    else:
        print("Failed to generate summary.")

if __name__ == '__main__':
    main()