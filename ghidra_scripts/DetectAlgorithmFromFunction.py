#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath Tools.ZAPHOD.Detect Algorithm
#@toolbar 

import json
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

def detect_algorithm(decompiled_code):
    try:
        payload = {
            "model_name": "default",
            "function_code": decompiled_code,
            "max_length": 500
        }
        response = make_api_request("/detect_algorithm", payload)
        if not response:
            return None
        return {
            "algorithm": response.get("algorithm_detected", "unknown"),
            "confidence": response.get("confidence", "unknown"),
            "notes": response.get("notes", "none")
        }
    except Exception as e:
        print("Algorithm detection failed: %s" % str(e))
        return None

def main():
    # Get current function
    func = getFunctionContaining(currentAddress)
    if func is None:
        print("No function found at the current cursor location.")
        return

    # Print function name (handling potential encoding issues)
    try:
        print("\n--- Analyzing Function: %s ---" % func.getName())
    except:
        print("\n--- Analyzing Function (name contains non-ASCII characters) ---")

    # Decompile the function
    decompiled_code = decompile_function(func)
    if not decompiled_code:
        print("Failed to decompile function.")
        return

    # Detect algorithm
    print("Sending request to Zaphod...")
    result = detect_algorithm(decompiled_code)
    
    if result:
        print("\nResults:")
        print("Algorithm Detected: %s" % result["algorithm"])
        print("Confidence: %s" % result["confidence"])
        print("Notes: %s" % result["notes"])
        
        # Add the notes as a comment to the function
        try:
            func.setComment(result["notes"])
            print("\nNotes added as function comment.")
        except Exception as e:
            print("Failed to set function comment: %s" % str(e))
    else:
        print("Failed to detect algorithm.")

if __name__ == '__main__':
    main()