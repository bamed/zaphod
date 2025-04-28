#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath 
#@toolbar 

import os
import sys
import json

from ghidra.program.model.address import Address
from ghidra.util.task import ConsoleTaskMonitor
from ghidra.app.decompiler import DecompInterface
from java.awt import Color
from ghidra.program.model.symbol import RefType

# List of suspicious Windows API calls
SUSPICIOUS_APIS = [
    "VirtualAlloc",
    "VirtualAllocEx",
    "VirtualProtect",
    "VirtualProtectEx",
    "WriteProcessMemory",
    "ReadProcessMemory",
    "NtAllocateVirtualMemory",
    "NtProtectVirtualMemory",
    "CreateThread",
    "CreateRemoteThread",
    "QueueUserAPC",
    "RtlMoveMemory"
]

EXPORT_FILENAME = "suspect_functions.json"

def get_called_functions(func):
    """Return list of called function names inside given function."""
    called_funcs = set()
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
    for ins in instructions:
        if ins.getMnemonicString().lower().startswith("call"):
            refs = ins.getReferencesFrom()
            for ref in refs:
                dest_func = getFunctionAt(ref.getToAddress())
                if dest_func:
                    called_funcs.add(dest_func.getName())
    return called_funcs


def is_suspicious(func):
    """ Check if a function calls any suspicious API. """
    called_funcs = get_called_functions(func)
    for called_func in called_funcs:
        if called_func in SUSPICIOUS_APIS:
            return called_func
    return None

def highlight(func):
    """ Highlight the suspicious function red. """
    instructions = currentProgram.getListing().getInstructions(func.getBody(), True)
    for ins in instructions:
        setBackgroundColor(ins.getAddress(), Color.RED)

def save_suspect_addresses(suspect_list):
    """ Save the suspect addresses to a JSON file. """
    workspace_dir = currentProgram.getExecutablePath()
    output_dir = os.path.dirname(workspace_dir)
    output_path = os.path.join(output_dir, EXPORT_FILENAME)

    with open(output_path, "w") as f:
        json.dump(suspect_list, f, indent=2)

    print("\n[+] Saved {} suspicious functions to {}".format(len(suspect_list), output_path))

def main():
    fm = currentProgram.getFunctionManager()
    funcs = fm.getFunctions(True)

    suspect_list = []

    print("=== Scanning for suspicious memory behavior ===")
    for func in funcs:
        suspicious_api = is_suspicious(func)
        if suspicious_api:
            addr = func.getEntryPoint()
            print("[CALLS] suspicious_memory_operation at {}: {}".format(addr, suspicious_api))
            highlight(func)
            suspect_list.append({
                "address": str(addr),
                "api_called": suspicious_api,
                "function_name": func.getName()
            })

    if suspect_list:
        save_suspect_addresses(suspect_list)
    else:
        print("[-] No suspicious memory operations detected.")

if __name__ == "__main__":
    main()
