# Import dumped memory artifacts into Ghidra bookmarks
#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath 
#@toolbar 

import os
import json
from ghidra.program.model.symbol import SourceType
from java.awt import Color

dumps_folder = askDirectory("Select dump folder", "OK")
metadata_file = os.path.join(dumps_folder.getAbsolutePath(), "dump_metadata.json")

if not os.path.exists(metadata_file):
    print("No metadata file found!")
    exit()

with open(metadata_file, 'r') as f:
    dump_info = json.load(f)

bm = currentProgram.getBookmarkManager()

for entry in dump_info:
    addr_str = entry['address']
    api = entry['api']
    size = entry['size']
    dump_file = entry['dump_file']

    try:
        addr = toAddr(int(addr_str, 16))
        bm.setBookmark(addr, "SuspiciousMemoryDump", "Detected at " + api, None)
        setBackgroundColor(addr, Color.YELLOW)
        print("Marked suspicious memory at {} ({} bytes) from {}".format(addr, size, api))
    except Exception as e:
        print("Failed to mark {}: {}".format(addr_str, e))
