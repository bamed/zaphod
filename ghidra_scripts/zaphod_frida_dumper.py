# Import dumped memory artifacts into Ghidra bookmarks
#@author bamed
#@category ZAPHOD
#@keybinding 
#@menupath 
#@toolbar 

import frida
import sys
import os
import json
import time
import subprocess
import psutil

dumps = []

def on_message(message, data):
    if message['type'] == 'send':
        payload = message['payload']
        if 'dump' in payload:
            addr = payload['address']
            size = payload['size']
            api = payload['api']
            timestamp = time.strftime('%Y-%m-%dT%H:%M:%S')
            filename = f"dump_{addr:x}.bin"
            filepath = os.path.join("dumps", filename)

            print(f"[+] Dumping memory {addr:x} ({size} bytes) from {api} to {filename}")

            os.makedirs("dumps", exist_ok=True)

            with open(filepath, 'wb') as f:
                f.write(data)

            dumps.append({
                "address": hex(addr),
                "size": size,
                "api": api,
                "dump_file": filename,
                "timestamp": timestamp
            })

    else:
        print(message)

def find_pid_by_name(name):
    """Find process ID by executable name."""
    for proc in psutil.process_iter(attrs=['pid', 'name']):
        if proc.info['name'] == name or proc.info['name'].lower() == name.lower():
            return proc.info['pid']
    return None

def main():
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <path_to_sample.exe>")
        sys.exit(1)

    sample_path = sys.argv[1]

    print(f"[*] Spawning {sample_path} in suspended mode...")

    # Create the sample process in suspended mode
    proc = subprocess.Popen(
        [sample_path],
        creationflags=0x00000004
    )

    time.sleep(1)

    pid = proc.pid
    print(f"[*] Process PID: {pid}")

    # Attach to the suspended process
    print("[*] Attaching with Frida...")
    session = frida.attach(pid)

    script = session.create_script("""
function hookApi(apiName) {
    var addr = Module.findExportByName(null, apiName);
    if (addr) {
        Interceptor.attach(addr, {
            onEnter: function (args) {
                this.addr_ptr = args[0];
                this.size = parseInt(args[1]);
            },
            onLeave: function (retval) {
                if (this.addr_ptr && this.size > 0) {
                    try {
                        var mem = Memory.readByteArray(this.addr_ptr, this.size);
                        send({dump: true, address: ptr(this.addr_ptr).toInt32(), size: this.size, api: apiName}, mem);
                    } catch (e) {
                        console.log("[-] Failed to read memory: " + e);
                    }
                }
            }
        });
        console.log("[*] Hooked " + apiName);
    }
}

hookApi("VirtualAlloc");
hookApi("VirtualProtect");
hookApi("HeapAlloc");
hookApi("VirtualAllocEx");
hookApi("VirtualProtectEx");
hookApi("NtAllocateVirtualMemory");
hookApi("NtProtectVirtualMemory");
hookApi("RtlDecompressBuffer");
hookApi("RtlDecompressBufferEx");
""")

    script.on('message', on_message)
    script.load()

    print("[*] Hooks installed. Resuming target...")
    # Resume the process
    proc_handle = psutil.Process(pid)
    proc_handle.resume()

    print("[*] Monitoring. Press Ctrl+C to stop.")
    try:
        sys.stdin.read()
    except KeyboardInterrupt:
        print("[*] Exiting... saving metadata...")
        with open("dumps/dump_metadata.json", 'w') as f:
            json.dump(dumps, f, indent=2)
        session.detach()
        try:
            proc_handle.terminate()
        except:
            pass

if __name__ == "__main__":
    main()
