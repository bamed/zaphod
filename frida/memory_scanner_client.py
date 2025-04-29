import sys
import os
import json
import requests
import argparse
import marshal
import re
from math import log2
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# Constants
PE_MAGIC = b'MZ'
PYTHON_MAGIC = [b'\x42\x0D\x0D\x0A', b'\x42\x0D\x0D\x0D']  # Python 3.11+
JSON_REGEX = r'\{(?:[^{}]|(?R))*\}'  # recursive regex to find JSON objects

def entropy(data):
    if not data:
        return 0
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * log2(p) for p in probs)

def detect_pe(data):
    return [i for i in range(len(data) - 1) if data[i:i+2] == PE_MAGIC]

def detect_python_bytecode(data):
    return [i for i in range(len(data) - 3) if data[i:i+4] in PYTHON_MAGIC]

def extract_ascii_strings(data, min_len=5):
    result = []
    current = b""
    for b in data:
        if 32 <= b <= 126:
            current += bytes([b])
        else:
            if len(current) >= min_len:
                result.append(current.decode('ascii', errors='ignore'))
            current = b""
    if len(current) >= min_len:
        result.append(current.decode('ascii', errors='ignore'))
    return result

def disassemble_pe(data, arch='x86'):
    md = Cs(CS_ARCH_X86, CS_MODE_32 if arch == 'x86' else CS_MODE_64)
    try:
        disasm = []
        for i in md.disasm(data, 0x1000):
            disasm.append(f"0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}")
        return disasm
    except Exception as e:
        return [f"Disassembly error: {e}"]

def try_unmarshal_python(data):
    try:
        obj = marshal.loads(data)
        return str(obj)
    except Exception as e:
        return f"Failed to unmarshal: {e}"

def scan_file(filepath):
    findings = {
        "pe_offsets": [],
        "python_offsets": [],
        "ascii_strings": [],
        "high_entropy_blocks": [],
        "needs_llm": False,
        "llm_payload": ""
    }
    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        print(f"Error reading {filepath}: {e}")
        return findings

    basename = os.path.basename(filepath)

    # Check PE headers
    pe_offsets = detect_pe(data)
    if pe_offsets:
        findings['pe_offsets'] = [hex(off) for off in pe_offsets]
        findings['needs_llm'] = True
        findings['llm_payload'] += f"PE header(s) found at {findings['pe_offsets']} in {basename}\n"

        # Try disassembly
        disasm_preview = disassemble_pe(data[:512])
        findings['llm_payload'] += "\nSample disassembly preview:\n" + "\n".join(disasm_preview[:10])

    # Check Python bytecode
    py_offsets = detect_python_bytecode(data)
    if py_offsets:
        findings['python_offsets'] = [hex(off) for off in py_offsets]
        for off in py_offsets:
            py_obj = try_unmarshal_python(data[off:])
            findings['llm_payload'] += f"\nPython bytecode found at offset {hex(off)}:\n{py_obj}\n"
        findings['needs_llm'] = True

    # Strings
    ascii_strs = extract_ascii_strings(data)
    findings['ascii_strings'] = ascii_strs[:10]  # Preview only

    # High-entropy blocks
    block_size = 512
    entropy_hits = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) == block_size and entropy(block) > 7.5:
            entropy_hits.append(hex(i))
    if entropy_hits:
        findings['high_entropy_blocks'] = entropy_hits
        findings['needs_llm'] = True
        findings['llm_payload'] += f"\nHigh-entropy regions found at: {entropy_hits}\n"

    return findings

def extract_json_blocks(text):
    matches = re.findall(JSON_REGEX, text, re.DOTALL)
    if matches:
        return matches[-1]  # Last JSON block
    return None

def main():
    parser = argparse.ArgumentParser(description="Scan memory dumps and send complex findings to Zaphod for LLM analysis.")
    parser.add_argument("dump_dir", help="Directory containing scan_*.bin files")
    parser.add_argument("zaphod_url", help="URL of Zaphod server, e.g., http://localhost:8000")
    parser.add_argument("--model", help="Model name to use (e.g., mistral)", default="mistral")
    parser.add_argument("--outdir", help="Directory to save LLM responses", default=None)
    args = parser.parse_args()

    if not os.path.isdir(args.dump_dir):
        print(f"Error: Directory not found: {args.dump_dir}")
        sys.exit(1)

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    for filename in os.listdir(args.dump_dir):
        if not filename.startswith("scan_"):
            continue
        filepath = os.path.join(args.dump_dir, filename)
        print(f"[*] Scanning {filename}...")
        findings = scan_file(filepath)

        if findings['needs_llm']:
            prompt = (
                "You are an expert reverse engineer.\n"
                "Analyze the following memory dump findings and summarize what the binary does.\n\n"
                "Return ONLY a JSON object in this format:\n"
                "{\n"
                '  "summary": "<explanation>"\n'
                "}\n\n"
                "Findings:\n\n"
                f"{findings['llm_payload']}"
            )
            payload = {
                "model_name": args.model,
                "function_code": prompt,
                "max_length": 512
            }
            try:
                response = requests.post(f"{args.zaphod_url}/analyze", json=payload)
                response.raise_for_status()
                raw_output = response.text

                extracted_json = extract_json_blocks(raw_output)
                if extracted_json:
                    try:
                        parsed_json = json.loads(extracted_json)
                        print(f"[*] LLM parsed response for {filename}:")
                        print(json.dumps(parsed_json, indent=2))

                        if args.outdir:
                            outpath = os.path.join(args.outdir, f"{filename}.json")
                            with open(outpath, "w") as outf:
                                json.dump(parsed_json, outf, indent=2)
                    except Exception as e:
                        print(f"[!] Failed to parse JSON for {filename}: {e}")
                        print(f"[!] Raw extracted JSON block:\n{extracted_json}")
                else:
                    print(f"[!] No JSON block found in LLM response for {filename}.")

            except requests.exceptions.HTTPError as e:
                print(f"[!] HTTP error for {filename}: {e}")
                print(f"[!] Server said: {response.text}")
            except Exception as e:
                print(f"[!] General error for {filename}: {e}")

        else:
            print(f"[*] {filename} did not require LLM analysis.")

if __name__ == "__main__":
    main()
