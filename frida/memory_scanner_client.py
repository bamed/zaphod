import sys
import os
import json
import requests
import argparse
import marshal
import re
import datetime
from math import log2
from capstone import Cs, CS_ARCH_X86, CS_MODE_32, CS_MODE_64

# === CONFIG ===
PE_MAGIC = b'MZ'
PYTHON_MAGIC = [b'\x42\x0D\x0D\x0A', b'\x42\x0D\x0D\x0D']
MAX_PROMPT_LENGTH = 5000
JSON_REGEX = r'\{(?:[^{}]|(?R))*\}'  # Recursive regex for JSON blocks
LOG_FILE = "scan.log"

# === ANALYSIS HELPERS ===
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

def extract_json_blocks(text):
    matches = re.findall(JSON_REGEX, text, re.DOTALL)
    return matches[-1] if matches else None

def log_message(message):
    timestamp = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

# === FILE SCAN ===
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
        log_message(f"ERROR: Could not read file {filepath}: {e}")
        return findings

    basename = os.path.basename(filepath)
    log_message(f"--- Scanning {basename} ---")

    # PE detection
    pe_offsets = detect_pe(data)
    if pe_offsets:
        findings['pe_offsets'] = [hex(off) for off in pe_offsets]
        findings['needs_llm'] = True
        findings['llm_payload'] += f"PE header(s) found at {findings['pe_offsets']}\n"
        disasm_preview = disassemble_pe(data[:2048])
        findings['llm_payload'] += "\nDisassembly Preview:\n" + "\n".join(disasm_preview[:20])
        log_message(f"{basename}: PE header(s) at {findings['pe_offsets']}")

    # Python bytecode
    py_offsets = detect_python_bytecode(data)
    if py_offsets:
        findings['python_offsets'] = [hex(off) for off in py_offsets]
        findings['needs_llm'] = True
        for off in py_offsets:
            py_obj = try_unmarshal_python(data[off:])
            findings['llm_payload'] += f"\nPython bytecode at {hex(off)}:\n{py_obj}\n"
        log_message(f"{basename}: Python bytecode at {findings['python_offsets']}")

    # Entropy scan
    block_size = 512
    entropy_hits = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) == block_size and entropy(block) > 7.5:
            entropy_hits.append(hex(i))
    if entropy_hits:
        findings['high_entropy_blocks'] = entropy_hits
        findings['needs_llm'] = True
        findings['llm_payload'] += f"\nHigh-entropy regions at: {entropy_hits}\n"
        log_message(f"{basename}: High entropy blocks at {entropy_hits}")

    # Strings (not used for LLM unless others fail)
    findings['ascii_strings'] = extract_ascii_strings(data)[:10]

    if not findings['needs_llm']:
        log_message(f"{basename}: No LLM analysis needed.")
    return findings

# === MAIN EXECUTION ===
def main():
    parser = argparse.ArgumentParser(description="Scan memory dumps and send complex findings to Zaphod.")
    parser.add_argument("dump_dir", help="Directory with scan_*.bin files")
    parser.add_argument("zaphod_url", help="Zaphod server URL, e.g. http://localhost:8000")
    parser.add_argument("--model", default="mistral", help="Model name to use (default: mistral)")
    parser.add_argument("--outdir", help="Directory to save JSON LLM responses", default=None)
    args = parser.parse_args()

    if args.outdir:
        os.makedirs(args.outdir, exist_ok=True)

    if not os.path.isdir(args.dump_dir):
        print(f"❌ Error: Directory not found: {args.dump_dir}")
        return

    for fname in os.listdir(args.dump_dir):
        if not fname.startswith("scan_"):
            continue
        fpath = os.path.join(args.dump_dir, fname)
        print(f"[*] Scanning {fname}...")
        findings = scan_file(fpath)

        if findings['needs_llm']:
            raw_prompt = (
                "You are an expert reverse engineer.\n"
                "Given the following dump analysis, explain what it appears to do.\n"
                "Return ONLY a JSON object in this format:\n"
                "{ \"summary\": \"<detailed explanation>\" }\n\n"
                f"{findings['llm_payload']}"
            )[:MAX_PROMPT_LENGTH]

            payload = {
                "model_name": args.model,
                "function_code": raw_prompt,
                "max_length": 512
            }

            try:
                response = requests.post(f"{args.zaphod_url}/analyze", json=payload)
                response.raise_for_status()
                raw_output = response.text

                extracted_json = extract_json_blocks(raw_output)
                if extracted_json:
                    try:
                        parsed = json.loads(extracted_json)
                        print(f"[+] LLM response: {parsed['summary'][:120]}...")
                        if args.outdir:
                            with open(os.path.join(args.outdir, f"{fname}.json"), "w") as out:
                                json.dump(parsed, out, indent=2)
                        log_message(f"{fname}: LLM summary written to JSON.")
                    except Exception as e:
                        print(f"[!] JSON parse error: {e}")
                        print(f"Raw block:\n{extracted_json[:300]}")
                        log_message(f"{fname}: JSON parse error: {e}")
                else:
                    print(f"[!] No valid JSON in LLM response for {fname}")
                    log_message(f"{fname}: No valid JSON extracted from LLM response.")

            except Exception as e:
                print(f"[!] Error contacting Zaphod for {fname}: {e}")
                log_message(f"{fname}: LLM request error: {e}")
        else:
            print(f"[~] No LLM needed for {fname}.")

if __name__ == "__main__":
    main()
