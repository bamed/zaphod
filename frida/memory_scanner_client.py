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
JSON_REGEX = r'\{(?:[^{}]|(?R))*\}'
LOG_FILE = "scan.log"

# SMART STRING PATTERNS
IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
EMAIL_REGEX = r'\b[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
FUNCNAME_REGEX = r'\b[A-Za-z_][A-Za-z0-9_]{4,}\b'

# === HELPERS ===
def entropy(data):
    if not data:
        return 0
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * log2(p) for p in probs)

def detect_pe(data):
    return [i for i in range(len(data) - 1) if data[i:i+2] == PE_MAGIC]

def detect_python_bytecode(data):
    return [i for i in range(len(data) - 3) if data[i:i+4] in PYTHON_MAGIC]

def string_entropy(s):
    if not s:
        return 0
    probs = [float(s.count(c)) / len(s) for c in set(s)]
    return -sum(p * log2(p) for p in probs)

def smart_extract_strings(data, min_len=5):
    printable = ''.join(chr(b) if 32 <= b <= 126 else '\x00' for b in data)
    candidates = printable.split('\x00')
    extracted = set()

    for s in candidates:
        s = s.strip()
        if len(s) >= min_len:
            if re.match(IP_REGEX, s) or re.match(DOMAIN_REGEX, s) or re.match(EMAIL_REGEX, s) or re.match(FUNCNAME_REGEX, s):
                extracted.add(s)
            else:
                if not re.fullmatch(r'[A-Z]{4,10}', s):
                    extracted.add(s)
                else:
                    if string_entropy(s) >= 3.0:
                        extracted.add(s)
    return list(extracted)

def extract_json_blocks(text):
    matches = re.findall(JSON_REGEX, text, re.DOTALL)
    return matches[-1] if matches else None

def log_message(message):
    timestamp = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message}\n")

def pseudo_decompile(data):
    """Try to pseudo-decompile code into C-like functions."""
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lines = []
    func_started = False

    try:
        for i in md.disasm(data, 0x1000):
            if not func_started and i.mnemonic == 'push' and i.op_str == 'ebp':
                lines.append(f"int sub_{hex(i.address)}() {{")
                func_started = True
            elif func_started and i.mnemonic == 'mov' and i.op_str == 'ebp, esp':
                continue
            elif func_started and i.mnemonic == 'ret':
                lines.append("  return;")
                lines.append("}")
                break
            elif func_started:
                # Very basic pseudo-instruction
                lines.append(f"  {i.mnemonic} {i.op_str};")
        return "\n".join(lines) if func_started else None
    except Exception as e:
        return None

# === FILE SCAN ===
def scan_file(filepath, decompile_mode=False):
    findings = {
        "pe_offsets": [],
        "python_offsets": [],
        "smart_strings": [],
        "high_entropy_blocks": [],
        "needs_llm": False,
        "llm_payload": "",
        "detection_log": ""
    }

    try:
        with open(filepath, "rb") as f:
            data = f.read()
    except Exception as e:
        findings['detection_log'] = f"ERROR: Could not read file: {e}"
        return findings

    basename = os.path.basename(filepath)
    findings['detection_log'] += f"--- Scanning {basename} ---\n"

    # PE detection
    pe_offsets = detect_pe(data)
    if pe_offsets:
        findings['pe_offsets'] = [hex(off) for off in pe_offsets]
        findings['needs_llm'] = True
        findings['detection_log'] += f"PE headers at: {findings['pe_offsets']}\n"
        if decompile_mode:
            pseudo_c = pseudo_decompile(data[:4096])
            if pseudo_c:
                findings['llm_payload'] += f"Pseudo-decompiled C function:\n{pseudo_c}\n"
                findings['detection_log'] += "Pseudo-C decompiled successfully.\n"
            else:
                findings['llm_payload'] += f"Disassembly fallback:\n"
                findings['detection_log'] += "Pseudo-C failed; fallback to disassembly.\n"
    else:
        findings['detection_log'] += "No PE headers found.\n"

    # Python bytecode
    py_offsets = detect_python_bytecode(data)
    if py_offsets:
        findings['python_offsets'] = [hex(off) for off in py_offsets]
        findings['needs_llm'] = True
        findings['detection_log'] += f"Python bytecode at: {findings['python_offsets']}\n"

    # Entropy
    block_size = 512
    entropy_hits = []
    for i in range(0, len(data), block_size):
        block = data[i:i+block_size]
        if len(block) == block_size and entropy(block) > 7.5:
            entropy_hits.append(hex(i))
    if entropy_hits:
        findings['high_entropy_blocks'] = entropy_hits
        findings['needs_llm'] = True
        findings['detection_log'] += f"High entropy blocks: {entropy_hits}\n"

    # Strings
    smart_strings = smart_extract_strings(data)
    if smart_strings:
        findings['smart_strings'] = smart_strings[:10]
        findings['detection_log'] += f"Interesting strings: {findings['smart_strings']}\n"

    if not findings['needs_llm']:
        findings['detection_log'] += "LLM analysis NOT triggered.\n"
    else:
        findings['detection_log'] += "LLM analysis triggered.\n"

    return findings

# === MAIN ===
def main():
    parser = argparse.ArgumentParser(description="Scan memory dumps and send complex findings to Zaphod.")
    parser.add_argument("dump_dir", help="Directory with scan_*.bin files")
    parser.add_argument("zaphod_url", help="Zaphod server URL, e.g., http://localhost:8000")
    parser.add_argument("--model", default="mistral", help="Model name (default: mistral)")
    parser.add_argument("--outdir", help="Directory to save LLM responses", default=None)
    parser.add_argument("--decompile", action="store_true", help="Attempt lightweight pseudo-decompilation")
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
        findings = scan_file(fpath, decompile_mode=args.decompile)
        log_message(findings['detection_log'])

        if findings['needs_llm']:
            prompt = (
                "You are an expert reverse engineer.\n"
                "Analyze the following findings extracted from memory.\n"
                "Return ONLY a JSON object in this format:\n"
                "{ \"summary\": \"<detailed explanation>\" }\n\n"
                f"{findings['llm_payload']}"
            )[:MAX_PROMPT_LENGTH]

            payload = {
                "model_name": args.model,
                "function_code": prompt,
                "max_length": 512
            }

            try:
                response = requests.post(f"{args.zaphod_url}/analyze", json=payload)
                response.raise_for_status()
                raw_output = response.text

                if args.outdir:
                    with open(os.path.join(args.outdir, f"{fname}.raw.txt"), "w") as rawfile:
                        rawfile.write(raw_output)

                extracted_json = extract_json_blocks(raw_output)
                if extracted_json:
                    try:
                        parsed = json.loads(extracted_json)
                        if args.outdir:
                            with open(os.path.join(args.outdir, f"{fname}.json"), "w") as out:
                                json.dump(parsed, out, indent=2)
                        print(f"[+] LLM summary saved for {fname}.")
                    except Exception as e:
                        if args.outdir:
                            with open(os.path.join(args.outdir, f"{fname}.partial.json"), "w") as partialfile:
                                partialfile.write(extracted_json)
                        print(f"[!] Partial JSON error for {fname}: {e}")
                else:
                    print(f"[!] No JSON extracted for {fname}.")

            except Exception as e:
                print(f"[!] LLM request error for {fname}: {e}")
        else:
            print(f"[~] No LLM needed for {fname}.")

if __name__ == "__main__":
    main()
