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

IP_REGEX = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
DOMAIN_REGEX = r'\b[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
EMAIL_REGEX = r'\b[a-zA-Z0-9._%-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
FUNCNAME_REGEX = r'\b[A-Za-z_][A-Za-z0-9_]{4,}\b'

# === UTILS ===
def entropy(data):
    if not data:
        return 0
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * log2(p) for p in probs)

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
            if (re.match(IP_REGEX, s) or re.match(DOMAIN_REGEX, s) or
                re.match(EMAIL_REGEX, s) or re.match(FUNCNAME_REGEX, s)):
                extracted.add(s)
            elif not re.fullmatch(r'[A-Z]{4,10}', s) or string_entropy(s) >= 3.0:
                extracted.add(s)
    return list(extracted)

def extract_json_blocks(text):
    matches = re.findall(JSON_REGEX, text, re.DOTALL)
    return matches[-1] if matches else None

def log_message(message):
    timestamp = datetime.datetime.now().isoformat()
    with open(LOG_FILE, "a") as f:
        f.write(f"[{timestamp}] {message.strip()}\n")

def pseudo_decompile(data):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lines = []
    started = False
    try:
        for i in md.disasm(data, 0x1000):
            if not started and i.mnemonic == 'push' and i.op_str == 'ebp':
                lines.append(f"int sub_{hex(i.address)}() {{")
                started = True
            elif started and i.mnemonic == 'ret':
                lines.append("  return;")
                lines.append("}")
                break
            elif started:
                lines.append(f"  {i.mnemonic} {i.op_str};")
        return "\n".join(lines) if started else None
    except Exception:
        return None

# === MAIN SCAN LOGIC ===
def scan_file(filepath, decompile=False):
    findings = {
        "filename": os.path.basename(filepath),
        "pe_headers": [],
        "python_offsets": [],
        "high_entropy_blocks": [],
        "smart_strings": [],
        "llm_payload": "",
        "llm_trigger_reason": "",
        "needs_llm": False
    }
    with open(filepath, "rb") as f:
        data = f.read()

    pe = [hex(i) for i in range(len(data)) if data[i:i+2] == PE_MAGIC]
    if pe:
        findings["pe_headers"] = pe
        findings["llm_trigger_reason"] += "PE header found. "
        findings["needs_llm"] = True
        if decompile:
            pseudo = pseudo_decompile(data[:4096])
            if pseudo:
                findings["llm_payload"] = pseudo
            else:
                findings["llm_payload"] = "\n".join(smart_extract_strings(data[:512]))
        else:
            findings["llm_payload"] = "\n".join(smart_extract_strings(data[:512]))

    pyc = [hex(i) for i in range(len(data)) if data[i:i+4] in PYTHON_MAGIC]
    if pyc:
        findings["python_offsets"] = pyc
        findings["llm_trigger_reason"] += "Python bytecode magic found. "
        findings["needs_llm"] = True
        findings["llm_payload"] += "\n# Possibly Python bytecode"

    high_entropy = [hex(i) for i in range(0, len(data), 512)
                    if entropy(data[i:i+512]) > 7.5]
    if high_entropy:
        findings["high_entropy_blocks"] = high_entropy
        findings["llm_trigger_reason"] += "High entropy block detected. "
        findings["needs_llm"] = True

    findings["smart_strings"] = smart_extract_strings(data)[:10]

    return findings, data

def build_llm_prompt(payload):
    return (
        "You are an expert reverse engineer.\n"
        "Analyze the following code or decompiled fragment. Provide ONLY a JSON object:\n"
        "{ \"summary\": \"<concise explanation>\" }\n\n" + payload
    )[:MAX_PROMPT_LENGTH]

def safe_write_json(path, obj):
    try:
        with open(path, "w") as f:
            json.dump(obj, f, indent=2)
    except Exception:
        with open(path, "w") as f:
            f.write(json.dumps(str(obj)))

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dump_dir")
    parser.add_argument("zaphod_url")
    parser.add_argument("--model", default="mistral")
    parser.add_argument("--outdir", default="./responses")
    parser.add_argument("--decompile", action="store_true")
    parser.add_argument("--debug", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    summary_report = []

    for fname in os.listdir(args.dump_dir):
        if not fname.startswith("scan_"):
            continue

        fpath = os.path.join(args.dump_dir, fname)
        print(f"[*] Scanning {fname}")
        try:
            findings, raw_data = scan_file(fpath, decompile=args.decompile)
            log_message(f"{fname}: {findings['llm_trigger_reason']}")

            if findings["needs_llm"]:
                prompt = build_llm_prompt(findings["llm_payload"])
                payload = {
                    "model_name": args.model,
                    "function_code": prompt,
                    "max_length": 512
                }

                r = requests.post(f"{args.zaphod_url}/analyze", json=payload)
                response_text = r.text
                raw_outfile = os.path.join(args.outdir, fname + ".raw.txt")
                with open(raw_outfile, "w") as f:
                    f.write(findings["llm_payload"])

                try:
                    extracted = extract_json_blocks(response_text)
                    result = json.loads(extracted)
                    safe_write_json(os.path.join(args.outdir, fname + ".json"), result)
                except Exception as e:
                    log_message(f"{fname}: Failed to parse JSON: {e}")
                    safe_write_json(os.path.join(args.outdir, fname + ".partial.json"), response_text)
                    result = {"summary": response_text.strip()[:200], "error": str(e)}

                if args.debug:
                    debug_out = {
                        "filename": fname,
                        "decompiled_code": findings["llm_payload"],
                        "disassembly_fallback": None,
                        "llm_response": result,
                        "errors": None if isinstance(result, dict) else "LLM output not parsed"
                    }
                    safe_write_json(os.path.join(args.outdir, fname + ".debug.json"), debug_out)

                # now send to /chat for summary sentence
                chat_payload = {
                    "model_name": args.model,
                    "message": "Give a short sentence explaining why this file may be interesting to a reverse engineer.",
                    "function_code": f"{findings['llm_trigger_reason']}\n\n{result.get('summary', '')}"
                }
                try:
                    chat_resp = requests.post(f"{args.zaphod_url}/chat", json=chat_payload).json()
                    summary = {
                        "file": fname,
                        "reason": findings["llm_trigger_reason"],
                        "summary": result.get("summary", "")[:500],
                        "chat_summary": chat_resp.get("response", "")[:300]
                    }
                    summary_report.append(summary)
                except Exception as e:
                    log_message(f"{fname}: Failed chat summary: {e}")

            else:
                log_message(f"{fname}: Not interesting.")

        except Exception as e:
            log_message(f"{fname}: SCAN ERROR: {e}")

    # Write summary
    with open("summary_report.json", "w") as f:
        json.dump(summary_report, f, indent=2)

if __name__ == "__main__":
    main()
