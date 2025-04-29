import os
import json
import re
import requests
import argparse
from datetime import datetime
from capstone import Cs, CS_ARCH_X86, CS_MODE_32

# === Helpers ===

def log(msg):
    with open("scan.log", "a") as f:
        f.write(f"[{datetime.now().isoformat()}] {msg.strip()}\n")

def entropy(data):
    from math import log2
    if not data: return 0
    probs = [float(data.count(c)) / len(data) for c in set(data)]
    return -sum(p * log2(p) for p in probs)

def extract_json(text):
    matches = re.findall(r'\{[^{}]*\}', text, re.DOTALL)
    if not matches:
        return {"summary": "No JSON block found."}
    last = matches[-1]
    try:
        return json.loads(last)
    except Exception:
        return {"summary": last.strip(), "error": "Malformed JSON"}

def smart_strings(data, min_len=5):
    ascii_part = ''.join(chr(b) if 32 <= b <= 126 else '\x00' for b in data)
    words = ascii_part.split('\x00')
    return [w for w in words if len(w) >= min_len][:10]

def pseudo_decompile(data):
    md = Cs(CS_ARCH_X86, CS_MODE_32)
    md.detail = True
    lines, started = [], False
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

def scan_file(path, decompile=False):
    findings = {
        "file": os.path.basename(path),
        "reason": "",
        "payload": "",
        "strings": [],
        "needs_llm": False
    }
    with open(path, "rb") as f:
        data = f.read()

    if b'MZ' in data:
        findings["reason"] += "PE header found. "
        findings["needs_llm"] = True
        if decompile:
            d = pseudo_decompile(data[:4096])
            if d:
                findings["payload"] = d
            else:
                findings["payload"] = "\n".join(smart_strings(data))
        else:
            findings["payload"] = "\n".join(smart_strings(data))

    if b'\x42\x0D\x0D' in data:
        findings["reason"] += "Python bytecode magic found. "
        findings["needs_llm"] = True

    if any(entropy(data[i:i+512]) > 7.5 for i in range(0, len(data), 512)):
        findings["reason"] += "High entropy block detected. "
        findings["needs_llm"] = True

    findings["strings"] = smart_strings(data)
    return findings

# === Main ===

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("dump_dir")
    parser.add_argument("zaphod_url")
    parser.add_argument("--model", default="mistral")
    parser.add_argument("--outdir", default="./responses")
    parser.add_argument("--decompile", action="store_true")
    args = parser.parse_args()

    os.makedirs(args.outdir, exist_ok=True)
    summary_report = []

    for fname in os.listdir(args.dump_dir):
        if not fname.startswith("scan_"): continue
        path = os.path.join(args.dump_dir, fname)
        print(f"[*] Scanning {fname}")
        try:
            findings = scan_file(path, decompile=args.decompile)
            log(f"{fname}: {findings['reason']}")
            if findings["needs_llm"]:
                prompt = (
                    "You are an expert reverse engineer.\n"
                    "Analyze the following. Return ONLY JSON: { \"summary\": \"<...>\" }\n\n"
                    + findings["payload"]
                )[:5000]

                # Analyze via /analyze
                response = requests.post(
                    f"{args.zaphod_url}/analyze",
                    json={"model_name": args.model, "function_code": prompt, "max_length": 512}
                )
                raw_txt_path = os.path.join(args.outdir, fname + ".raw.txt")
                with open(raw_txt_path, "w") as f:
                    f.write(findings["payload"])

                llm_json = extract_json(response.text)

                # Chat summary via /chat
                chat_prompt = (
                    "Give a short sentence explaining why this file may be interesting to a reverse engineer."
                )
                chat_payload = {
                    "model_name": args.model,
                    "message": chat_prompt,
                    "function_code": f"{findings['reason']}\n\n{llm_json.get('summary','')}"
                }
                chat_resp = requests.post(f"{args.zaphod_url}/chat", json=chat_payload)
                chat_parsed = extract_json(chat_resp.text)

                summary_report.append({
                    "filename": fname,
                    "reason": findings["reason"].strip(),
                    "chat_summary": chat_parsed.get("summary", "No summary returned.")
                })

            else:
                log(f"{fname}: Not interesting.")

        except Exception as e:
            log(f"{fname}: ERROR: {e}")

    with open("summary_report.json", "w") as f:
        json.dump(summary_report, f, indent=2)

if __name__ == "__main__":
    main()
