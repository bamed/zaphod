# ZAPHOD - Zenith of Assisted Program Handling and Objective Decompilation

"Don't Panic. Just Disassemble."

Welcome to **ZAPHOD**, your soon-to-be-favorite companion for malware analysis, decompilation, and unraveling the mysteries of obfuscated code, all without losing your towel.

---

## 📖 Project Overview

ZAPHOD connects **Ghidra** to a **local or cloud-hosted LLM** that helps:

- Decompile and analyze suspicious binaries.
- Suggest deobfuscated function names.
- Dump payloads, decode obfuscation, hook processes.
- Summarize functions in simple English.
- Answer "What is this eldritch horror of a function doing?" questions.

All with the calm, dry wit of a vaguely unhelpful but enthusiastic android.

---

## 🫠 Installation (Local Dev Mode)

### Requirements

- Windows 11 / WSL2 or Linux
- Docker & Docker Compose
- Python 3.10+ (for running Ghidra scripts)
- A GPU that isn't powered by a hamster wheel (8GB VRAM recommended)
- Git

### Setup

1. Clone this Repository:

```bash
git clone https://github.com/your-username/zaphod.git
cd zaphod
```

2. Create `config/config.json`:

```json
{
  "hf_token": "your_huggingface_access_token"
}
```

**Note:** `.gitignore` will automatically prevent you from accidentally committing your secret keys to interstellar infamy.

3. Choose your Deployment Mode:

#### Development Mode (auto-reloads server on changes):

```bash
docker-compose -f docker-compose.dev.yml up
```

#### Production Mode (when you want to pretend you know what you're doing):

```bash
docker-compose up
```

4. Verify the API Server is Up: Visit: [http://localhost:8000/docs](http://localhost:8000/docs)

If you see FastAPI's swagger UI, you're halfway to enlightenment.

---

## 🚀 Ghidra Setup

1. Copy Scripts:

- Copy all Python scripts from `/ghidra-scripts/` into your Ghidra's `ghidra_scripts` directory.

2. Using Scripts:

- Open a binary in Ghidra.
- Navigate to **Script Manager**.
- Run scripts like `BatchFunctionRenamer.py` to automatically rename terrible function names like `_funky_monkey_42` to something almost sensible.

---

## 🛸 Deploying ZAPHOD to Vast.ai

When your puny laptop can't handle 10B parameter models, Vast.ai shall provide.

### Setup for Vast.ai

1. Rent a suitable instance:

- GPU: Tesla P100 / A6000 / 3090 / Something fancy
- RAM: 48GB+ recommended
- CUDA 12.x supported

2. Create a Vast.ai Custom Template (or just SSH into instance manually):

On your SSH session:

```bash
apt update && apt install -y git docker-compose
cd /workspace
git clone https://github.com/your-username/zaphod.git
cd zaphod
mkdir config
nano config/config.json # Paste Huggingface token
docker-compose -f docker-compose.vast.yml up
```

3. Expose Port 8000:

- Make sure your Vast.ai instance allows traffic to port 8000.

4. Test it:

```bash
curl http://your-vast-ip:8000/models
```

If you see model names listed, you're now a galactic-level cybernetic researcher.

---

## 🌐 Current Features (as of this improbable timeline)

- 💻 Local and Cloud hosting (switch models easily)
- 🤔 Function Renaming (via LLM)
- 📃 Function Summarization
- 🔄 Integration with Ghidra scripting
- 🧬 Automatic model loading via `config.json`

---

## 📊 TODO (or Things We'll Regret Adding Later)

- 

---

## 📢 Final Words

In the unlikely event of catastrophic failure, remember: **"It's probably not your fault."**

If all else fails, turn it off and on again, or offer it a cup of tea.

---

_"It is a mistake to think you can solve any major problems just with potatoes."_ — **Douglas Adams**
