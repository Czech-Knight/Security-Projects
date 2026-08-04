# Ollama and AirLLM Setup and Integration

> **Current cloud note:** YashSec now also supports explicit, HTTPS-only, allow-listed Ollama Cloud configuration. Local Ollama remains the privacy-first default. See [OLLAMA_MODES.md](OLLAMA_MODES.md) for the current configuration and public-demo boundary.

## 1. Recommended architecture

```text
Interactive finding explanation and code navigation
→ Ollama on Windows
→ http://127.0.0.1:11434

Optional slow large-model/batch analysis
→ AirLLM worker in an isolated environment
→ http://127.0.0.1:8765
```

Neither provider detects vulnerabilities by itself. Deterministic scanners produce findings; local AI explains, correlates and drafts advisory remediation.

## 2. Ollama: recommended default

### Install

Download the official Windows installer from `https://ollama.com/download/windows` and complete setup. Ollama runs as a native Windows background application and exposes its local API on port 11434 by default.

Verify:

```powershell
ollama --version
ollama list
Invoke-RestMethod http://127.0.0.1:11434/api/tags
```

### Pull the configured model

```powershell
ollama pull qwen3:8b
```

The model name in **YashSec → Settings → Local AI** must match `ollama list` exactly.

### Configure YashSec

```text
Provider: Ollama
Endpoint: http://127.0.0.1:11434
Model: qwen3:8b
```

Then open Tool Manager and test again.

### Model storage

Models can consume many gigabytes. To choose another disk:

1. Quit Ollama from the tray.
2. Create a Windows user environment variable:

```text
OLLAMA_MODELS=D:\OllamaModels
```

3. Relaunch Ollama from the Start menu.

### Privacy boundary

YashSec uses the local Ollama API. Local Ollama API access normally does not require authentication. Do not configure `https://ollama.com/api` or a cloud model when the project owner has not approved external transfer.

### Common failures

| Symptom | Resolution |
|---|---|
| Tool Manager says Ollama unavailable | Start Ollama and verify `/api/tags` |
| Model not found | Run `ollama pull <exact-model-name>` |
| First reply is slow | Model is loading; subsequent replies are usually faster |
| Out of memory | Choose a smaller model or reduce competing GPU/RAM use |
| Wrong disk fills | Configure `OLLAMA_MODELS` and restart Ollama |

## 3. AirLLM: optional experimental worker

AirLLM loads model layers in sequence to reduce peak VRAM requirements. This does **not** guarantee interactive speed. Initial decomposition and layer storage can consume substantial disk space, and dependency compatibility must be validated in an isolated environment.

### When to use it

- deep batch review of multiple files;
- larger-model experiments;
- slower executive synthesis;
- situations where VRAM is the primary constraint and fast NVMe is available.

### When not to use it

- every finding click;
- low-latency chat;
- a machine with limited free disk;
- a shared Python environment;
- the critical path of scanning or reporting.

### Recommended environment

For NVIDIA acceleration, use an isolated WSL 2 Ubuntu environment with compatible CUDA/PyTorch. Native Windows support changes across releases and hardware; treat it as experimental unless verified on the exact machine.

In WSL:

```bash
nvidia-smi
python3 -m venv ~/venvs/yashsec-airllm
source ~/venvs/yashsec-airllm/bin/activate
python -m pip install --upgrade pip
```

Install the CUDA-enabled PyTorch build appropriate for the installed driver, then:

```bash
cd /mnt/c/path/to/YashSec-Autopilot/airllm_worker
pip install -r requirements-airllm.txt
```

Keep AirLLM isolated because package installation and fast-moving transformer dependencies can affect other environments.

### Configure model and storage

```bash
export AIRLLM_MODEL_ID="Qwen/Qwen3-8B"
export AIRLLM_SHARD_PATH="$HOME/airllm-models/yashsec-qwen3-8b"
export AIRLLM_COMPRESSION="4bit"
```

`4bit` and `8bit` compression normally depend on bitsandbytes/CUDA. Set `AIRLLM_COMPRESSION=none` when the selected environment does not support that path, but expect much greater disk and memory demand.

### Start the worker

```bash
uvicorn server:app --host 127.0.0.1 --port 8765
```

Health check:

```bash
curl http://127.0.0.1:8765/health
```

Expected fields include model ID, compression, shard path and whether the model has already been loaded.

### Connect YashSec

```text
Provider: AirLLM
AirLLM worker endpoint: http://127.0.0.1:8765
```

If Windows-to-WSL localhost forwarding is unavailable, do not casually bind the worker to every interface. Prefer restoring localhost forwarding. Any non-loopback address requires firewall restriction and a deliberate change to YashSec's local target policy.

### First request behaviour

The first request can:

- download model files;
- split or transform model layers;
- write large shard files;
- take much longer than subsequent requests.

Run the first load manually while monitoring free disk, RAM, GPU memory and temperature.

### Recovery

If the worker becomes unstable:

1. Stop the worker.
2. Keep YashSec provider set to Ollama or disabled.
3. Review the isolated environment package versions.
4. Remove only the specific incomplete shard directory after confirming it is not needed.
5. Recreate the virtual environment rather than repairing a shared Python installation.

## 4. Provider trust labels

YashSec should show:

- **Local protected** when using loopback Ollama/AirLLM;
- **Unavailable** when the configured service cannot be reached;
- **External transfer warning** when an explicitly approved, HTTPS-only, allow-listed Ollama Cloud endpoint is configured.

AI output is always labelled generated analysis and cannot apply a code change or alter finding status.
