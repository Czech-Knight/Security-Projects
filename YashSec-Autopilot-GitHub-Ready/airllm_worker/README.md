# Optional AirLLM Worker

The main YashSec application does **not** require AirLLM. Ollama is recommended for responsive on-the-spot chat. This worker exists for slower, large-model analysis while preserving a stable main application.

## Recommended environment

Use WSL 2 Ubuntu with working NVIDIA CUDA access:

```bash
nvidia-smi
python3 -m venv ~/venvs/yashsec-airllm
source ~/venvs/yashsec-airllm/bin/activate
python -m pip install --upgrade pip
```

Install the correct CUDA-enabled PyTorch build for your environment first. Then, from this folder:

```bash
pip install -r requirements-airllm.txt
```

## Model configuration

```bash
export AIRLLM_MODEL_ID="Qwen/Qwen3-8B"
export AIRLLM_SHARD_PATH="$HOME/airllm-models/yashsec-qwen3-8b"
export AIRLLM_COMPRESSION="4bit"
```

Start the worker:

```bash
uvicorn server:app --host 127.0.0.1 --port 8765
```

Health check:

```bash
curl http://127.0.0.1:8765/health
```

In the YashSec GUI, open **Tools & Setup** and set:

```text
AirLLM worker URL: http://127.0.0.1:8765
Default provider: AirLLM
```

## WSL networking note

When the main YashSec application runs natively on Windows and the worker runs inside WSL, recent WSL configurations commonly forward localhost. If `127.0.0.1:8765` does not work, obtain the WSL IP with `hostname -I`, bind the worker carefully, and configure that address in YashSec. Keep it private and firewall-restricted.

## Practical warning

The first run may download and split a large model, consume significant disk space, and take a long time. AirLLM's layer streaming saves VRAM but can be much slower than a smaller model served by Ollama.
