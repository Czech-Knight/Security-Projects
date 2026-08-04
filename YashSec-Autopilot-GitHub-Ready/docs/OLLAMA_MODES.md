# Ollama Modes and Privacy Boundaries

YashSec supports Ollama in two distinct modes. Local mode is the default for real repository work. Cloud mode is an explicit option for the read-only public demo or an organisation-approved environment.

## Local Ollama: recommended

Install Ollama for Windows, then pull a model:

```powershell
ollama pull qwen3:8b
ollama list
```

For lower-memory machines:

```powershell
ollama pull qwen2.5-coder:1.5b
```

Configuration:

```dotenv
YASHSEC_AI_PROVIDER=ollama
YASHSEC_ALLOW_CLOUD_AI=false
YASHSEC_OLLAMA_URL=http://127.0.0.1:11434
YASHSEC_OLLAMA_MODEL=qwen3:8b
```

Repository excerpts selected for an AI question remain on the local machine and are sent only to the loopback Ollama endpoint.

## Docker local Ollama

```bash
docker compose up --build
```

The application calls `http://ollama:11434` inside the Compose network. The service is not published to the host network. Model data persists in the `ollama_data` volume.

Change the model before first startup:

```bash
YASHSEC_OLLAMA_MODEL=qwen3:8b docker compose up --build
```

## Ollama Cloud: explicit opt-in

Cloud mode sends selected repository excerpts and the user question to the configured remote provider. Do not use it with private source, credentials, CVs, client data, or regulated information unless the data owner has explicitly approved the transfer.

Required host configuration:

```dotenv
YASHSEC_ALLOW_CLOUD_AI=true
YASHSEC_CLOUD_AI_HOSTS=ollama.com
YASHSEC_OLLAMA_URL=https://ollama.com
YASHSEC_OLLAMA_MODEL=gpt-oss:20b
OLLAMA_API_KEY=<host secret>
```

Security controls:

- non-loopback endpoints are rejected unless cloud AI is explicitly enabled;
- remote endpoints must use HTTPS;
- the hostname must be in `YASHSEC_CLOUD_AI_HOSTS`;
- the API key is read only from the server environment;
- the settings API returns only whether a key is configured, never its value;
- browser JavaScript never receives the key;
- demo-mode AI requests are rate-limited per IP;
- repository files remain untrusted data and cannot instruct the assistant to change policy or execute commands.

## Provider failure behaviour

YashSec does not silently switch providers. A missing key, missing model, rate limit, connection failure, or cloud outage returns a clear provider error. Scanner evidence and the rest of the workspace continue to function.

## AI evidence policy

AI output is always interpretation. It must not be presented as a confirmed vulnerability without deterministic scanner or repository evidence. The system prompt asks the assistant to separate scanner-confirmed evidence, repository evidence, assumptions, missing information, and suggested actions.

## Troubleshooting

### Local connection refused

```powershell
ollama list
curl.exe http://127.0.0.1:11434/api/tags
```

Start Ollama and verify the endpoint in Settings.

### Model not found

```powershell
ollama pull <model-name>
```

Ensure `YASHSEC_OLLAMA_MODEL` exactly matches `ollama list`.

### Cloud 401 or missing key

Confirm `OLLAMA_API_KEY` exists in the hosting provider secret store and redeploy. Do not print it in logs.

### Cloud 404

List models available to the account through the Ollama API and update `YASHSEC_OLLAMA_MODEL`.

### Cloud 429

The provider rate or usage limit was reached. Wait, lower usage, or use local Ollama. YashSec's own demo limiter does not remove provider-side quotas.
