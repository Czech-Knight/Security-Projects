from __future__ import annotations

import os
from pathlib import Path
from threading import Lock
from typing import Any

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field


app = FastAPI(title="YashSec AirLLM Worker", version="0.1.1")
MODEL_ID = os.getenv("AIRLLM_MODEL_ID", "Qwen/Qwen3-8B")
SHARD_PATH = Path(os.getenv("AIRLLM_SHARD_PATH", str(Path.home() / "airllm-models" / "yashsec")))
COMPRESSION = os.getenv("AIRLLM_COMPRESSION", "4bit")
_model: Any = None
_lock = Lock()


class ChatRequest(BaseModel):
    messages: list[dict[str, str]]
    max_new_tokens: int = Field(default=420, ge=32, le=1200)
    temperature: float = Field(default=0.2, ge=0, le=1.5)


def get_model():
    global _model
    if _model is not None:
        return _model
    with _lock:
        if _model is not None:
            return _model
        try:
            from airllm import AutoModel
        except ImportError as exc:
            raise RuntimeError("AirLLM is not installed in this worker environment.") from exc
        SHARD_PATH.mkdir(parents=True, exist_ok=True)
        kwargs = {
            "layer_shards_saving_path": str(SHARD_PATH),
            "delete_original": True,
        }
        if COMPRESSION.lower() in {"4bit", "8bit"}:
            kwargs["compression"] = COMPRESSION.lower()
        _model = AutoModel.from_pretrained(MODEL_ID, **kwargs)
        return _model


def format_prompt(messages: list[dict[str, str]]) -> str:
    parts = []
    for message in messages:
        role = message.get("role", "user").upper()
        parts.append(f"{role}:\n{message.get('content', '')}")
    parts.append("ASSISTANT:\n")
    return "\n\n".join(parts)


@app.get("/health")
def health() -> dict[str, Any]:
    return {
        "status": "ok",
        "model_id": MODEL_ID,
        "compression": COMPRESSION,
        "model_loaded": _model is not None,
        "shard_path": str(SHARD_PATH),
    }


@app.post("/v1/chat")
def chat(payload: ChatRequest) -> dict[str, str]:
    try:
        model = get_model()
        prompt = [format_prompt(payload.messages)]
        tokens = model.tokenizer(
            prompt,
            return_tensors="pt",
            return_attention_mask=False,
            truncation=True,
            max_length=4096,
            padding=False,
        )
        input_ids = tokens["input_ids"]
        try:
            input_ids = input_ids.cuda()
        except Exception:
            pass
        result = model.generate(
            input_ids,
            max_new_tokens=payload.max_new_tokens,
            use_cache=True,
            return_dict_in_generate=True,
            do_sample=payload.temperature > 0,
            temperature=max(payload.temperature, 0.01),
        )
        text = model.tokenizer.decode(result.sequences[0], skip_special_tokens=True)
        prompt_text = prompt[0]
        if text.startswith(prompt_text):
            text = text[len(prompt_text):]
        return {"content": text.strip()}
    except Exception as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
