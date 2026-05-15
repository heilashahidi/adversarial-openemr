"""
LLM Client — unified interface to OpenRouter for all agent roles.
Each agent specifies its model; the client handles the API call.
"""

import json
import random
import time
import openai
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, MODELS, MODEL_COSTS

# Retry tuning for 429 / capacity-exceeded errors (ARCHITECTURE.md §7.2).
# Exponential backoff with jitter; bounded attempts so we never block a
# whole run on a single sustained outage.
_RETRY_MAX_ATTEMPTS = 4         # 1 initial + 3 retries
_RETRY_BASE_SECONDS = 1.0
_RETRY_JITTER_FRAC  = 0.25      # ±25% jitter to prevent thundering-herd retries
_RETRYABLE_STATUS   = {429, 502, 503, 504}  # rate-limit + transient upstream


def _is_retryable_error(exc: Exception) -> bool:
    """True if the exception represents a transient condition worth retrying."""
    # OpenAI SDK raises typed errors with .status_code on the response
    status = getattr(exc, "status_code", None) or getattr(getattr(exc, "response", None), "status_code", None)
    if status in _RETRYABLE_STATUS:
        return True
    msg = str(exc).lower()
    # Anthropic/OpenRouter sometimes surface capacity as a body error rather
    # than a typed exception. Catch the most common phrasings.
    return any(s in msg for s in (
        "429", "rate limit", "rate_limit", "rate-limit",
        "capacity", "overloaded", "too many requests",
        "service unavailable", "gateway timeout",
    ))


def _backoff_seconds(attempt: int) -> float:
    """Exponential backoff with jitter. attempt=1 → ~1s, 2 → ~2s, 3 → ~4s."""
    base = _RETRY_BASE_SECONDS * (2 ** (attempt - 1))
    jitter = base * _RETRY_JITTER_FRAC * (2 * random.random() - 1)
    return max(0.1, base + jitter)

# LangSmith @traceable becomes a no-op if LANGCHAIN_TRACING_V2 is unset, so the
# import is safe whether or not the user has configured LangSmith.
try:
    from langsmith import traceable
except ImportError:
    def traceable(*args, **kwargs):
        if len(args) == 1 and callable(args[0]):
            return args[0]
        def _decorator(fn):
            return fn
        return _decorator


# Singleton client
_client = None


def get_client():
    global _client
    if _client is None:
        _client = openai.OpenAI(
            base_url=OPENROUTER_BASE_URL,
            api_key=OPENROUTER_API_KEY,
        )
    return _client


@traceable(run_type="llm", name="call_llm")
def call_llm(
    role: str,
    messages: list[dict],
    model_override: str = None,
    temperature: float = 0.7,
    max_tokens: int = 1024,
    json_mode: bool = False,
    extra_body: dict = None,
) -> dict:
    """
    Call an LLM via OpenRouter.

    Args:
        role: agent role key from MODELS config (red_team, judge, orchestrator, documentation)
        messages: chat messages in OpenAI format
        model_override: override the default model for this role
        temperature: sampling temperature
        max_tokens: max output tokens
        json_mode: request JSON output format

    Returns:
        dict with text, tokens, cost, latency, model
    """
    client = get_client()
    model = model_override or MODELS.get(role, "mistralai/mistral-7b-instruct")

    kwargs = {
        "model": model,
        "messages": messages,
        "temperature": temperature,
        "max_tokens": max_tokens,
    }

    if json_mode:
        kwargs["response_format"] = {"type": "json_object"}

    if extra_body:
        kwargs["extra_body"] = extra_body

    start = time.time()
    last_exc = None
    for attempt in range(1, _RETRY_MAX_ATTEMPTS + 1):
        try:
            response = client.chat.completions.create(**kwargs)
            elapsed = time.time() - start

            text = response.choices[0].message.content or ""
            input_tokens = response.usage.prompt_tokens if response.usage else 0
            output_tokens = response.usage.completion_tokens if response.usage else 0

            # Calculate cost
            costs = MODEL_COSTS.get(model, {"input": 0.10, "output": 0.10})
            cost = (input_tokens * costs["input"] / 1_000_000) + (output_tokens * costs["output"] / 1_000_000)

            return {
                "text": text,
                "model": model,
                "tokens": {"input": input_tokens, "output": output_tokens},
                "cost": round(cost, 6),
                "latency_ms": round(elapsed * 1000),
                "success": True,
                "retry_attempts": attempt - 1,
            }

        except Exception as e:
            last_exc = e
            if attempt < _RETRY_MAX_ATTEMPTS and _is_retryable_error(e):
                sleep_s = _backoff_seconds(attempt)
                # Stderr-only — calling agents shouldn't be spammed with retry
                # noise on every transient blip. LangSmith captures the full trace.
                import sys
                print(f"  [llm_client] {role} {model} attempt {attempt}/{_RETRY_MAX_ATTEMPTS} "
                      f"retryable error ({type(e).__name__}: {str(e)[:80]}); "
                      f"backoff {sleep_s:.1f}s", file=sys.stderr)
                time.sleep(sleep_s)
                continue
            break

    return {
        "text": "",
        "model": model,
        "tokens": {"input": 0, "output": 0},
        "cost": 0,
        "latency_ms": round((time.time() - start) * 1000),
        "success": False,
        "error": str(last_exc) if last_exc else "unknown",
        "retry_attempts": attempt - 1 if last_exc else 0,
    }


def parse_json_response(text: str) -> dict:
    """Safely parse JSON from LLM output."""
    clean = text.strip()
    if clean.startswith("```"):
        clean = clean.split("\n", 1)[1] if "\n" in clean else clean[3:]
    if clean.endswith("```"):
        clean = clean[:-3]
    clean = clean.strip()

    try:
        return json.loads(clean)
    except json.JSONDecodeError:
        return {}
