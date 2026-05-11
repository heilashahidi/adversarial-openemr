"""
LLM Client — unified interface to OpenRouter for all agent roles.
Each agent specifies its model; the client handles the API call.
"""

import json
import time
import openai
from config import OPENROUTER_API_KEY, OPENROUTER_BASE_URL, MODELS, MODEL_COSTS

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
        }

    except Exception as e:
        return {
            "text": "",
            "model": model,
            "tokens": {"input": 0, "output": 0},
            "cost": 0,
            "latency_ms": round((time.time() - start) * 1000),
            "success": False,
            "error": str(e),
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
