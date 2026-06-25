"""Lightweight OpenAI-compatible async LLM client.

Self-contained (no third-party SDK). Works with any /chat/completions endpoint:
OpenAI, Azure OpenAI, GLM/Zhipu, Ollama (with /v1), vLLM, etc. The model and
credentials are user-configured via cluescan.yaml — ClueScan is model-agnostic.
"""

from __future__ import annotations

import asyncio
import random
import time
from dataclasses import dataclass, field
from typing import Any

import httpx


class LLMError(Exception):
    def __init__(self, message: str, *, retryable: bool = False, context: dict[str, Any] | None = None):
        super().__init__(message)
        self.retryable = retryable
        self.context = context or {}


class LLMConfigError(LLMError):
    pass


class LLMRateLimitError(LLMError):
    def __init__(self, message: str, retry_after: int | None = None):
        super().__init__(message, retryable=True)
        self.retry_after = retry_after


class LLMTimeoutError(LLMError):
    def __init__(self, message: str, timeout: int | None = None):
        super().__init__(message, retryable=True)
        self.timeout = timeout


class LLMTruncatedError(LLMError):
    """Response hit max_tokens; usually produces invalid JSON — retriable."""


@dataclass
class TokenUsage:
    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0

    def add(self, other: "TokenUsage") -> "TokenUsage":
        self.prompt_tokens += other.prompt_tokens
        self.completion_tokens += other.completion_tokens
        self.total_tokens += other.total_tokens
        return self


@dataclass
class LLMResponse:
    content: str
    model: str
    usage: TokenUsage = field(default_factory=TokenUsage)
    finish_reason: str | None = None
    latency_seconds: float = 0.0


class LLMClient:
    """Async client for an OpenAI-compatible /chat/completions endpoint."""

    def __init__(
        self,
        *,
        base_url: str,
        api_key: str,
        model: str,
        max_tokens: int = 16384,
        temperature: float = 0.1,
        timeout: int = 120,
        max_retries: int = 5,
        json_mode: bool = False,
    ):
        if not api_key:
            raise LLMConfigError("LLM api_key is not configured (set llm.api_key / CLUESCAN_LLM_API_KEY).")
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.model = model
        self.max_tokens = max_tokens
        self.temperature = temperature
        self.timeout = timeout
        self.max_retries = max(1, max_retries)
        self.json_mode = json_mode
        self.total_usage = TokenUsage()
        self._client: httpx.AsyncClient | None = None

    # -- lifecycle --------------------------------------------------------
    def _ensure_client(self) -> httpx.AsyncClient:
        if self._client is None or self._client.is_closed:
            self._client = httpx.AsyncClient(
                base_url=self.base_url,
                headers={
                    "Authorization": f"Bearer {self.api_key}",
                    "Content-Type": "application/json",
                },
                timeout=httpx.Timeout(self.timeout, connect=30.0),
            )
        return self._client

    async def close(self) -> None:
        if self._client and not self._client.is_closed:
            await self._client.aclose()
            self._client = None

    async def __aenter__(self) -> "LLMClient":
        return self

    async def __aexit__(self, *_exc) -> None:
        await self.close()

    # -- core -------------------------------------------------------------
    async def complete(
        self,
        messages: list[dict[str, str]],
        *,
        json_mode: bool | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: list[str] | None = None,
    ) -> LLMResponse:
        """Send a chat completion and return the parsed response.

        Retries on 429 / 5xx / timeouts with exponential backoff + jitter.
        Raises LLMConfigError/LLMError on non-retryable failures."""
        want_json = self.json_mode if json_mode is None else json_mode
        body: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "max_tokens": max_tokens if max_tokens is not None else self.max_tokens,
            "temperature": temperature if temperature is not None else self.temperature,
            "stream": False,
        }
        if want_json:
            body["response_format"] = {"type": "json_object"}
        if stop:
            body["stop"] = stop

        client = self._ensure_client()
        last_err: LLMError | None = None

        for attempt in range(self.max_retries):
            start = time.monotonic()
            try:
                resp = await client.post("/chat/completions", json=body)
            except httpx.TimeoutException as e:
                last_err = LLMTimeoutError(f"LLM request timed out: {e}", timeout=self.timeout)
                await self._sleep_backoff(attempt)
                continue
            except httpx.RequestError as e:
                last_err = LLMError(f"LLM request failed: {e}", retryable=True)
                await self._sleep_backoff(attempt)
                continue

            latency = time.monotonic() - start

            if resp.status_code == 429:
                retry_after = self._parse_retry_after(resp)
                last_err = LLMRateLimitError("LLM rate limit (429)", retry_after=retry_after)
                await self._sleep_backoff(attempt, retry_after=retry_after)
                continue
            if resp.status_code >= 500 or resp.status_code == 408:
                last_err = LLMError(
                    f"LLM server error ({resp.status_code}): {resp.text[:300]}",
                    retryable=True,
                )
                await self._sleep_backoff(attempt)
                continue
            if resp.status_code >= 400:
                # 4xx (non-429): config/request problem — do not retry.
                raise LLMError(
                    f"LLM client error ({resp.status_code}): {resp.text[:500]}",
                    context={"status": resp.status_code},
                )

            return self._parse(resp.json(), latency)

        assert last_err is not None
        raise last_err

    async def complete_text(
        self,
        system: str,
        user: str,
        *,
        json_mode: bool | None = None,
        temperature: float | None = None,
        max_tokens: int | None = None,
    ) -> str:
        """Convenience: return just the content string."""
        r = await self.complete(
            [{"role": "system", "content": system}, {"role": "user", "content": user}],
            json_mode=json_mode,
            temperature=temperature,
            max_tokens=max_tokens,
        )
        return r.content

    # -- helpers ----------------------------------------------------------
    def _parse(self, data: dict[str, Any], latency: float) -> LLMResponse:
        choices = data.get("choices") or []
        if not choices:
            raise LLMError(f"LLM returned no choices: {str(data)[:300]}")
        msg = choices[0].get("message", {})
        content = msg.get("content") or ""
        # Some reasoning models (e.g. GLM) expose reasoning_content; fall back only
        # when the final content is empty so we don't surface scratchpad noise.
        if not content.strip():
            content = msg.get("reasoning_content") or ""
        finish = choices[0].get("finish_reason")

        u = data.get("usage") or {}
        usage = TokenUsage(
            prompt_tokens=int(u.get("prompt_tokens", 0) or 0),
            completion_tokens=int(u.get("completion_tokens", 0) or 0),
            total_tokens=int(u.get("total_tokens", 0) or 0),
        )
        self.total_usage.add(usage)

        if not content.strip() and finish != "length":
            raise LLMError("LLM returned empty content", context={"finish_reason": finish})
        if finish == "length":
            raise LLMTruncatedError(
                f"LLM response truncated at {usage.completion_tokens} tokens (increase max_tokens).",
                retryable=True,
            )
        return LLMResponse(
            content=content,
            model=data.get("model", self.model),
            usage=usage,
            finish_reason=finish,
            latency_seconds=latency,
        )

    @staticmethod
    def _parse_retry_after(resp: httpx.Response) -> int | None:
        ra = resp.headers.get("retry-after")
        if ra:
            try:
                return int(float(ra))
            except ValueError:
                return None
        return None

    async def _sleep_backoff(self, attempt: int, *, retry_after: int | None = None) -> None:
        base = retry_after if retry_after else min(2 ** attempt, 30)
        # jitter to avoid thundering herd; cap at 60s
        delay = min(base * random.uniform(0.6, 1.4), 60.0)
        await asyncio.sleep(max(0.5, delay))


async def extract_json(content: str) -> Any:
    """Best-effort extraction of a JSON object/array from an LLM response.

    Tolerates ```json fences and leading/trailing prose."""
    import json

    text = content.strip()
    if text.startswith("```"):
        # strip a single opening fence (with optional language) and closing fence
        text = text.split("```", 2)[1] if text.count("```") >= 2 else text
        if text.startswith("json"):
            text = text[4:]
        text = text.strip()
        if text.endswith("```"):
            text = text[:-3].strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass
    # fall back: first {...} or [...] span
    for opener, closer in (("{", "}"), ("[", "]")):
        start = text.find(opener)
        end = text.rfind(closer)
        if start != -1 and end != -1 and end > start:
            try:
                return json.loads(text[start : end + 1])
            except json.JSONDecodeError:
                continue
    raise LLMError(f"Could not parse JSON from LLM response: {content[:300]}")
