#!/usr/bin/env python3
"""Real LLM providers for the gatekeeper agentic loop.

This module provides concrete implementations of the ``LLMProvider`` ABC
defined in ``agentic.py``.  Each provider wraps a specific LLM API (OpenAI,
Anthropic, etc.) and returns JSON responses that ``_select_with_llm`` can
parse into ``AgentAction`` instances.

Usage
─────
    from gatekeeper_eos_v6.providers import OpenAIProvider

    provider = OpenAIProvider(model="gpt-4o-mini")
    response = provider.generate("... prompt ...")
    # → '{"tool": "nmap", "command": "discover", ...}'

Rate limiting & retries
───────────────────────
Both providers support configurable rate limiting (token bucket) and
retry with exponential backoff for transient API errors (429, 503,
connection errors).  Use ``max_retries`` (default 3) and ``rate_limiter``
constructor arguments to tune production behaviour.
"""

from __future__ import annotations

import json
import os
import random
import time
import enum
from collections.abc import Callable
from typing import Any

# Local imports — the LLMProvider ABC lives in agentic.py
from gatekeeper_eos_v6.agentic import LLMProvider


# ===========================================================================
# Rate limiter — token bucket
# ===========================================================================


class RateLimiter:
    """Token-bucket rate limiter for LLM API calls.

    Maintains a bucket of *capacity* tokens.  Every ``_call_and_retry``
    consumes one token.  Tokens refill at *tokens_per_second* up to the
    bucket capacity.  If the bucket is empty, the caller must wait until
    a token is available (sleeps the required amount).

    Parameters
    ----------
    capacity:
        Maximum burst size — how many requests can be sent back-to-back
        before the limiter kicks in (default 60).
    tokens_per_second:
        Steady-state refill rate (default 3, so ~20 RPM).  For OpenAI
        tier-1 this is safe; for higher tiers increase to 5-10.
    """

    def __init__(self, capacity: int = 60, tokens_per_second: float = 3.0) -> None:
        self._capacity = capacity
        self._tokens_per_second = tokens_per_second
        self._tokens = float(capacity)
        self._last_refill = time.monotonic()
        self._total_waited = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def wait_if_needed(self) -> None:
        """Block until a rate-limit token is available.

        If the bucket has tokens, consumes one and returns immediately.
        If empty, sleeps for the refill time of one token and then
        consumes one.

        Thread-safe for single-threaded use (the agent loop is
        single-threaded by design).
        """
        self._refill()

        if self._tokens >= 1.0:
            self._tokens -= 1.0
            return

        # Bucket empty — sleep for one token's worth of time
        sleep_for = 1.0 / self._tokens_per_second
        time.sleep(sleep_for)
        self._total_waited += sleep_for
        self._tokens = 0.0  # consumed the just-refilled token

    @property
    def available_tokens(self) -> float:
        """Number of tokens currently in the bucket (best-effort)."""
        self._refill()
        return self._tokens

    @property
    def total_wait_seconds(self) -> float:
        """Cumulative seconds spent waiting for rate-limit tokens."""
        return self._total_waited

    def reset(self) -> None:
        """Reset the bucket to full capacity and clear wait tracking."""
        self._tokens = float(self._capacity)
        self._last_refill = time.monotonic()
        self._total_waited = 0.0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _refill(self) -> None:
        """Refill tokens based on elapsed time since last refill."""
        now = time.monotonic()
        elapsed = now - self._last_refill
        gained = elapsed * self._tokens_per_second
        self._tokens = min(self._capacity, self._tokens + gained)
        self._last_refill = now


# ===========================================================================
# Retry helper — exponential backoff for transient API errors
# ===========================================================================


def _call_with_retry(
    api_call: Callable[[], str],
    max_retries: int = 3,
    base_delay: float = 1.0,
    max_delay: float = 60.0,
    rate_limiter: RateLimiter | None = None,
) -> tuple[str, int, float]:
    """Call *api_call* with exponential backoff retry.

    Retries on transient errors (429, 503, connection resets, timeouts).
    Non-transient errors (401, 403, 400) are **not** retried.

    Parameters
    ----------
    api_call:
        A zero-argument callable that returns the response text string
        on success, or raises an exception on failure.
    max_retries:
        Maximum number of retry attempts (default 3).
    base_delay:
        Initial delay in seconds before the first retry (default 1.0).
    max_delay:
        Maximum delay cap in seconds (default 60.0).
    rate_limiter:
        Optional ``RateLimiter`` to wait for a token before each call.

    Returns
    -------
    A tuple of (response_text, total_retries, total_delay_seconds).
    On fatal failure after all retries, returns ("", retries, delay).
    """
    last_error: Exception | None = None
    total_delay = 0.0
    retries = 0

    for attempt in range(max_retries + 1):
        # Rate-limit wait before each attempt
        if rate_limiter is not None:
            rate_limiter.wait_if_needed()

        try:
            result = api_call()
            return result, retries, total_delay
        except Exception as exc:
            last_error = exc
            if attempt >= max_retries:
                break

            # Determine if this is retryable
            if not _is_retryable_error(exc):
                break

            retries += 1
            delay = min(base_delay * (2 ** (attempt)), max_delay)
            # Add jitter: ±25%
            delay *= 0.75 + random.random() * 0.5
            total_delay += delay
            time.sleep(delay)

    return "", retries, total_delay


def _is_retryable_error(exc: Exception) -> bool:
    """Return True if the exception represents a transient error.

    Retryable: 429 (rate limit), 503 (service unavailable), 502 (bad
    gateway), 500 (internal server error — sometimes transient),
    connection errors, timeouts.

    Non-retryable: 400, 401, 403, 404, 413, 422, JSON decode errors.
    """
    exc_str = str(exc).lower()

    # HTTP status code checks
    for code, retryable in [("429", True), ("503", True), ("502", True),
                             ("500", True), ("401", False), ("403", False),
                             ("400", False), ("404", False)]:
        if code in exc_str:
            return retryable

    # Connection / timeout errors are always retryable
    if any(kw in exc_str for kw in ["connection", "timeout", "timed out",
                                     "reset", "temporarily unavailable",
                                     "too many requests"]):
        return True

    # Non-HTTP errors (JSON decode, etc.) — not retryable
    if any(kw in exc_str for kw in ["decode", "parse", "invalid"]):
        return False

    # Default: don't retry (safety)
    return False


# ===========================================================================
# Shared default rate limiter
# ===========================================================================

_DEFAULT_RATE_LIMITER = RateLimiter(capacity=60, tokens_per_second=3.0)


# ===========================================================================
# Circuit breaker — prevents calls after repeated failures
# ===========================================================================


class CircuitState(enum.Enum):
    """Circuit breaker state machine states."""
    CLOSED = "closed"
    OPEN = "open"
    HALF_OPEN = "half_open"


class CircuitBreakerError(Exception):
    """Raised when a call is rejected because the circuit is open."""


class CircuitBreaker:
    """Circuit breaker for LLM API calls.

    Prevents cascading failures by fast-rejecting calls after a threshold of
    consecutive failures.  After a recovery timeout the circuit transitions
    to half-open, allowing a limited number of test calls.  If they succeed
    the circuit closes; if they fail it opens again.

    States
    ------
    CLOSED:
        Normal operation.  Each failure increments a counter.  When the
        counter reaches ``failure_threshold`` the circuit opens.
    OPEN:
        All calls are fast-rejected (return the configured fallback).
        After ``recovery_timeout`` seconds the circuit transitions to
        half-open automatically (lazy evaluation via ``.state``).
    HALF_OPEN:
        A limited number of test calls (``half_open_max_retries``) are
        allowed through.  If one succeeds the circuit closes.  If all
        fail the circuit opens again.

    Parameters
    ----------
    failure_threshold:
        Consecutive failures before the circuit opens (default 5).
    recovery_timeout:
        Seconds to wait before transitioning to half-open (default 60.0).
    half_open_max_retries:
        How many test calls to allow in half-open state (default 3).
    """

    def __init__(
        self,
        failure_threshold: int = 5,
        recovery_timeout: float = 60.0,
        half_open_max_retries: int = 3,
    ) -> None:
        self._failure_threshold = failure_threshold
        self._recovery_timeout = recovery_timeout
        self._half_open_max_retries = half_open_max_retries
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._half_open_retries = 0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    @property
    def state(self) -> CircuitState:
        """Current circuit state (lazy OPEN → HALF_OPEN transition)."""
        if self._state is CircuitState.OPEN:
            if time.monotonic() - self._last_failure_time >= self._recovery_timeout:
                self._state = CircuitState.HALF_OPEN
                self._half_open_retries = 0
        return self._state

    @property
    def failure_count(self) -> int:
        return self._failure_count

    @property
    def closed(self) -> bool:
        return self.state is CircuitState.CLOSED

    @property
    def open(self) -> bool:
        return self.state is CircuitState.OPEN

    def call(self, func: Callable[[], str], fallback: str = "") -> str:
        """Execute *func* through the circuit breaker.

        Parameters
        ----------
        func:
            Zero-argument callable returning a string.
        fallback:
            Value returned when the circuit is open (default "").

        Returns
        -------
        The result of *func* on success, or *fallback* if the circuit is
        open.  Exceptions from *func* are re-raised after recording the
        failure.
        """
        if self.state is CircuitState.OPEN:
            return fallback

        try:
            result = func()
            self._record_success()
            return result
        except CircuitBreakerError:
            # Already recorded — just re-raise for the retry loop
            raise
        except Exception as exc:
            self._record_failure()
            raise

    def reset(self) -> None:
        """Manually close the circuit and reset all counters."""
        self._state = CircuitState.CLOSED
        self._failure_count = 0
        self._last_failure_time = 0.0
        self._half_open_retries = 0

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _record_success(self) -> None:
        self._failure_count = 0
        self._state = CircuitState.CLOSED
        self._half_open_retries = 0

    def _record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure_time = time.monotonic()

        if self._state is CircuitState.HALF_OPEN:
            self._half_open_retries += 1
            if self._half_open_retries >= self._half_open_max_retries:
                self._state = CircuitState.OPEN
                self._half_open_retries = 0
        elif self._failure_count >= self._failure_threshold:
            self._state = CircuitState.OPEN


# ---------------------------------------------------------------------------
# Default system prompt for action generation
# ---------------------------------------------------------------------------

DEFAULT_SYSTEM_PROMPT = """\
You are a penetration-testing AI that chooses the next action to take. \
You must respond with valid JSON only — no markdown, no commentary.

The JSON must have these fields:
  "tool":      one of the allowed tool names
  "command":   one of that tool's allowed commands
  "arguments": a dict of arguments for the tool (e.g. {"target": "..."})
  "target":    the target host or IP
  "reasoning": a short explanation of why this action was chosen

Example response:
{"tool": "nmap", "command": "discover", "arguments": {"target": "10.0.0.1", "ports": "top-1000"}, "target": "10.0.0.1", "reasoning": "Initial recon on target"}

Respond ONLY with JSON. No other text."""


# ---------------------------------------------------------------------------
# OpenAI provider
# ---------------------------------------------------------------------------


class OpenAIProvider(LLMProvider):
    """LLM provider backed by the OpenAI chat completions API.

    Reads ``OPENAI_API_KEY`` from the environment by default (standard
    OpenAI convention) but also accepts an explicit *api_key* argument
    for custom endpoints or alternate key sources.

    The model can be any OpenAI chat model (``gpt-4o``, ``gpt-4o-mini``,
    ``gpt-4-turbo``, or even a compatible third-party endpoint).

    If the API call fails or returns unparseable content, ``generate()``
    returns an empty string so the caller falls back to rule-based selection.

    Parameters
    ----------
    api_key:
        OpenAI API key.  Defaults to ``OPENAI_API_KEY`` env var.
    model:
        Model name (default: ``gpt-4o-mini`` — fast and cheap for action
        selection).
    temperature:
        Sampling temperature (default 0.2 — low for deterministic outputs).
    max_tokens:
        Max tokens in the response (default 1024).
    timeout:
        HTTP request timeout in seconds (default 30).
    base_url:
        Optional base URL for custom / compatible endpoints
        (e.g. ``http://localhost:8080/v1`` for local models).
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gpt-4o-mini",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: int = 30,
        base_url: str | None = None,
        max_retries: int = 3,
        rate_limiter: RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        super().__init__(model=model)
        from openai import OpenAI

        key = api_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            raise ValueError(
                "OPENAI_API_KEY not set. Export it or pass api_key= to the constructor."
            )

        kwargs: dict[str, Any] = {"api_key": key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url

        self._client = OpenAI(**kwargs)
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._max_retries = max_retries
        self._rate_limiter = rate_limiter or _DEFAULT_RATE_LIMITER
        self._circuit_breaker = circuit_breaker
        self.call_count = 0
        self.last_prompt = ""
        self.last_raw_response: str = ""
        self.retry_count = 0
        self.total_retry_delay: float = 0.0
        self.last_rate_limit_hit: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the OpenAI model and return the response text.

        Retries on transient errors (429, 503) with exponential backoff
        up to ``self._max_retries`` attempts.  Returns an empty string
        on ultimate failure so the caller can fall back to rule-based
        selection (see ``_select_with_llm``).
        """
        self.call_count += 1
        self.last_prompt = prompt

        messages = [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        def _do_call() -> str:
            response = self._client.chat.completions.create(
                model=self.model,
                messages=messages,
                temperature=self._temperature,
                max_tokens=self._max_tokens,
                timeout=self._timeout,
            )

            content = response.choices[0].message.content or ""
            self.last_raw_response = content

            # Validate it's parseable JSON before returning
            if content.strip():
                json.loads(content)  # validate
                return content

            return ""

        # Wrap with circuit breaker if configured
        if self._circuit_breaker is not None:
            def _cb_wrapped() -> str:
                return self._circuit_breaker.call(_do_call, fallback="")
            api_call: Callable[[], str] = _cb_wrapped
        else:
            api_call = _do_call

        result, retries, delay = _call_with_retry(
            api_call,
            max_retries=self._max_retries,
            rate_limiter=self._rate_limiter,
        )

        self.retry_count += retries
        self.total_retry_delay += delay
        if retries > 0:
            self.last_rate_limit_hit = time.time()

        return result


# ---------------------------------------------------------------------------
# Anthropic provider
# ---------------------------------------------------------------------------


class AnthropicProvider(LLMProvider):
    """LLM provider backed by the Anthropic Messages API.

    Reads ``ANTHROPIC_API_KEY`` from the environment by default (standard
    Anthropic convention) but also accepts an explicit *api_key* argument.

    The model can be any Anthropic chat model (``claude-sonnet-4-20250514``,
    ``claude-3-5-sonnet-20241022``, ``claude-3-5-haiku-20241022``, etc.).

    If the API call fails or returns unparseable content, ``generate()``
    returns an empty string so the caller falls back to rule-based selection.

    Parameters
    ----------
    api_key:
        Anthropic API key.  Defaults to ``ANTHROPIC_API_KEY`` env var.
    model:
        Model name (default: ``claude-sonnet-4-20250514`` — fast and capable
        for action selection).
    temperature:
        Sampling temperature (default 0.2 — low for deterministic outputs).
    max_tokens:
        Max tokens in the response (default 1024).
    timeout:
        HTTP request timeout in seconds (default 30).
    base_url:
        Optional base URL for custom / compatible endpoints.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "claude-sonnet-4-20250514",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: int = 30,
        base_url: str | None = None,
        max_retries: int = 3,
        rate_limiter: RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        super().__init__(model=model)
        from anthropic import Anthropic

        key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            raise ValueError(
                "ANTHROPIC_API_KEY not set. Export it or pass api_key= to the constructor."
            )

        kwargs: dict[str, Any] = {"api_key": key, "timeout": timeout}
        if base_url:
            kwargs["base_url"] = base_url

        self._client = Anthropic(**kwargs)
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._max_retries = max_retries
        self._rate_limiter = rate_limiter or _DEFAULT_RATE_LIMITER
        self._circuit_breaker = circuit_breaker
        self.call_count = 0
        self.last_prompt = ""
        self.last_raw_response: str = ""
        self.retry_count = 0
        self.total_retry_delay: float = 0.0
        self.last_rate_limit_hit: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the Anthropic model and return the response text.

        Retries on transient errors (429, 503) with exponential backoff
        up to ``self._max_retries`` attempts.  Returns an empty string
        on ultimate failure so the caller can fall back to rule-based
        selection (see ``_select_with_llm``).
        """
        self.call_count += 1
        self.last_prompt = prompt

        messages = [
            {"role": "user", "content": prompt},
        ]

        def _do_call() -> str:
            response = self._client.messages.create(
                model=self.model,
                messages=messages,
                system=DEFAULT_SYSTEM_PROMPT,
                max_tokens=self._max_tokens,
                temperature=self._temperature,
                timeout=self._timeout,
            )

            content = response.content[0].text if response.content else ""
            self.last_raw_response = content

            # Validate it's parseable JSON before returning
            if content.strip():
                json.loads(content)  # validate
                return content

            return ""

        # Wrap with circuit breaker if configured
        if self._circuit_breaker is not None:
            def _cb_wrapped() -> str:
                return self._circuit_breaker.call(_do_call, fallback="")
            api_call: Callable[[], str] = _cb_wrapped
        else:
            api_call = _do_call

        result, retries, delay = _call_with_retry(
            api_call,
            max_retries=self._max_retries,
            rate_limiter=self._rate_limiter,
        )

        self.retry_count += retries
        self.total_retry_delay += delay
        if retries > 0:
            self.last_rate_limit_hit = time.time()

        return result


# ---------------------------------------------------------------------------
# Google / Gemini provider
# ---------------------------------------------------------------------------


class GoogleProvider(LLMProvider):
    """LLM provider backed by the Google Gemini API (``google-genai`` SDK).

    Reads ``GEMINI_API_KEY`` from the environment by default but also accepts
    an explicit *api_key* argument.

    The model can be any Gemini model (``gemini-2.0-flash``, ``gemini-2.0-flash-lite``,
    ``gemini-1.5-pro``, etc.).

    For proxy/custom endpoints, pass *base_url* or set the ``GEMINI_BASE_URL``
    environment variable.  Both flow through to ``genai.Client(http_options=...)``.

    Parameters
    ----------
    api_key:
        Gemini API key.  Defaults to ``GEMINI_API_KEY`` env var.
    model:
        Model name (default: ``gemini-2.0-flash`` — fast and capable for
        action selection).
    temperature:
        Sampling temperature (default 0.2).
    max_tokens:
        Max output tokens in the response (default 1024).
    timeout:
        HTTP request timeout in seconds (default 30).
    base_url:
        Optional base URL for custom / compatible endpoints.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "gemini-2.0-flash",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: int = 30,
        base_url: str | None = None,
        max_retries: int = 3,
        rate_limiter: RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        super().__init__(model=model)
        from google import genai

        key = api_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            raise ValueError(
                "GEMINI_API_KEY not set. Export it or pass api_key= to the constructor."
            )

        http_options: dict[str, Any] = {"timeout": timeout}
        if base_url or os.environ.get("GEMINI_BASE_URL"):
            http_options["base_url"] = base_url or os.environ["GEMINI_BASE_URL"]

        self._client = genai.Client(api_key=key, http_options=http_options)
        self._temperature = temperature
        self._max_tokens = max_tokens
        self._timeout = timeout
        self._max_retries = max_retries
        self._rate_limiter = rate_limiter or _DEFAULT_RATE_LIMITER
        self._circuit_breaker = circuit_breaker
        self.call_count = 0
        self.last_prompt = ""
        self.last_raw_response: str = ""
        self.retry_count = 0
        self.total_retry_delay: float = 0.0
        self.last_rate_limit_hit: float = 0.0

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the Gemini model and return the response text.

        Retries on transient errors (429, 503) with exponential backoff
        up to ``self._max_retries`` attempts.  Returns an empty string
        on ultimate failure so the caller can fall back to rule-based
        selection (see ``_select_with_llm``).
        """
        self.call_count += 1
        self.last_prompt = prompt

        def _do_call() -> str:
            from google.genai import types

            response = self._client.models.generate_content(
                model=self.model,
                contents=prompt,
                config=types.GenerateContentConfig(
                    system_instruction=DEFAULT_SYSTEM_PROMPT,
                    temperature=self._temperature,
                    max_output_tokens=self._max_tokens,
                ),
            )

            content = response.text or ""
            self.last_raw_response = content

            # Validate it's parseable JSON before returning
            if content.strip():
                json.loads(content)  # validate
                return content

            return ""

        # Wrap with circuit breaker if configured
        if self._circuit_breaker is not None:
            def _cb_wrapped() -> str:
                return self._circuit_breaker.call(_do_call, fallback="")
            api_call: Callable[[], str] = _cb_wrapped
        else:
            api_call = _do_call

        result, retries, delay = _call_with_retry(
            api_call,
            max_retries=self._max_retries,
            rate_limiter=self._rate_limiter,
        )

        self.retry_count += retries
        self.total_retry_delay += delay
        if retries > 0:
            self.last_rate_limit_hit = time.time()

        return result


# ---------------------------------------------------------------------------
# OpenRouter provider (OpenAI-compatible, via OpenRouter's unified API)
# ---------------------------------------------------------------------------


class OpenRouterProvider(OpenAIProvider):
    """LLM provider backed by OpenRouter's unified API endpoint.

    OpenRouter provides a unified OpenAI-compatible API for many LLM
    providers.  This class wraps ``OpenAIProvider`` with OpenRouter-
    specific defaults.

    Reads ``OPENROUTER_API_KEY`` from the environment by default.
    The default model is a free-tier model on OpenRouter.

    Parameters
    ----------
    api_key:
        OpenRouter API key.  Defaults to ``OPENROUTER_API_KEY`` env var.
    model:
        Model ID on OpenRouter (default: ``meta-llama/llama-3.2-3b-instruct:free``).
        See https://openrouter.ai/models for available models.
    temperature:
        Sampling temperature (default 0.2).
    max_tokens:
        Max tokens in the response (default 1024).
    timeout:
        HTTP request timeout in seconds (default 30).
    max_retries:
        Max retries on transient errors (default 3).
    rate_limiter:
        Optional ``RateLimiter`` instance.
    circuit_breaker:
        Optional ``CircuitBreaker`` instance.
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str = "meta-llama/llama-3.2-3b-instruct:free",
        temperature: float = 0.2,
        max_tokens: int = 1024,
        timeout: int = 30,
        max_retries: int = 3,
        rate_limiter: RateLimiter | None = None,
        circuit_breaker: CircuitBreaker | None = None,
    ) -> None:
        key = api_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            raise ValueError(
                "OPENROUTER_API_KEY not set. Export it or pass api_key= to the constructor."
            )

        super().__init__(
            api_key=key,
            model=model,
            temperature=temperature,
            max_tokens=max_tokens,
            timeout=timeout,
            base_url="https://openrouter.ai/api/v1",
            max_retries=max_retries,
            rate_limiter=rate_limiter,
            circuit_breaker=circuit_breaker,
        )


# ---------------------------------------------------------------------------
# Factory helpers
# ---------------------------------------------------------------------------


def create_llm_provider(
    provider_type: str = "openai",
    model: str = "gpt-4o-mini",
    **kwargs: Any,
) -> LLMProvider:
    """Create an LLM provider by type name.

    This is a lightweight factory that maps string names to provider classes.
    Useful for config-driven creation (e.g. from YAML specs or CLI flags).

    Parameters
    ----------
    provider_type:
        One of ``"openai"`` (default) or ``"mock"`` (for testing).
    model:
        Model name passed to the provider constructor.
    **kwargs:
        Additional keyword arguments forwarded to the provider.

    Returns
    -------
    A configured ``LLMProvider`` instance.
    """
    if provider_type == "openai":
        return OpenAIProvider(model=model, **kwargs)
    if provider_type == "anthropic":
        return AnthropicProvider(model=model, **kwargs)
    if provider_type in ("google", "gemini"):
        return GoogleProvider(model=model, **kwargs)
    if provider_type == "openrouter":
        return OpenRouterProvider(model=model, **kwargs)
    if provider_type in ("mock", "test"):
        from gatekeeper_eos_v6.agentic import MockLLMProvider

        return MockLLMProvider(model=model, default_action=kwargs.get("default_action"))
    raise ValueError(f"Unknown provider_type: {provider_type!r}. Supported: openai, anthropic, google, openrouter, mock")
