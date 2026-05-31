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
"""

from __future__ import annotations

import json
import os
import time
from typing import Any

# Local imports — the LLMProvider ABC lives in agentic.py
from gatekeeper_eos_v6.agentic import LLMProvider


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
        self.call_count = 0
        self.last_prompt = ""
        self.last_raw_response: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the OpenAI model and return the response text.

        Returns an empty string on any error so the caller can fall back
        to rule-based selection (see ``_select_with_llm``).
        """
        self.call_count += 1
        self.last_prompt = prompt

        messages = [
            {"role": "system", "content": DEFAULT_SYSTEM_PROMPT},
            {"role": "user", "content": prompt},
        ]

        try:
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

        except Exception:
            # Any error → fall back to rules
            return ""


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
        self.call_count = 0
        self.last_prompt = ""
        self.last_raw_response: str = ""

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(self, prompt: str) -> str:
        """Send *prompt* to the Anthropic model and return the response text.

        Returns an empty string on any error so the caller can fall back
        to rule-based selection (see ``_select_with_llm``).
        """
        self.call_count += 1
        self.last_prompt = prompt

        messages = [
            {"role": "user", "content": prompt},
        ]

        try:
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

        except Exception:
            # Any error → fall back to rules
            return ""


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
    if provider_type in ("mock", "test"):
        from gatekeeper_eos_v6.agentic import MockLLMProvider

        return MockLLMProvider(model=model, default_action=kwargs.get("default_action"))
    raise ValueError(f"Unknown provider_type: {provider_type!r}. Supported: openai, anthropic, mock")
