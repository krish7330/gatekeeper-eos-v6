#!/usr/bin/env python3
"""Perplexity AI API client — research-grade LLM with live web search.

Uses the OpenAI-compatible chat completions endpoint at
``https://api.perplexity.ai/v1/chat/completions`` so it can be called
with a standard HTTP POST — no heavyweight SDK required.

Environment variables
─────────────────────
    PERPLEXITY_API_KEY      (required)
    PERPLEXITY_MODEL         (default: sonar-pro)
    PERPLEXITY_MAX_TOKENS   (default: 4096)

Response structure
──────────────────
Returns a ``PerplexityResponse`` dataclass with:
    - content:     The LLM-generated answer text.
    - citations:   List of source URLs.
    - model:       Model name used.
    - usage:       Token counts and cost breakdown.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

import requests  # type: ignore[import-untyped]

# ── Constants ────────────────────────────────────────────────────────────────

BASE_URL = "https://api.perplexity.ai/v1/chat/completions"

DEFAULT_MODEL = "sonar-pro"
DEFAULT_MAX_TOKENS = 4096
DEFAULT_TIMEOUT = 60  # seconds

# ── Data classes ─────────────────────────────────────────────────────────────


@dataclass
class Usage:
    """Token-usage detail returned by the Perplexity API."""

    prompt_tokens: int = 0
    completion_tokens: int = 0
    total_tokens: int = 0
    input_tokens_cost: float = 0.0
    output_tokens_cost: float = 0.0
    total_cost: float = 0.0

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> Usage:
        return cls(
            prompt_tokens=data.get("prompt_tokens", 0),
            completion_tokens=data.get("completion_tokens", 0),
            total_tokens=data.get("total_tokens", 0),
            input_tokens_cost=data.get("input_tokens_cost", 0.0),
            output_tokens_cost=data.get("output_tokens_cost", 0.0),
            total_cost=data.get("total_cost", 0.0),
        )


@dataclass
class PerplexityResponse:
    """Structured response from a Perplexity API call."""

    content: str
    citations: list[str] = field(default_factory=list)
    model: str = ""
    usage: Usage = field(default_factory=Usage)
    error: str | None = None
    raw: dict[str, Any] | None = None


# ── Client ───────────────────────────────────────────────────────────────────


class PerplexityClient:
    """Thin wrapper around the Perplexity chat completions endpoint.

    Usage
    ─────
        client = PerplexityClient()
        resp = client.chat("What is the latest on agentic AI workflows?")
        print(resp.content)
        for url in resp.citations:
            print(f"  → {url}")
    """

    def __init__(
        self,
        api_key: str | None = None,
        model: str | None = None,
        max_tokens: int | None = None,
        timeout: int = DEFAULT_TIMEOUT,
    ) -> None:
        self.api_key = api_key or os.environ.get("PERPLEXITY_API_KEY", "")
        if not self.api_key:
            raise ValueError(
                "PERPLEXITY_API_KEY not set. "
                "Export it or pass api_key= to the constructor."
            )

        self.model = model or os.environ.get("PERPLEXITY_MODEL", DEFAULT_MODEL)
        self.max_tokens = max_tokens or int(
            os.environ.get("PERPLEXITY_MAX_TOKENS", str(DEFAULT_MAX_TOKENS))
        )
        self.timeout = timeout
        self._session = requests.Session()
        self._session.headers.update(
            {
                "Authorization": f"Bearer {self.api_key}",
                "Content-Type": "application/json",
            }
        )

    # ── Public API ───────────────────────────────────────────────────────

    def chat(
        self,
        prompt: str,
        system_prompt: str | None = None,
        temperature: float = 0.3,
        max_tokens: int | None = None,
    ) -> PerplexityResponse:
        """Send a chat request and return a structured response.

        Parameters
        ----------
        prompt:
            The user message / question.
        system_prompt:
            Optional system-level instruction (defaults to a concise researcher
            persona).
        temperature:
            Sampling temperature (0.0 = deterministic, 1.0 = creative).
        max_tokens:
            Max tokens in the response (defaults to instance setting).
        """
        messages: list[dict[str, str]] = []
        messages.append(
            {
                "role": "system",
                "content": system_prompt
                or (
                    "You are a thorough research assistant. "
                    "Answer with well-sourced reasoning. "
                    "Cite sources when possible."
                ),
            }
        )
        messages.append({"role": "user", "content": prompt})

        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "temperature": temperature,
            "max_tokens": max_tokens or self.max_tokens,
        }

        try:
            resp = self._session.post(
                BASE_URL, json=payload, timeout=self.timeout
            )
            resp.raise_for_status()
            data = resp.json()
            return self._parse_response(data, self.model)
        except requests.exceptions.RequestException as exc:
            error_detail = str(exc)
            if hasattr(exc, "response") and exc.response is not None:
                try:
                    body = exc.response.json()
                    error_detail = body.get("error", {}).get(
                        "message", str(exc)
                    )
                except (ValueError, KeyError):
                    error_detail = (
                        f"HTTP {exc.response.status_code}: {exc.response.text[:300]}"
                    )
            return PerplexityResponse(
                content="", error=error_detail, model=self.model
            )

    def research(
        self,
        query: str,
        context: str | None = None,
        **kwargs: Any,
    ) -> PerplexityResponse:
        """Convenience: send a research query, optionally with file context.

        Parameters
        ----------
        query:
            The research question.
        context:
            Optional file contents, logs, or code to ground the query on.
        """
        prompt = query
        if context:
            prompt = (
                f"Here is context to ground your research on:\n\n"
                f"```\n{context[:8000]}\n```\n\n"
                f"---\n\n"
                f"Now answer the following, using the context above:\n\n{query}"
            )
        return self.chat(prompt, **kwargs)

    def analyze(
        self,
        content: str,
        analysis_goal: str = "Identify key findings, patterns, and actionable insights.",
        **kwargs: Any,
    ) -> PerplexityResponse:
        """Analyze file/output content with Perplexity.

        Parameters
        ----------
        content:
            The text content to analyze (logs, code, output, etc.).
        analysis_goal:
            What the analysis should focus on.
        """
        system = (
            "You are an expert analyst. Review the provided content and "
            f"{analysis_goal} "
            "Be specific, cite evidence from the content, and suggest improvements."
        )
        return self.chat(
            prompt=f"Analyze the following:\n\n```\n{content[:12000]}\n```",
            system_prompt=system,
            **kwargs,
        )

    # ── Response parsing ────────────────────────────────────────────────

    @staticmethod
    def _parse_response(
        data: dict[str, Any], model: str
    ) -> PerplexityResponse:
        choices = data.get("choices", [])
        content = ""
        if choices:
            content = choices[0].get("message", {}).get("content", "")

        citations: list[str] = data.get("citations", [])
        usage_raw = data.get("usage", {})
        usage = Usage.from_dict(usage_raw)

        return PerplexityResponse(
            content=content,
            citations=citations,
            model=model,
            usage=usage,
            raw=data,
        )


# ── File helpers ─────────────────────────────────────────────────────────────


def load_log(path: str | Path, max_chars: int = 12000) -> str:
    """Read a log file, truncated to *max_chars* for token-efficiency."""
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Log file not found: {path}")
    text = path.read_text(encoding="utf-8", errors="replace")
    if len(text) > max_chars:
        text = text[:max_chars] + "\n\n... [truncated]"
    return text


# ── CLI entry (lightweight; richer CLI in bridge.py) ─────────────────────────


def cli() -> int:
    """Minimal standalone CLI for quick queries::

        python -m gatekeeper_eos_v6.perplexity_client "your query"
    """
    if len(sys.argv) < 2:
        print("Usage: python -m gatekeeper_eos_v6.perplexity_client \"<query>\"", file=sys.stderr)
        return 1

    query = " ".join(sys.argv[1:])
    client = PerplexityClient()
    resp = client.chat(query)

    if resp.error:
        print(f"❌ Error: {resp.error}", file=sys.stderr)
        return 1

    print(resp.content)
    if resp.citations:
        print("\n── Sources ──")
        for url in resp.citations:
            print(f"  • {url}")
    if resp.usage.total_cost > 0:
        print(f"\n── Cost: ${resp.usage.total_cost:.6f} ──")
    return 0


if __name__ == "__main__":
    sys.exit(cli())
