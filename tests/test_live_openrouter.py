"""Live smoke test for OpenRouterProvider.

Requires OPENROUTER_API_KEY to be set in the environment.
Skips automatically when the key is absent — safe to run in any CI suite.
"""

from __future__ import annotations

import json
import os

import pytest

from gatekeeper_eos_v6.providers import OpenRouterProvider, create_llm_provider

pytestmark = pytest.mark.skipif(
    not os.environ.get("OPENROUTER_API_KEY"),
    reason="OPENROUTER_API_KEY not set — live OpenRouter test skipped",
)


class TestLiveOpenRouterSmoke:
    """End-to-end smoke tests against the real OpenRouter API.

    Uses the free Llama 3.2 3B model so there is zero cost.
    """

    FREE_MODEL = "meta-llama/llama-3.2-3b-instruct:free"

    def test_live_initialization(self):
        """OpenRouterProvider initialises with the real API key and a live model."""
        provider = OpenRouterProvider(model=self.FREE_MODEL)
        assert provider.model == self.FREE_MODEL
        assert provider._client is not None

    def test_live_generate_returns_valid_json(self):
        """A real prompt returns parseable JSON with expected keys."""
        provider = OpenRouterProvider(model=self.FREE_MODEL, max_retries=1)
        prompt = (
            'Respond with valid JSON only: {"tool": "nmap", "command": "scan", '
            '"arguments": {"target": "10.0.0.1"}, "target": "10.0.0.1", '
            '"reasoning": "Quick test"}'
        )
        raw = provider.generate(prompt)
        assert raw, "Expected non-empty response from live API"

        data = json.loads(raw)
        assert "tool" in data, f"Missing 'tool' key in: {data}"
        assert "command" in data, f"Missing 'command' key in: {data}"
        assert provider.call_count == 1
        assert provider.last_prompt == prompt

    def test_live_generate_with_custom_model(self):
        """A different free model (Phi-3) also returns valid JSON."""
        provider = OpenRouterProvider(
            model="microsoft/phi-3-mini-4k-instruct:free",
            max_retries=1,
        )
        raw = provider.generate('{"tool": "nmap", "command": "discover"}')
        assert raw, "Expected non-empty response from Phi-3 via OpenRouter"
        data = json.loads(raw)
        assert "tool" in data

    def test_live_create_llm_provider_factory(self):
        """Factory function returns a working OpenRouterProvider."""
        provider = create_llm_provider("openrouter", model=self.FREE_MODEL)
        assert isinstance(provider, OpenRouterProvider)
        raw = provider.generate('{"tool": "test", "command": "run"}')
        assert raw
        data = json.loads(raw)
        assert "tool" in data

    def test_live_with_rate_limiter(self):
        """OpenRouterProvider works with a RateLimiter attached."""
        from gatekeeper_eos_v6.providers import RateLimiter

        limiter = RateLimiter(capacity=10, tokens_per_second=5.0)
        provider = OpenRouterProvider(
            model=self.FREE_MODEL,
            rate_limiter=limiter,
            max_retries=1,
        )
        raw = provider.generate('{"tool": "nmap", "command": "recon"}')
        assert raw
        data = json.loads(raw)
        assert "tool" in data

    def test_live_with_circuit_breaker(self):
        """OpenRouterProvider works with a CircuitBreaker attached (CLOSED state)."""
        from gatekeeper_eos_v6.providers import CircuitBreaker

        cb = CircuitBreaker(failure_threshold=10, recovery_timeout=999)
        provider = OpenRouterProvider(
            model=self.FREE_MODEL,
            circuit_breaker=cb,
            max_retries=1,
        )
        raw = provider.generate('{"tool": "nmap", "command": "recon"}')
        assert raw
        data = json.loads(raw)
        assert "tool" in data
        # Circuit should still be closed after a successful call
        assert cb.open is False
