#!/usr/bin/env python3
"""E2E smoke test for all production LLM providers.

Tests that each provider can be instantiated and makes a real API call.
Set the following environment variables to run:
  - OPENAI_API_KEY           (or passed via --openai-key)
  - ANTHROPIC_API_KEY        (or passed via --anthropic-key)
  - GEMINI_API_KEY           (or passed via --gemini-key)
  - GROQ_API_KEY             (or passed via --groq-key; also needs OPENAI_BASE_URL)
  - OPENROUTER_API_KEY       (or passed via --openrouter-key)

Usage:
    # Test all providers (keys must be set in env)
    python scripts/smoke_test_providers.py

    # Test specific providers only
    python scripts/smoke_test_providers.py --openai-only

    # Pass keys inline (overrides env)
    python scripts/smoke_test_providers.py \\
        --openai-key sk-... \\
        --openrouter-key sk-or-...

Each test sends a simple JSON-format prompt and validates the response
contains parseable tool/command/arguments JSON.
"""

import argparse
import json
import os
import sys
import time
from typing import Any

# Add project root to path
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from gatekeeper_eos_v6.providers import (
    OpenAIProvider,
    AnthropicProvider,
    GoogleProvider,
    OpenRouterProvider,
)

# ---------------------------------------------------------------------------
# Prompt
# ---------------------------------------------------------------------------

TEST_PROMPT = (
    'You are a pentest agent. Return ONLY valid JSON with keys: tool, command, arguments, target, reasoning. '
    'No explanation, no markdown, no backticks. '
    'Example: {"tool": "nmap", "command": "discover", "arguments": {"target": "10.0.0.1"}, '
    '"target": "10.0.0.1", "reasoning": "Initial recon"} '
    'Respond with JSON now.'
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def try_parse_json(raw: str) -> dict[str, Any] | None:
    """Try to parse raw response as JSON, stripping markdown fences if present."""
    text = raw.strip()
    # Strip ```json ... ``` fences
    if text.startswith("```"):
        lines = text.splitlines()
        if lines[0].strip().startswith("```"):
            lines = lines[1:]
        if lines and lines[-1].strip().startswith("```"):
            lines = lines[:-1]
        text = "\n".join(lines).strip()
    try:
        data = json.loads(text)
        if isinstance(data, dict) and "tool" in data and "command" in data:
            return data
        return None
    except (json.JSONDecodeError, TypeError):
        return None


def smoke_test(
    name: str,
    provider: Any,
    model: str,
    timeout: int = 30,
) -> tuple[bool, str]:
    """Run a single smoke test returning (passed, detail)."""
    print(f"  🔄 {name} ({model})...", end=" ", flush=True)
    start = time.monotonic()
    try:
        raw = provider.generate(TEST_PROMPT)
        elapsed = time.monotonic() - start

        if not raw:
            print(f"❌ EMPTY ({elapsed:.1f}s)")
            return False, f"Empty response after {elapsed:.1f}s"

        parsed = try_parse_json(raw)
        if parsed is None:
            preview = raw[:120].replace("\n", " ")
            print(f"❌ NOT JSON ({elapsed:.1f}s)")
            return False, f"Response not valid JSON: {preview}"

        print(f"✅ ({elapsed:.1f}s)")
        return True, f"tool={parsed['tool']}, command={parsed['command']}"
    except Exception as e:
        elapsed = time.monotonic() - start
        print(f"❌ ERROR ({elapsed:.1f}s): {e}")
        return False, str(e)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(description="Provider E2E smoke tests")
    parser.add_argument("--openai-key", help="OpenAI API key")
    parser.add_argument("--anthropic-key", help="Anthropic API key")
    parser.add_argument("--gemini-key", help="Gemini API key")
    parser.add_argument("--groq-key", help="Groq API key")
    parser.add_argument("--openrouter-key", help="OpenRouter API key")
    parser.add_argument("--openrouter-only", action="store_true", help="Test only OpenRouter")
    parser.add_argument("--all", action="store_true", default=True, help="Test all providers (default)")
    parser.add_argument("--openai-only", action="store_true", help="Test only OpenAI")
    parser.add_argument("--anthropic-only", action="store_true", help="Test only Anthropic")
    parser.add_argument("--gemini-only", action="store_true", help="Test only Gemini")
    parser.add_argument("--groq-only", action="store_true", help="Test only Groq")
    parser.add_argument("--timeout", type=int, default=30, help="Per-provider timeout in seconds")
    args = parser.parse_args()

    # Determine which providers to test
    if args.openai_only:
        providers_to_test = ["openai"]
    elif args.anthropic_only:
        providers_to_test = ["anthropic"]
    elif args.gemini_only:
        providers_to_test = ["gemini"]
    el    if args.groq_only:
        providers_to_test = ["groq"]
    elif args.openrouter_only:
        providers_to_test = ["openrouter"]
    else:
        providers_to_test = ["openai", "anthropic", "gemini", "groq", "openrouter"]

    results: list[tuple[str, bool, str]] = []

    print(f"\n{'='*60}")
    print(f"  LLM Provider Smoke Tests")
    print(f"{'='*60}\n")

    # ---- OpenAI ----
    if "openai" in providers_to_test:
        print("[1/4] OpenAI (GPT-4o Mini)")
        key = args.openai_key or os.environ.get("OPENAI_API_KEY")
        if not key:
            print("  ⏭  SKIP (no OPENAI_API_KEY)\n")
            results.append(("openai", False, "No key"))
        else:
            try:
                provider = OpenAIProvider(
                    model="gpt-4o-mini",
                    temperature=0.1,
                    max_tokens=512,
                    timeout=args.timeout,
                )
                ok, detail = smoke_test("OpenAI", provider, "gpt-4o-mini", args.timeout)
                results.append(("openai", ok, detail))
            except Exception as e:
                print(f"  ❌ INIT ERROR: {e}\n")
                results.append(("openai", False, str(e)))
        print()

    # ---- Anthropic ----
    if "anthropic" in providers_to_test:
        print("[2/4] Anthropic (Claude Sonnet 4)")
        key = args.anthropic_key or os.environ.get("ANTHROPIC_API_KEY")
        if not key:
            print("  ⏭  SKIP (no ANTHROPIC_API_KEY)\n")
            results.append(("anthropic", False, "No key"))
        else:
            try:
                provider = AnthropicProvider(
                    model="claude-sonnet-4-20250514",
                    temperature=0.1,
                    max_tokens=512,
                    timeout=args.timeout,
                )
                ok, detail = smoke_test("Anthropic", provider, "claude-sonnet-4-20250514", args.timeout)
                results.append(("anthropic", ok, detail))
            except Exception as e:
                print(f"  ❌ INIT ERROR: {e}\n")
                results.append(("anthropic", False, str(e)))
        print()

    # ---- Gemini ----
    if "gemini" in providers_to_test:
        print("[3/4] Google (Gemini 2.0 Flash)")
        key = args.gemini_key or os.environ.get("GEMINI_API_KEY")
        if not key:
            print("  ⏭  SKIP (no GEMINI_API_KEY)\n")
            results.append(("gemini", False, "No key"))
        else:
            try:
                provider = GoogleProvider(
                    model="gemini-2.0-flash",
                    temperature=0.1,
                    max_tokens=512,
                    timeout=args.timeout,
                )
                ok, detail = smoke_test("Gemini", provider, "gemini-2.0-flash", args.timeout)
                results.append(("gemini", ok, detail))
            except Exception as e:
                print(f"  ❌ INIT ERROR: {e}\n")
                results.append(("gemini", False, str(e)))
        print()

    # ---- Groq (via OpenAI-compatible endpoint) ----
    if "groq" in providers_to_test:
        print("[4/4] Groq (Llama 3.3 70B via OpenAI endpoint)")
        key = args.groq_key or os.environ.get("GROQ_API_KEY")
        if not key:
            print("  ⏭  SKIP (no GROQ_API_KEY)\n")
            results.append(("groq", False, "No key"))
        else:
            try:
                provider = OpenAIProvider(
                    model="llama-3.3-70b-versatile",
                    api_key=key,
                    base_url="https://api.groq.com/openai/v1",
                    temperature=0.1,
                    max_tokens=512,
                    timeout=args.timeout,
                )
                ok, detail = smoke_test("Groq", provider, "llama-3.3-70b-versatile", args.timeout)
                results.append(("groq", ok, detail))
            except Exception as e:
                print(f"  ❌ INIT ERROR: {e}\n")
                results.append(("groq", False, str(e)))
        print()

    # ---- OpenRouter ----
    if "openrouter" in providers_to_test:
        print("[5/5] OpenRouter (OpenRouter Free Models)")
        key = args.openrouter_key or os.environ.get("OPENROUTER_API_KEY")
        if not key:
            print("  ⏭  SKIP (no OPENROUTER_API_KEY)\n")
            results.append(("openrouter", False, "No key"))
        else:
            try:
                provider = OpenRouterProvider(
                    model="meta-llama/llama-3.2-3b-instruct:free",
                    temperature=0.1,
                    max_tokens=512,
                    timeout=args.timeout,
                )
                ok, detail = smoke_test("OpenRouter", provider, "meta-llama/llama-3.2-3b-instruct:free", args.timeout)
                results.append(("openrouter", ok, detail))
            except Exception as e:
                print(f"  ❌ INIT ERROR: {e}\n")
                results.append(("openrouter", False, str(e)))
        print()

    # ---- Summary ----
    print(f"{'='*60}")
    print(f"  Summary")
    print(f"{'='*60}")
    passed = sum(1 for _, ok, _ in results if ok)
    failed = sum(1 for _, ok, _ in results if not ok)
    for name, ok, detail in results:
        status = "✅ PASS" if ok else "❌ FAIL"
        print(f"  {status} {name}: {detail}")
    print(f"\n  {passed} passed, {failed} failed")
    print(f"{'='*60}\n")

    sys.exit(0 if failed == 0 else 1)


if __name__ == "__main__":
    main()
