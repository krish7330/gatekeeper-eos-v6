# gatekeeper-eos-v6

> **Generate production-ready multi-agent AI systems from a single YAML spec.**

[![Tests](https://img.shields.io/badge/tests-105%20passed-brightgreen)](tests/)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](pyproject.toml)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Version](https://img.shields.io/badge/version-1.0.0-blue)](pyproject.toml)

Gatekeeper EOS v6 is a **code-generation factory** for multi-agent AI systems. Define your agents and orchestration pattern in YAML — the factory renders a complete, runnable Python project using the OpenAI Agents SDK or LangGraph.

---

## Features

- **2 targets** — `openai` (Agents SDK) and `langgraph`
- **10 orchestration patterns** — chain, handoffs, broadcast, debate, consensus, reflection, router_manager, supervisor_workers, agents_as_tools, planner_executor
- **21 ready-made specs** — covering healthcare, legal, security, content, research, and more
- **Batch generation** — regenerate all systems with one command via `specs/batch.yaml`
- **OpenAI-compatible** — works with any provider (Groq, OpenRouter, etc.) via `OPENAI_BASE_URL`
- **105 tests** — full generation + validation coverage

---

## Quick Start

```bash
git clone https://github.com/krishanumala/gatekeeper-eos-v6
cd gatekeeper-eos-v6
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

python -m gatekeeper_eos_v6 specs/data-pipeline-chain.yaml

cd generated/data-pipeline-chain
export OPENAI_API_KEY=your_groq_key
export OPENAI_BASE_URL=https://api.groq.com/openai/v1
export OPENAI_MODEL=llama-3.3-70b-versatile
python main.py

python -m gatekeeper_eos_v6 specs/batch.yaml

systems:
- name: my-pipeline
  description: A custom data pipeline
  target: openai
  pattern: chain
  model: gpt-4o
  example_input: Analyze this dataset.
  agents:
  - name: extractor
    instructions: You are a data extractor. Parse the input and return structured data.
  - name: analyzer
    instructions: You are an analyst. Identify trends and insights from the extracted data.
  - name: formatter
    instructions: You are a formatter. Produce a clean executive report from the analysis.

