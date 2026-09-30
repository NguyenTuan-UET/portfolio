"""
NeMo Guardrails wiring for the chatbot's content rails (config in nemo_config/).

The checks themselves are the rules in guardrails.py, registered as NeMo actions, so the rails
run in a few milliseconds and never call an LLM. NeMo is async; the HTTP server is threaded, so
all rail calls go through one event loop on a background thread.
"""
from __future__ import annotations

import asyncio
import logging
import threading
from pathlib import Path

from nemoguardrails import LLMRails, RailsConfig
from nemoguardrails.actions import action
from nemoguardrails.actions.actions import ActionResult

from guardrails import MAX_INPUT_CHARS, clean_text, detect_injection, harmful_request, legal_content, restricted_topic

CONFIG_DIR = Path(__file__).resolve().parent / "nemo_config"
logging.getLogger("nemoguardrails").setLevel(logging.WARNING)


@action(name="check_input")
async def check_input(text: str) -> str | None:
    """Return the block reason for a user message (a BLOCK_MESSAGES key in app.py), or None."""
    if len(text) > MAX_INPUT_CHARS:
        return "too_long"
    if detect_injection(text) == "BLOCK":
        return "injection"
    if harmful_request(text) == "BLOCK":
        return "harmful_topic"
    return restricted_topic(text)


@action(name="check_output")
async def check_output(text: str) -> str | None:
    """Return the legal-content evidence found in a reply, or None."""
    return legal_content(text)


@action(name="clean_output")
async def clean_output(text: str, context: dict | None = None) -> ActionResult:
    issues: list[str] = []
    cleaned = clean_text(text, set((context or {}).get("allowed_urls") or []), issues)
    return ActionResult(return_value=cleaned, context_updates={"output_issues": issues})


class ContentRails:
    def __init__(self) -> None:
        self._rails = LLMRails(RailsConfig.from_path(str(CONFIG_DIR)))
        for fn in (check_input, check_output, clean_output):
            self._rails.register_action(fn)
        self._loop = asyncio.new_event_loop()
        threading.Thread(target=self._loop.run_forever, name="nemo-rails", daemon=True).start()

    def _run(self, messages: list[dict], rail: str, output_vars: list[str]) -> tuple[str, dict]:
        options = {"rails": [rail], "output_vars": output_vars}
        future = asyncio.run_coroutine_threadsafe(
            self._rails.generate_async(messages=messages, options=options), self._loop)
        result = future.result(timeout=10)
        return result.response[0]["content"], result.output_data or {}

    def check_input(self, message: str) -> str | None:
        """Input rail: the block reason, or None when the message may go to the model."""
        _, data = self._run([{"role": "user", "content": message}], "input", ["input_block"])
        return data.get("input_block") or None

    def check_output(self, reply: str, allowed_urls: set[str]) -> tuple[str | None, str, list[str]]:
        """Output rail: (legal evidence or None, cleaned reply, issues fixed)."""
        text, data = self._run([
            {"role": "context", "content": {"allowed_urls": sorted(allowed_urls)}},
            {"role": "user", "content": "."},
            {"role": "assistant", "content": reply},
        ], "output", ["output_block", "output_issues"])
        if data.get("output_block"):
            return data["output_block"], "", []
        return None, text, data.get("output_issues") or []
