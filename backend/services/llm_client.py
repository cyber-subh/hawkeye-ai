"""
LLM client wrapper around the Anthropic API.

Design goal: the rest of the app should work even if no API key is
configured (e.g. someone clones the repo and runs it before setting up
billing) - it just falls back to a template-based response instead of
crashing. This also makes the project easy to demo offline.

Set the ANTHROPIC_API_KEY environment variable to enable real LLM output.
"""

import os

_API_KEY = os.environ.get("ANTHROPIC_API_KEY")
_client = None
_ENABLED = False

if _API_KEY:
    try:
        import anthropic
        _client = anthropic.Anthropic(api_key=_API_KEY)
        _ENABLED = True
    except ImportError:
        # anthropic package not installed - fall back gracefully
        _ENABLED = False


def llm_enabled() -> bool:
    return _ENABLED


def ask_llm(prompt: str, max_tokens: int = 600) -> str:
    """
    Send a prompt to Claude and return the text response.
    Raises RuntimeError if the LLM is not configured - callers should
    check llm_enabled() first and use a fallback in that case.
    """
    if not _ENABLED:
        raise RuntimeError("LLM not configured - set ANTHROPIC_API_KEY to enable this.")

    response = _client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=max_tokens,
        messages=[{"role": "user", "content": prompt}],
    )
    return "".join(block.text for block in response.content if block.type == "text")
