"""Subscription-based model authentication.

Strix normally authenticates to a model provider with an API key. This package
adds a second path: signing in with a model *subscription* (currently ChatGPT
Plus/Pro, via the OpenAI Codex OAuth flow) and using that for inference instead
of metered API billing.

- :mod:`strix.auth.store` — the on-disk credential store
  (``~/.strix/subscription-auth.json``, ``0600``), one record per provider.
- :mod:`strix.auth.codex` — the ChatGPT (Codex) OAuth flow, token refresh, and
  the OpenAI client that routes inference through the ChatGPT backend.
"""
