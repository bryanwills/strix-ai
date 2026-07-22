"""Tests for the `strix auth` CLI: subcommand routing and provider naming."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

import pytest

from strix.auth import codex, store
from strix.interface import auth_cli


if TYPE_CHECKING:
    from pathlib import Path


@pytest.fixture(autouse=True)
def _tmp_store(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(store, "AUTH_PATH", tmp_path / "home" / ".strix" / "subscription-auth.json")


def test_login_provider_is_chatgpt() -> None:
    assert auth_cli.LOGIN_PROVIDER == "chatgpt"
    assert codex.PROVIDER in auth_cli._ACCEPTED_PROVIDERS
    assert "chatgpt" in auth_cli._ACCEPTED_PROVIDERS


def test_unknown_subcommand_returns_usage_error() -> None:
    assert auth_cli.run_auth(["bogus"]) == 2


def test_help_returns_zero() -> None:
    assert auth_cli.run_auth(["--help"]) == 0


def test_status_not_signed_in() -> None:
    assert auth_cli.run_auth(["status"]) == 1


def test_login_rejects_unsupported_provider(monkeypatch: pytest.MonkeyPatch) -> None:
    def _should_not_run(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        msg = "OAuth flow must not start for an unsupported provider"
        raise AssertionError(msg)

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _should_not_run)
    assert auth_cli.run_auth(["login", "gemini"]) == 2


@pytest.mark.parametrize("provider", ["chatgpt", "codex", "ChatGPT"])
def test_login_accepts_provider_aliases(provider: str, monkeypatch: pytest.MonkeyPatch) -> None:
    reached = {"flow": False}

    def _fake_flow(*_args: Any, **_kwargs: Any) -> dict[str, Any]:
        reached["flow"] = True
        return {
            "type": "oauth",
            "provider": "codex",
            "access": "a",
            "refresh": "r",
            "account_id": "acct",
            "expires_at": 0,
        }

    monkeypatch.setattr(auth_cli, "_run_oauth_flow", _fake_flow)
    monkeypatch.setattr(codex, "save_record", lambda _record: None)
    monkeypatch.setattr(auth_cli, "_persist_subscription_config", lambda _model: None)

    assert auth_cli.run_auth(["login", provider]) == 0
    assert reached["flow"] is True
