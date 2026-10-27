from __future__ import annotations

from cairn.redact import key_names_from_env, redact_text, redact_url


def test_redacts_common_secret_shapes():
    text = (
        "Authorization: Bearer abcdefghijklmnop\n"
        "api_key=super-secret-value\n"
        "Set-Cookie: session=supersecretvalue; Path=/\n"
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "token: ghp_abcdefghijklmnopqrstuvwxyz0123456789\n"
    )
    cleaned = redact_text(text, limit=4000)
    assert "supersecret" not in cleaned
    assert "super-secret-value" not in cleaned
    assert "AKIAIOSFODNN7EXAMPLE" not in cleaned
    assert "ghp_abcdefghijklmnopqrstuvwxyz0123456789" not in cleaned
    assert "[REDACTED" in cleaned
    assert "api_key=" in cleaned


def test_redacts_sensitive_query_values_but_keeps_other_params():
    url = "https://example.com/callback?access_token=abc123&state=xyz&sig=deadbeef"
    cleaned = redact_url(url)
    assert "abc123" not in cleaned
    assert "deadbeef" not in cleaned
    assert "state=xyz" in cleaned
    assert cleaned.startswith("https://example.com/callback?")


def test_truncation_is_explicit():
    cleaned = redact_text("x" * 100, limit=20)
    assert cleaned.startswith("x" * 20)
    assert "truncated" in cleaned


def test_environment_keys_are_useful_for_evidence_without_values():
    names = key_names_from_env(
        "# comment\nDATABASE_URL=postgres://u:p@db/app\nSECRET_KEY='value'\ninvalid line\n"
    )
    assert names == ["DATABASE_URL", "SECRET_KEY"]
