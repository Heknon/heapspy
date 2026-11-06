from __future__ import annotations

import pytest

from heapspy_mcp.processes import describe_cmdline
from heapspy_mcp.system.redact import REDACTED, redact_args, redact_cmdline

R = REDACTED


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["app", "--password=hunter2"], ["app", f"--password={R}"]),
        (["app", "--db-password", "hunter2", "-v"], ["app", "--db-password", R, "-v"]),
        (["app", "--token", "abc"], ["app", "--token", R]),
        (["app", "--api-key=k1", "--apikey", "k2"], ["app", f"--api-key={R}", "--apikey", R]),
        (["app", "--client_secret=s"], ["app", f"--client_secret={R}"]),
        (
            ["env", "AWS_SECRET_ACCESS_KEY=xyz", "PATH=/bin"],
            ["env", f"AWS_SECRET_ACCESS_KEY={R}", "PATH=/bin"],
        ),
        (
            ["env", "STRIPE_KEY=sk_live_1", "GITHUB_TOKEN=ghp_1"],
            ["env", f"STRIPE_KEY={R}", f"GITHUB_TOKEN={R}"],
        ),
        (["env", "DB_PASSWORD=pw"], ["env", f"DB_PASSWORD={R}"]),
        (
            ["curl", "-H", "Authorization: Bearer eyJhbGci"],
            ["curl", "-H", f"Authorization: {R}"],
        ),
        (
            ["curl", "-H", "Authorization:", "Bearer", "eyJ"],
            ["curl", "-H", "Authorization:", "Bearer", R],
        ),
        (["curl", "-H", "X-Api-Key: abc"], ["curl", "-H", f"X-Api-Key: {R}"]),
        (
            ["psql", "postgres://admin:s3cret@db:5432/app"],
            ["psql", f"postgres://admin:{R}@db:5432/app"],
        ),
        (
            ["git", "clone", "https://ghp_abc@github.com/o/r"],
            ["git", "clone", f"https://{R}@github.com/o/r"],
        ),
        (
            ["fetch", "https://api.example.com/v1?user=bob&access_token=t0k&x=1"],
            ["fetch", f"https://api.example.com/v1?user=bob&access_token={R}&x=1"],
        ),
        # Things that must be left alone.
        (
            ["python", "-m", "gunicorn", "app:wsgi", "--workers", "4"],
            ["python", "-m", "gunicorn", "app:wsgi", "--workers", "4"],
        ),
        (
            ["app", "--author=me", "--passes=3", "--keyboard"],
            ["app", "--author=me", "--passes=3", "--keyboard"],
        ),
        (["ssh", "git@github.com"], ["ssh", "git@github.com"]),
    ],
)
def test_redact_args(args: list[str], expected: list[str]) -> None:
    assert redact_args(args) == expected


def test_truncation_after_redaction() -> None:
    text = redact_cmdline(["x", "--token=" + "a" * 500, "y" * 500], 60)
    assert len(text) == 60 and text.endswith("...")
    assert "aaaa" not in text


def test_list_python_processes_uses_redaction() -> None:
    assert describe_cmdline(["python3", "app.py", "--password", "pw"]).endswith(R)
