"""Redact secret-looking values from command lines before they are returned.

Command lines are world-readable on Linux and often carry credentials. This
is a best-effort filter for common shapes; it does not make a command line
safe to publish:

- ``--password=x``, ``--token x``, ``-p=x`` style options whose name looks secret
- ``NAME=value`` pairs whose name looks secret (``AWS_SECRET_ACCESS_KEY=...``,
  ``DB_PASSWORD=...``, ``*_KEY=...``, ``*_TOKEN=...``)
- ``Authorization: ...`` and similar header strings, joined or split over arguments
- credentials in URLs (``scheme://user:pass@host``) and secret-named query parameters
"""

from __future__ import annotations

import re

REDACTED = "<redacted>"

_SECRET_WORD = (
    r"pass(?:word|wd|phrase)?|pwd|secret|token|api[-_]?key|apikey|access[-_]?key|"
    r"private[-_]?key|auth(?:orization)?|credentials?|creds?|session[-_]?id|cookie|"
    r"signature|client[-_]?secret|bearer|jwt|dsn|conn(?:ection)?[-_]?string"
)
_SECRET_NAME = re.compile(rf"(?i)(?:^|[-_.])(?:{_SECRET_WORD})(?:$|[-_.])|(?i:_KEY$)")
_OPTION = re.compile(r"^(?P<dashes>--?)(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)(?P<eq>=)(?P<value>.*)$")
_BARE_OPTION = re.compile(r"^--?(?P<name>[A-Za-z0-9][A-Za-z0-9_.-]*)$")
_ENV_PAIR = re.compile(r"^(?P<name>[A-Za-z_][A-Za-z0-9_]*)=(?P<value>.*)$")
_HEADER = re.compile(
    r"(?i)\b(?P<h>(?:proxy-)?authorization|x-api-key|x-auth-token|api-key|cookie|set-cookie)"
    r"(?P<sep>\s*:\s*)(?P<value>.+)$"
)
_HEADER_NAME_ONLY = re.compile(
    r"(?i)^(?:(?:proxy-)?authorization|x-api-key|x-auth-token|api-key|cookie):?$"
)
_URL_USERINFO = re.compile(r"(?P<scheme>[A-Za-z][A-Za-z0-9+.-]*://)(?P<userinfo>[^/@\s]+)@")
_QUERY_PARAM = re.compile(r"(?P<pre>[?&;])(?P<name>[A-Za-z0-9_.-]+)=(?P<value>[^&;#\s]*)")
_AUTH_SCHEMES = {"bearer", "basic", "token", "digest", "negotiate"}


def is_secret_name(name: str) -> bool:
    return bool(_SECRET_NAME.search(name))


def _redact_inline(arg: str) -> str:
    def userinfo(m: re.Match[str]) -> str:
        user, sep, _ = m.group("userinfo").partition(":")
        return (
            f"{m.group('scheme')}{user}:{REDACTED}@" if sep else f"{m.group('scheme')}{REDACTED}@"
        )

    def query(m: re.Match[str]) -> str:
        if is_secret_name(m.group("name")):
            return f"{m.group('pre')}{m.group('name')}={REDACTED}"
        return m.group(0)

    arg = _URL_USERINFO.sub(userinfo, arg)
    if "://" in arg or "?" in arg:
        arg = _QUERY_PARAM.sub(query, arg)
    m = _HEADER.search(arg)
    if m:
        arg = arg[: m.start("value")] + REDACTED
    return arg


def redact_args(args: list[str]) -> list[str]:
    """Return a copy of ``args`` with secret-looking values replaced by ``<redacted>``."""
    out: list[str] = []
    redact_next = 0
    for arg in args:
        if redact_next:
            redact_next -= 1
            if arg.lower() in _AUTH_SCHEMES:
                out.append(arg)
                redact_next = 1
            else:
                out.append(REDACTED)
            continue
        m = _OPTION.match(arg)
        if m and is_secret_name(m.group("name")):
            out.append(f"{m.group('dashes')}{m.group('name')}={REDACTED}")
            continue
        m = _BARE_OPTION.match(arg)
        if m and is_secret_name(m.group("name")):
            out.append(arg)
            redact_next = 1
            continue
        m = _ENV_PAIR.match(arg)
        if m and is_secret_name(m.group("name")):
            out.append(f"{m.group('name')}={REDACTED}")
            continue
        if _HEADER_NAME_ONLY.match(arg):
            out.append(arg)
            redact_next = 1
            continue
        out.append(_redact_inline(arg))
    return out


def redact_cmdline(args: list[str] | None, max_len: int) -> str:
    text = " ".join(redact_args(args or []))
    return text if len(text) <= max_len else text[: max_len - 3] + "..."
