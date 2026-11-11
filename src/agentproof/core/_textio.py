"""Decoding of user-supplied text files (chain JSON, policy YAML).

Those files are written by the user, not by agentproof, so they arrive in
whatever encoding the local tooling happens to use. On Windows that is
commonly:

* UTF-8 without BOM (what this package writes),
* UTF-8 *with* BOM (Notepad, some editors),
* UTF-16LE/BE with a BOM (Windows PowerShell 5.1 ``>`` and ``Out-File``),
* ANSI / GBK (Notepad "ANSI", legacy console redirection).

We accept the two unambiguous Unicode encodings when a BOM identifies them,
and UTF-8 without a BOM. Anything else is rejected with an actionable error
telling the user to re-save the file as UTF-8; guessing at GBK by sniffing
bytes would silently mis-decode a perfectly valid file, which is worse than a
clear refusal in an evidence tool.
"""

from __future__ import annotations

import codecs
from pathlib import Path

__all__ = ["TextDecodeError", "decode_text", "read_text"]


class TextDecodeError(ValueError):
    """A text file is not in an encoding this package can safely read."""


def read_text(path: str | Path, *, kind: str) -> str:
    """Read ``path`` and decode it using :func:`decode_text`."""
    raw = Path(path).read_bytes()
    return decode_text(raw, path=path, kind=kind)


def decode_text(raw: bytes, *, path: str | Path, kind: str) -> str:
    """Decode bytes from a user-supplied file.

    ``kind`` names the document type in the error message (``"chain"``,
    ``"policy"``, ``"public key"``) so the caller can report precisely which
    file has to be re-saved.
    """
    for bom, encoding in (
        (codecs.BOM_UTF8, "utf-8-sig"),
        (codecs.BOM_UTF16_LE, "utf-16"),
        (codecs.BOM_UTF16_BE, "utf-16"),
    ):
        if raw.startswith(bom):
            try:
                return raw.decode(encoding)
            except UnicodeDecodeError as exc:
                raise TextDecodeError(
                    f"{kind} file {path} starts with a {encoding} BOM but the "
                    f"rest is not valid {encoding}: {exc}"
                ) from exc

    try:
        return raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise TextDecodeError(
            f"{kind} file {path} is not valid UTF-8 and carries no UTF-16 BOM "
            f"({exc}). Re-save it as UTF-8 (without a BOM is fine), or as "
            "UTF-16 with a BOM, and retry. agentproof does not guess at legacy "
            "code pages such as GBK because a wrong guess would silently "
            "change the content of an evidence file."
        ) from exc
