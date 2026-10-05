from __future__ import annotations

import json

import pytest

from airlock_engine.ipc import protocol
from airlock_engine.ipc.protocol import ProtocolError, parse_message


def test_parse_valid_request() -> None:
    req = parse_message(b'{"jsonrpc":"2.0","id":7,"method":"system.hello","params":{"a":1}}')
    assert (req.request_id, req.method, req.params) == (7, "system.hello", {"a": 1})
    assert not req.is_notification


def test_parse_notification_and_missing_params() -> None:
    req = parse_message(b'{"jsonrpc":"2.0","method":"$/cancelRequest"}')
    assert req.is_notification and req.params == {}


@pytest.mark.parametrize(
    ("raw", "code"),
    [
        (b"not json", protocol.PARSE_ERROR),
        (b"\xff\xfe", protocol.PARSE_ERROR),
        (b"[1,2]", protocol.INVALID_REQUEST),
        (b'{"jsonrpc":"1.0","id":1,"method":"x"}', protocol.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1}', protocol.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":true,"method":"x"}', protocol.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":{"a":1},"method":"x"}', protocol.INVALID_REQUEST),
        (b'{"jsonrpc":"2.0","id":1,"method":"x","params":[1]}', protocol.INVALID_PARAMS),
    ],
)
def test_parse_errors(raw: bytes, code: int) -> None:
    with pytest.raises(ProtocolError) as info:
        parse_message(raw)
    assert info.value.code == code


def test_encode_is_single_ascii_line() -> None:
    data = protocol.encode({"text": "line1\nline2 ₹ नमस्ते"})
    assert data.endswith(b"\n") and data.count(b"\n") == 1
    data.decode("ascii")
    assert json.loads(data)["text"].startswith("line1\nline2")
