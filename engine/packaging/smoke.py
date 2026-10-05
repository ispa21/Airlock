"""Smoke test for a frozen (installed) engine.

Drives the real executable over stdio, exactly as the desktop host does:
handshake, then scan → protected copy → verification for a Word file (with
the language model), a scanned image (OCR) and a PDF. Fails loudly if any
bundled component is missing from the build.

Usage:  python packaging/smoke.py <path to airlock-engine[.exe]> [<work folder>]
Needs the dev dependencies (python-docx, reportlab...) to build the fixtures.
"""

from __future__ import annotations

import json
import subprocess
import sys
import tempfile
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "tests"))

import builders


class Engine:
    def __init__(self, exe: Path, data_dir: Path) -> None:
        self.proc = subprocess.Popen(
            [str(exe), "--log-level", "info", "--data-dir", str(data_dir)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        self.next_id = 0

    def call(self, method: str, **params: Any) -> Any:
        self.next_id += 1
        request = {"jsonrpc": "2.0", "id": self.next_id, "method": method, "params": params}
        assert self.proc.stdin is not None and self.proc.stdout is not None
        self.proc.stdin.write(json.dumps(request).encode() + b"\n")
        self.proc.stdin.flush()
        while True:
            line = self.proc.stdout.readline()
            if not line:
                stderr = (
                    self.proc.stderr.read().decode(errors="replace") if self.proc.stderr else ""
                )
                raise RuntimeError(f"engine exited during {method}:\n{stderr[-4000:]}")
            message = json.loads(line)
            if message.get("id") != self.next_id:
                continue  # progress notifications
            if "error" in message:
                raise RuntimeError(f"{method} failed: {message['error']}")
            return message["result"]

    def close(self) -> None:
        try:
            self.call("system.shutdown")
        finally:
            self.proc.wait(timeout=30)


def protect(engine: Engine, path: Path, *, ner: bool, ocr: bool) -> dict[str, Any]:
    scan = engine.call("scan.start", path=str(path), ner=ner, ocr=ocr)
    blocked = [f["id"] for f in scan["findings"] if f["effective_action"] == "BLOCK"]
    if blocked:
        engine.call(
            "scan.override",
            scan_id=scan["scan_id"],
            overrides=[{"finding_id": i, "action": "REDACT"} for i in blocked],
        )
    copy = engine.call("sanitize.run", scan_id=scan["scan_id"])
    check = engine.call("verify.run", artifact_id=copy["artifact_id"])
    return {"scan": scan, "copy": copy, "check": check}


def main() -> int:
    exe = Path(sys.argv[1]).resolve()
    work = (
        Path(sys.argv[2]) if len(sys.argv) > 2 else Path(tempfile.mkdtemp(prefix="airlock-smoke-"))
    )
    work.mkdir(parents=True, exist_ok=True)
    engine = Engine(exe, work / "data")
    try:
        hello = engine.call("system.hello", protocol_version="1.0")
        assert hello["compatible"] and hello["network_isolation"], hello
        print(f"engine {hello['engine_version']} pid {hello['pid']}: network isolation on")

        docx = work / "contract.docx"
        docx.write_bytes(builders.build_docx(with_ocr_image=True))
        result = protect(engine, docx, ner=True, ocr=True)
        scan = result["scan"]
        assert scan["summary"]["detectors"]["ner"] == "used", "language model missing"
        assert scan["extraction"]["ocr_used"], "OCR missing"
        types = {f["entity_type"] for f in scan["findings"]}
        print(f"docx: {len(scan['findings'])} findings ({', '.join(sorted(types))})")
        assert result["check"]["status"] == "passed", result["check"]

        image = work / "scan.png"
        image.write_bytes(builders.png_bytes(builders.text_image("Contact ops@example.invalid")))
        result = protect(engine, image, ner=False, ocr=True)
        assert "EMAIL" in {f["entity_type"] for f in result["scan"]["findings"]}, "OCR text"
        assert result["check"]["status"] == "passed", result["check"]
        print("png: OCR found the e-mail; copy verified")

        pdf = work / "report.pdf"
        pdf.write_bytes(builders.build_pdf(scanned_page=True))
        result = protect(engine, pdf, ner=False, ocr=True)
        assert result["check"]["status"] == "passed", result["check"]
        print(f"pdf: {len(result['scan']['findings'])} findings; rebuilt copy verified")
    finally:
        engine.close()
    print("smoke test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
