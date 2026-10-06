"""End-to-end test of the desktop app's UI through WebDriver (tauri-driver).

Drives the real app the way a person does:

 1. tauri-driver starts the native WebDriver (msedgedriver for WebView2 on
    Windows, WebKitWebDriver on Linux). On Linux the driver starts the app.
    On Windows the test starts the app itself with a WebView2 debugging port
    (WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS, set for this process only) and
    msedgedriver attaches to it (`debuggerAddress`, Microsoft's documented
    mode for WebView2 apps). Letting msedgedriver launch the installed app
    timed out on the runner ("DevToolsActivePort file doesn't exist",
    WebView2 153).
 2. The privacy bar says "Processing locally": the host started the engine,
    checked it (SHA-256 in release builds) and network isolation is on.
 3. A synthetic document is dropped on the window. WebDriver cannot drag
    files from the desktop, so the page emits the `tauri://drag-drop` event
    with `{paths, position}`, the event the window sends on a real drop.
 4. Scan Document, Create Protected Copy, and the copy passes verification.
 5. Copy Text for AI, then the system clipboard is read (Get-Clipboard on
    Windows): placeholders, and none of the document's sensitive values.
 6. The original file is unchanged and the log holds the expected events
    but none of the values (and not the file name).
 7. The engine is killed; Scan Again works because the host restarts it, and
    the log shows engine_exited and a second engine_ready.
 8. The window is closed like a person does (WM_CLOSE on Windows); the app
    exits and no engine process is left.

Standard library only. Used by packaging/windows/installer-smoke.ps1 on the
installed app; also runs on Linux against a development build (see
docs/TESTING.md).

Usage:
  python scripts/desktop_e2e.py --app <Airlock.exe> --log <airlock.log>
      [--driver tauri-driver] [--native-driver <msedgedriver.exe>] [--work <folder>]
"""

from __future__ import annotations

import argparse
import contextlib
import csv
import hashlib
import io
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

WINDOWS = sys.platform == "win32"
PORT = 4444
ELEMENT = "element-6066-11e4-a52e-4f735466cecf"

# Synthetic values only (example.invalid domain, generated PAN and mobile).
NAME_IN_FILE = "vendor-notes-e2e"
EMAIL = "dana.reyes@example.invalid"
PAN = "JLELZ9275C"
MOBILE = "+91 98201 47265"
DOCUMENT = (
    "Vendor onboarding notes\n\n"
    f"Primary contact: {EMAIL}\n"
    f"Mobile: {MOBILE}\n"
    f"Vendor PAN: {PAN}\n"
    "Invoices are due within 30 days.\n"
)
VALUES = (EMAIL, PAN, MOBILE, MOBILE.replace(" ", ""), "dana.reyes")
EXPECTED_EVENTS = (
    "engine_ready",
    "document_inspected",
    "scan_completed",
    "sanitize_completed",
    "verify_completed",
    "export_text",
)

# No proxy: the drivers listen on the loopback address only.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


def step(text: str) -> None:
    print(f"\n-- {text}", flush=True)


class WebDriverError(RuntimeError):
    pass


class Session:
    """A minimal W3C WebDriver client."""

    def __init__(self, base: str, capabilities: dict[str, Any]) -> None:
        self.base = base
        value = self._request("POST", "/session", {"capabilities": capabilities}, timeout=180)
        self.id: str = value["sessionId"]

    def _request(
        self, method: str, path: str, body: dict[str, Any] | None = None, timeout: float = 60
    ) -> Any:
        data = json.dumps(body).encode() if body is not None else None
        request = urllib.request.Request(  # noqa: S310 - the loopback WebDriver URL
            self.base + path,
            data=data,
            method=method,
            headers={"Content-Type": "application/json; charset=utf-8"},
        )
        try:
            with _opener.open(request, timeout=timeout) as response:
                payload = json.loads(response.read() or b"{}")
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode("utf-8", "replace")[:2000]
            raise WebDriverError(f"{method} {path}: HTTP {exc.code} {detail}") from None
        return payload.get("value")

    def command(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        return self._request(method, f"/session/{self.id}{path}", body)

    def run(self, script: str, *args: Any) -> Any:
        return self.command("POST", "/execute/sync", {"script": script, "args": list(args)})

    def run_async(self, script: str, *args: Any) -> Any:
        return self.command("POST", "/execute/async", {"script": script, "args": list(args)})

    def find(self, xpath: str) -> str | None:
        found = self.command("POST", "/elements", {"using": "xpath", "value": xpath})
        if not found:
            return None
        if ELEMENT not in found[0]:
            raise AssertionError(f"unexpected element reference: {found[0]!r}")
        element: str = found[0][ELEMENT]
        return element

    def click(self, xpath: str, timeout: float = 30) -> None:
        def ready() -> str | None:
            element = self.find(xpath)
            if element and self.command("GET", f"/element/{element}/enabled"):
                return element
            return None

        element = wait_for(ready, f"an enabled {xpath}", timeout, self)
        self.command("POST", f"/element/{element}/click", {})

    def end(self) -> None:
        with contextlib.suppress(WebDriverError, OSError):  # the app has already closed
            self._request("DELETE", f"/session/{self.id}", timeout=30)


def button(label: str) -> str:
    return f"//button[normalize-space()='{label}']"


# What the page shows: the privacy bar and any error, never document text.
PAGE_STATE = """
const text = (s) => {
  const e = document.querySelector(s);
  return e ? e.textContent.trim() : null;
};
return {
  engine: text('.trust__item[role=status]'),
  file: (document.querySelector('.filecard') || {}).dataset?.status ?? null,
  error: text('.notice--error .notice__title') || text('.notice .notice__title'),
};
"""


def wait_for(
    check: Callable[[], Any], what: str, timeout: float, session: Session | None = None
) -> Any:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            result = check()
        except WebDriverError:
            result = None
        if result:
            return result
        time.sleep(0.5)
    state = ""
    if session is not None:
        with contextlib.suppress(WebDriverError, OSError):
            state = f" (page: {session.run(PAGE_STATE)})"
    raise AssertionError(f"timed out after {timeout:.0f}s waiting for {what}{state}")


def text_of(session: Session, selector: str) -> str | None:
    value = session.run(
        "const e = document.querySelector(arguments[0]); return e ? e.textContent.trim() : null;",
        selector,
    )
    return value if isinstance(value, str) else None


# --- processes -----------------------------------------------------------------


def _tasklist(image: str) -> list[int]:
    out = subprocess.run(
        ["tasklist", "/FI", f"IMAGENAME eq {image}", "/FO", "CSV", "/NH"],
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    return [
        int(row[1]) for row in csv.reader(io.StringIO(out)) if len(row) > 1 and row[1].isdigit()
    ]


def _pgrep(pattern: str) -> list[int]:
    out = subprocess.run(
        ["pgrep", "-f", "--", pattern], capture_output=True, text=True, check=False
    )
    return [int(pid) for pid in out.stdout.split() if int(pid) != os.getpid()]


def engine_pids() -> list[int]:
    if WINDOWS:
        return _tasklist("airlock-engine.exe")
    # Release builds run the frozen engine; development builds run `-m airlock_engine`.
    return sorted(set(_pgrep("airlock-engine") + _pgrep("-m airlock_engine")))


def app_pids(app: Path) -> list[int]:
    if WINDOWS:
        return _tasklist(app.name)
    return _pgrep(f"^{re.escape(str(app))}")


def kill(pid: int) -> None:
    if WINDOWS:
        subprocess.run(["taskkill", "/F", "/T", "/PID", str(pid)], capture_output=True, check=False)
    else:
        with contextlib.suppress(ProcessLookupError):
            os.kill(pid, signal.SIGKILL)


def close_window(app: Path) -> None:
    """Close the app's window as a person does."""
    pids = app_pids(app)
    assert pids, "the app is not running"
    if WINDOWS:
        ids = ",".join(str(pid) for pid in pids)
        powershell(f"Get-Process -Id {ids} | ForEach-Object {{ [void]$_.CloseMainWindow() }}")
    else:
        # Xvfb has no window manager to send WM_DELETE_WINDOW; SIGTERM ends
        # the host and the engine must notice its pipes closing.
        for pid in pids:
            os.kill(pid, signal.SIGTERM)


def focus_window(app: Path) -> None:
    """The clipboard API needs the page to have focus (WebView2)."""
    if WINDOWS:
        for pid in app_pids(app):
            powershell(f"[void](New-Object -ComObject WScript.Shell).AppActivate({pid})")


def powershell(command: str) -> str:
    result = subprocess.run(
        [
            "powershell.exe",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            "[Console]::OutputEncoding = [Text.Encoding]::UTF8; " + command,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        check=False,
    )
    return result.stdout


def read_clipboard() -> str:
    if WINDOWS:
        return powershell("Get-Clipboard -Raw")
    return subprocess.run(
        ["xclip", "-o", "-selection", "clipboard"], capture_output=True, text=True, check=False
    ).stdout


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def log_events(log: Path) -> list[str]:
    events = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            events.append(json.loads(line).get("event", ""))
        except json.JSONDecodeError:
            raise AssertionError("the log has a line that is not a JSON record") from None
    return events


def assert_no_values(where: str, text: str, extra: tuple[str, ...] = ()) -> None:
    lowered = text.lower()
    for value in (*VALUES, *extra):
        assert value.lower() not in lowered, f"{where} contains a sensitive value"


# --- the test ------------------------------------------------------------------


#: wry's own WebView2 arguments; the environment variable replaces them, so keep them.
WRY_ARGS = "--disable-features=msWebOOUI,msPdfOOUI,msSmartScreenProtection"


def free_port() -> int:
    with socket.socket() as probe:
        probe.bind(("127.0.0.1", 0))
        port: int = probe.getsockname()[1]
        return port


def airlock_webviews() -> list[tuple[int, str]]:
    """WebView2 browser processes using the app's data folder (Windows)."""
    out = powershell(
        "Get-CimInstance Win32_Process -Filter \"Name='msedgewebview2.exe'\" | "
        'ForEach-Object { "$($_.ProcessId)`t$($_.CommandLine)" }'
    )
    found = []
    for line in out.splitlines():
        pid, _, command = line.partition("\t")
        if pid.strip().isdigit() and "com.airlock.desktop" in command:
            found.append((int(pid), command))
    return found


def launch_for_attach(app: Path) -> tuple[subprocess.Popen[bytes], int]:
    """Start the app with a WebView2 debugging port; return it and the port."""
    for pid, _ in airlock_webviews():
        kill(pid)  # a leftover browser process would ignore the new arguments
    wait_for(lambda: not airlock_webviews(), "earlier WebView2 processes to exit", 30)
    port = free_port()
    env = dict(os.environ)
    env["WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS"] = f"--remote-debugging-port={port} {WRY_ARGS}"
    proc = subprocess.Popen([str(app)], env=env)

    def debugging() -> bool:
        try:
            with _opener.open(f"http://127.0.0.1:{port}/json/version", timeout=2):
                return True
        except OSError:
            return False

    try:
        wait_for(debugging, "WebView2 to open its debugging port", 90)
    except AssertionError:
        for pid, command in airlock_webviews():
            print(f"msedgewebview2 {pid}: {command[:400]}")
        raise
    return proc, port


def start_driver(driver: str, native_driver: str | None) -> subprocess.Popen[bytes]:
    command = [driver, "--port", str(PORT)]
    if native_driver:
        command += ["--native-driver", native_driver]
    proc = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    def listening() -> bool:
        try:
            with _opener.open(f"http://127.0.0.1:{PORT}/status", timeout=2):
                return True
        except urllib.error.HTTPError:
            return True  # tauri-driver answers, even if not with a status
        except OSError:
            return False

    wait_for(listening, "tauri-driver to listen", 30)
    return proc


def drop(session: Session, path: Path) -> None:
    """Emit the window's file-drop event from the page (see module docstring)."""
    error = session.run_async(
        """
        const [paths, done] = [arguments[0], arguments[arguments.length - 1]];
        window.__TAURI_INTERNALS__
          .invoke('plugin:event|emit', {
            event: 'tauri://drag-drop',
            payload: { paths, position: { x: 400, y: 300 } },
          })
          .then(() => done(null), (e) => done(String(e)));
        """,
        [str(path)],
    )
    assert error is None, f"emitting the drop event failed: {error}"


FINDING_TYPES = """
const report = document.querySelector('#findings-title');
if (!report || report.dataset.e2eSeen) return null;
report.dataset.e2eSeen = '1';
const types = document.querySelectorAll('.finding .finding__type');
return { types: [...types].map((e) => e.textContent.trim()) };
"""


def scan(session: Session) -> list[str]:
    """Scan the loaded file; return the finding types of the new report."""
    session.click(button("Scan Document") + " | " + button("Scan Again"))
    # A report already on screen is marked as seen, so this waits for the new one.
    report = wait_for(lambda: session.run(FINDING_TYPES), "the privacy report", 600, session)
    types: list[str] = report["types"]
    assert len(types) >= 3, f"expected the e-mail, mobile and PAN, found {types}"
    return types


def run(args: argparse.Namespace) -> None:
    app = Path(args.app).resolve()
    log = Path(args.log)
    work = Path(args.work or tempfile.mkdtemp(prefix="airlock-e2e-"))
    work.mkdir(parents=True, exist_ok=True)
    document = work / f"{NAME_IN_FILE}.txt"
    document.write_text(DOCUMENT, encoding="utf-8")
    original_hash = sha256(document)
    log.unlink(missing_ok=True)
    assert not engine_pids(), "an engine is already running before the test"

    step("tauri-driver starts the app")
    driver = start_driver(args.driver, args.native_driver)
    session: Session | None = None
    try:
        if WINDOWS:
            _, debug_port = launch_for_attach(app)
            capabilities: dict[str, Any] = {
                "browserName": "webview2",
                "ms:edgeOptions": {"debuggerAddress": f"127.0.0.1:{debug_port}"},
            }
            print(f"app started; WebView2 debugging port {debug_port}")
        else:
            capabilities = {"tauri:options": {"application": str(app)}}
        session = Session(f"http://127.0.0.1:{PORT}", {"alwaysMatch": capabilities})
        status = wait_for(
            lambda: (
                (text_of(session, ".trust__item[role=status]") or "").startswith(
                    ("Processing locally", "Network isolation inactive", "Local engine unavailable")
                )
                and text_of(session, ".trust__item[role=status]")
            ),
            "the engine status",
            120,
            session,
        )
        assert status == "Processing locally", f"privacy bar says {status!r}"
        print(f"privacy bar: {status}")
        first_engine = engine_pids()
        assert first_engine, "no engine process is running"

        step("Drop the document on the window (tauri://drag-drop)")
        drop(session, document)
        wait_for(
            lambda: session.run(PAGE_STATE)["file"] == "verified",
            "the dropped file to be checked",
            60,
            session,
        )
        print("file accepted")

        step("Scan, create the protected copy, verification passes")
        print(f"report: {scan(session)}")
        session.click(button("Create Protected Copy"))
        verified = wait_for(
            lambda: text_of(session, ".copy__verified"), "the copy to pass its check", 600, session
        )
        print(f"check: {verified}")
        assert verified.startswith("Checked:"), verified

        step("Copy Text for AI, then read the clipboard")
        focus_window(app)
        session.click(button("Copy Text for AI"))
        note = wait_for(
            lambda: text_of(session, ".report__callout"), "the copy confirmation", 30, session
        )
        assert note.startswith("Copied the protected text"), note
        clipboard = wait_for(read_clipboard, "text on the clipboard", 15)
        assert_no_values("the clipboard", clipboard)
        placeholders = sorted(set(re.findall(r"\[?([A-Z][A-Z_]*?_\d+)\]?", clipboard)))
        assert any(p.startswith("EMAIL_") for p in placeholders), placeholders
        assert "Invoices are due within 30 days." in clipboard, "the copy lost ordinary text"
        print(f"clipboard: {len(clipboard)} characters, placeholders {', '.join(placeholders)}")

        step("Original unchanged; the log has the events and no content")
        assert sha256(document) == original_hash, "the original file was changed"
        events = log_events(log)
        for event in EXPECTED_EVENTS:
            assert event in events, f"{event} missing from the log"
        assert_no_values("the log", log.read_text(encoding="utf-8"), (NAME_IN_FILE,))
        print(f"log: {len(events)} records, no values or file name")

        step("Kill the engine; the host restarts it on the next action")
        for pid in first_engine:
            kill(pid)
        wait_for(lambda: not set(first_engine) & set(engine_pids()), "the engine to die", 15)
        print(f"killed engine process {', '.join(map(str, first_engine))}")
        print(f"report after restart: {scan(session)}")
        restarted = engine_pids()
        assert restarted and not set(restarted) & set(first_engine), "no new engine process"
        events = log_events(log)
        assert "engine_exited" in events, "engine_exited missing from the log"
        assert events.count("engine_ready") >= 2, "the engine was not started again"
        assert_no_values("the log", log.read_text(encoding="utf-8"), (NAME_IN_FILE,))
        print(
            f"new engine process {', '.join(map(str, restarted))}; log: engine_exited, engine_ready"
        )

        step("Close the window; no process is left")
        close_window(app)
        wait_for(lambda: not app_pids(app), "the app to exit", 30)
        wait_for(lambda: not engine_pids(), "the engine to exit (no orphan)", 15)
        print("app closed; no engine process left")
        if WINDOWS:
            assert "engine_stopped" in log_events(log), "the host did not stop the engine"
    finally:
        if session is not None:
            session.end()
        if WINDOWS:
            kill(driver.pid)  # with its native driver (/T)
        else:
            driver.terminate()
        driver.wait(timeout=30)
        for pid in app_pids(app) + engine_pids():
            kill(pid)
        if not args.work:
            shutil.rmtree(work, ignore_errors=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--app", required=True, help="the app executable")
    parser.add_argument("--log", required=True, help="the app's airlock.log")
    parser.add_argument("--driver", default="tauri-driver")
    parser.add_argument("--native-driver", help="msedgedriver.exe (Windows)")
    parser.add_argument("--work", help="folder for the test document (kept)")
    run(parser.parse_args())
    print("\ndesktop end-to-end test passed")
    return 0


if __name__ == "__main__":
    sys.exit(main())
