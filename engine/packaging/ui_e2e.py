"""End-to-end test of the installed app's interface through WebDriver.

Starts tauri-driver (which drives WebView2 through msedgedriver on Windows,
WebKitGTK through WebKitWebDriver on Linux) and uses Airlock the way a person
does:

1. the app starts and its engine is ready ("Processing locally");
2. a file is dropped on the window (the same ``tauri://drag-drop`` event the
   operating system's drop produces) and scanned;
3. a protected copy is created and passes verification;
4. "Copy Text for AI" puts the protected text on the clipboard: no protected
   value, placeholders instead;
5. the engine is killed and the next scan still works (automatic restart);
6. closing the app leaves no engine process, and the log holds no file name,
   path or value.

Usage:
  python packaging/ui_e2e.py --app <Airlock executable> --tauri-driver <path>
                             [--native-driver <msedgedriver or WebKitWebDriver>]
                             [--log <airlock.log>] [--work <folder>]

Standard library only, so it runs with any Python 3.11.
"""

from __future__ import annotations

import argparse
import contextlib
import http.client
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from collections.abc import Callable
from pathlib import Path
from typing import Any

DRIVER = "http://127.0.0.1:4444"
ELEMENT = "element-6066-11e4-a52e-4f735466cecf"
# Synthetic values only (example.invalid, a reserved test number range).
EMAIL = "priya.raman@example.invalid"
PHONE = "+91 98450 12345"
NAME = "Priya Raman"
DOCUMENT = (
    f"Renewal notes\n\nContact {NAME} at {EMAIL} or {PHONE} before Friday.\n"
    "The renewal covers two sites and the support plan.\n"
)
ENGINE = "airlock-engine.exe" if sys.platform == "win32" else "airlock-engine"


def step(text: str) -> None:
    print(f"\n== {text}", flush=True)


class WebDriver:
    def __init__(self, app: Path) -> None:
        caps = {"capabilities": {"alwaysMatch": {"tauri:options": {"application": str(app)}}}}
        self.session = self.request("POST", "/session", caps)["sessionId"]

    def request(self, method: str, path: str, body: dict[str, Any] | None = None) -> Any:
        data = json.dumps(body if body is not None else {}).encode() if method == "POST" else None
        # The driver chain (tauri-driver -> native driver) sometimes drops a
        # kept-alive connection; such a request never reached the app.
        for attempt in range(3):
            # The local driver at a fixed http URL.
            headers = {"Content-Type": "application/json"}
            req = urllib.request.Request(DRIVER + path, data, headers, method=method)  # noqa: S310
            try:
                with urllib.request.urlopen(req, timeout=180) as response:  # noqa: S310 - loopback
                    return json.loads(response.read() or b"{}").get("value")
            except urllib.error.HTTPError as error:
                detail = error.read().decode(errors="replace")[:2000]
                if attempt < 2 and "SendRequest" in detail:
                    time.sleep(1)
                    continue
                raise RuntimeError(f"WebDriver {method} {path}: {error.code} {detail}") from None
            except (http.client.RemoteDisconnected, ConnectionResetError):
                if attempt == 2:
                    raise
                time.sleep(1)
        raise AssertionError("unreachable")

    def run(self, script: str, *args: Any) -> Any:
        return self.request(
            "POST", f"/session/{self.session}/execute/sync", {"script": script, "args": list(args)}
        )

    def run_async(self, script: str, *args: Any) -> Any:
        return self.request(
            "POST", f"/session/{self.session}/execute/async", {"script": script, "args": list(args)}
        )

    def text(self) -> str:
        return str(self.run("return document.body.innerText"))

    def wait_for(self, what: str, check: Callable[[], Any], timeout: float = 120) -> Any:
        deadline = time.monotonic() + timeout
        while True:
            value = check()
            if value:
                return value
            if time.monotonic() > deadline:
                raise RuntimeError(f"timed out waiting for {what}. Screen:\n{self.text()[:3000]}")
            time.sleep(0.5)

    def wait_text(self, needle: str, timeout: float = 120) -> None:
        self.wait_for(repr(needle), lambda: needle in self.text(), timeout)

    def click(self, label: str, timeout: float = 120) -> None:
        """Clicks the enabled button whose text starts with ``label``."""
        xpath = f"//button[starts-with(normalize-space(.), {json.dumps(label)}) and not(@disabled)]"

        def find() -> str | None:
            found = self.request(
                "POST", f"/session/{self.session}/elements", {"using": "xpath", "value": xpath}
            )
            return found[0][ELEMENT] if found else None

        element = self.wait_for(f"button {label!r}", find, timeout)
        self.request("POST", f"/session/{self.session}/element/{element}/click")

    def close_window(self) -> None:
        """Closes the window, as the user does with its close button."""
        self.request("DELETE", f"/session/{self.session}/window")

    def close(self) -> None:
        self.request("DELETE", f"/session/{self.session}")


def drop(driver: WebDriver, path: Path) -> None:
    """Delivers the drop event the window receives when a file is dropped on it."""
    result = driver.run_async(
        """
        const [path, done] = arguments;
        window.__TAURI_INTERNALS__
          .invoke("plugin:event|emit", {
            event: "tauri://drag-drop",
            payload: { paths: [path], position: { x: 200, y: 200 } },
          })
          .then(() => done("ok"), (error) => done(String(error)));
        """,
        str(path),
    )
    if result != "ok":
        raise RuntimeError(f"could not deliver the drop event: {result}")


def clipboard() -> str:
    if sys.platform == "win32":
        command = ["powershell", "-NoProfile", "-Command", "Get-Clipboard -Raw"]
    else:
        command = ["xclip", "-o", "-selection", "clipboard"]
    try:
        return subprocess.run(command, capture_output=True, text=True, timeout=20).stdout
    except subprocess.TimeoutExpired:
        return ""


def running(image: str) -> int:
    """Live processes with this executable name."""
    if sys.platform == "win32":
        out = subprocess.run(
            ["tasklist", "/FI", f"IMAGENAME eq {image}", "/NH"], capture_output=True, text=True
        ).stdout
        return out.lower().count(image.lower())
    # Threads, not processes: a killed process shows as a zombie as soon as its
    # main thread exits, while its other threads (holding its pipes) still run.
    # A fully dead engine stays a zombie until the host's next request reaps it.
    out = subprocess.run(
        ["ps", "-L", "-C", image, "-o", "stat="], capture_output=True, text=True
    ).stdout
    return sum(1 for stat in out.split() if not stat.startswith("Z"))


def engines() -> int:
    return running(ENGINE)


def kill_engines() -> None:
    if sys.platform == "win32":
        subprocess.run(["taskkill", "/F", "/T", "/IM", ENGINE], capture_output=True)
    else:
        subprocess.run(["pkill", "-9", "-x", ENGINE], capture_output=True)


def scan_and_protect(driver: WebDriver, document: Path) -> None:
    drop(driver, document)
    driver.wait_text(document.name)
    driver.click("Scan")  # "Scan Document", or "Scan Again" after a first scan
    driver.click("Create")  # "Create Protected Copy", or "Create Again"
    driver.wait_for(
        "the copy's check",
        lambda: "none of the" in driver.text() and "protected values are in it" in driver.text(),
        timeout=180,
    )


def default_log() -> Path:
    if sys.platform == "win32":
        base = Path(os.environ["LOCALAPPDATA"])
    else:
        base = Path(os.environ.get("XDG_DATA_HOME") or Path.home() / ".local" / "share")
    return base / "com.airlock.desktop" / "logs" / "airlock.log"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    parser.add_argument("--app", required=True, type=Path)
    parser.add_argument("--tauri-driver", required=True)
    parser.add_argument("--native-driver")
    parser.add_argument("--log", type=Path, default=default_log())
    parser.add_argument("--work", type=Path)
    args = parser.parse_args()

    work = args.work or Path(tempfile.mkdtemp(prefix="airlock-ui-"))
    work.mkdir(parents=True, exist_ok=True)
    document = work / "renewal-notes.txt"
    document.write_text(DOCUMENT, encoding="utf-8")
    original = document.read_bytes()
    args.log.unlink(missing_ok=True)

    command = [args.tauri_driver]
    if args.native_driver:
        command += ["--native-driver", args.native_driver]
    tauri_driver = subprocess.Popen(command)
    driver: WebDriver | None = None
    try:
        time.sleep(3)
        step("App starts; its engine is ready")
        driver = WebDriver(args.app.resolve())
        driver.wait_text("Processing locally")
        print("status: Processing locally")

        step("Drop a file, scan it, create and check a protected copy")
        scan_and_protect(driver, document)
        print(driver.text().split("Checked:")[1].split("\n")[0].strip()[:200])

        step("Copy Text for AI")
        driver.click("Copy Text for AI")
        text = driver.wait_for("the clipboard", lambda: "[EMAIL_1]" in (c := clipboard()) and c)
        for value in (EMAIL, PHONE, NAME):
            assert value not in text, "a protected value reached the clipboard"
        print(f"clipboard: {text.strip()[:200]!r}")

        step("The engine is killed; the next scan still works")
        assert engines() >= 1, "no engine process is running"
        kill_engines()
        driver.wait_for("the engine to stop", lambda: engines() == 0, timeout=30)
        scan_and_protect(driver, document)
        print("scanned and protected again after the engine was restarted")

        step("Closing the window quits the app and leaves no engine behind")
        driver.close_window()
        with contextlib.suppress(OSError, RuntimeError):
            driver.close()
        driver = None
        app = args.app.name
        deadline = time.monotonic() + 30
        while running(app) and time.monotonic() < deadline:
            time.sleep(1)
        assert running(app) == 0, "the app is still running after its window closed"
    except BaseException:
        # The log is content-free by design, so its events can be shown.
        if args.log.exists():
            for line in args.log.read_text(encoding="utf-8").splitlines():
                record = json.loads(line)
                print("log:", record.get("event"), record.get("kind", ""), record.get("source", ""))
        raise
    finally:
        if driver is not None:
            with contextlib.suppress(OSError, RuntimeError):
                driver.close()  # a failed run still closes the app
        tauri_driver.terminate()
        tauri_driver.wait(timeout=30)
    deadline = time.monotonic() + 30
    while engines() and time.monotonic() < deadline:
        time.sleep(1)
    assert engines() == 0, "an engine process is still running after the app closed"
    assert document.read_bytes() == original, "the original file changed"
    print("no engine process left; the original file is unchanged")

    step("The log holds no file name, path or value")
    log = args.log.read_text(encoding="utf-8")
    for secret in (EMAIL, PHONE, NAME, "Priya", document.name, str(work)):
        assert secret not in log, "the log contains document content or a path"
    events = sorted({json.loads(line).get("event", "") for line in log.splitlines() if line})
    print(f"{len(log.splitlines())} log lines; events: {', '.join(events)}")

    shutil.rmtree(work, ignore_errors=True)
    print("\nUI end-to-end test passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
