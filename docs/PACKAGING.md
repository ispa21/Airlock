# Packaging and release (Windows)

Phase 8 turns the repository into an installer that runs on a Windows PC with
no Python, no developer tools and no internet connection.

## What ships

```
C:\Program Files\Airlock\            (all users)   or   %LOCALAPPDATA%\Airlock\ (just me)
├── Airlock.exe                      Tauri host + interface (WebView2)
├── engine\
│   ├── airlock-engine.exe           frozen Python engine (PyInstaller onedir)
│   └── _internal\                   Python, spaCy + English model, OCR models,
│                                    PDFium, ONNX Runtime, OpenCV, Vera fonts
├── THIRD_PARTY_NOTICES.txt          every shipped component and its licence text
├── native-messaging-host.json       lets Chrome and Edge start the engine for the
│                                    Airlock extension (Phase 11)
└── uninstall.exe
```

User data stays out of the install folder: settings, company rules, the
allow-list, the encrypted vault and the work folder for protected copies are
in `%LOCALAPPDATA%\com.airlock.desktop`, the log in its `logs` folder.

## Building

```
python scripts/package.py                    # installer, WebView2 bootstrapper
python scripts/package.py --offline-webview  # also an installer with WebView2 inside
python scripts/package.py --engine-only      # frozen engine only (any OS, for testing)
```

The script:

1. syncs the engine environment with the `package` dependency group
   (PyInstaller, build-only) and freezes the engine with
   `engine/packaging/airlock-engine.spec`;
2. checks the bundle for files that must never ship (ReportLab's GPL
   *DarkGarden* font, OpenCV's LGPL FFmpeg video plugin) and fails if any is
   present;
3. runs `engine/packaging/smoke.py` against the frozen executable: handshake,
   then scan → protected copy → verification for a Word file with the
   language model, a picture with OCR and a PDF;
4. signs the engine executable when `AIRLOCK_SIGN_COMMAND` is set, then
   records its SHA-256;
5. writes `THIRD_PARTY_NOTICES.txt` (`scripts/notices.py`; fails if a
   copyleft-only Rust or npm component would ship);
6. builds the app with the engine's SHA-256 compiled in
   (`AIRLOCK_ENGINE_SHA256`) and the NSIS installer, adding the engine and
   the notices as resources (`tauri.bundle.conf.json`).

The `Package` workflow (`.github/workflows/package.yml`) runs all of this on
`windows-latest`, uploads both installers, then runs
`packaging/windows/installer-smoke.ps1` on the fresh runner: silent
all-users install, firewall rules present, the installed engine passes the
smoke test, Chrome and Edge are registered and the engine answers as the
extension's native-messaging host (`engine/packaging/bridge_smoke.py`), the
installed app completes the engine handshake, no engine process is left after
closing, and the
silent uninstall removes the files, the rules and the browser registrations.

The UI end-to-end test (`scripts/desktop_e2e.py`, standard library only;
not in the workflow yet, see the Phase 8 log in ROADMAP.md) drives the installed app through WebDriver: `tauri-driver` (built in the
workflow with `cargo install`) and the `msedgedriver` that matches the
runner's WebView2 runtime (`packaging/windows/edgedriver.ps1`; a test tool,
never shipped). The test starts the installed app with a WebView2 debugging
port (`WEBVIEW2_ADDITIONAL_BROWSER_ARGUMENTS`, set for the test's process
only) and msedgedriver attaches to it (`debuggerAddress`); letting
msedgedriver launch the app timed out on the runner waiting for
`DevToolsActivePort`. WebDriver cannot drag files from the desktop, so the page
emits the window's own `tauri://drag-drop` event with `{paths, position}`.
The test then scans, creates the protected copy, waits for its check to
pass, clicks Copy Text for AI and reads the clipboard with `Get-Clipboard`
(placeholders, none of the values), checks that the original is unchanged
and that the log has the expected events and no values or file name, kills
`airlock-engine.exe` and scans again (the host restarts it: `engine_exited`,
a second `engine_ready`), and finally closes the window with WM_CLOSE: the
app exits, the host logs `engine_stopped` and no engine process is left.
To run it on a test VM, pass `-TauriDriver <path>` to `installer-smoke.ps1`.

## WebView2

Windows 11 ships the WebView2 runtime, and Windows 10 receives it with Edge
updates. The default installer embeds Microsoft's small **bootstrapper**,
which installs the runtime only if it is missing (that one step needs
internet). For machines that are never online, use the installer built with
`--offline-webview` (`tauri.offline.conf.json`): it carries the full runtime
(about 130 MB more) and needs no network at all.

## Install modes and the firewall rule

The installer asks whether to install for the current user (no administrator
rights) or for all users. An all-users install also adds two Windows Firewall
rules that block inbound and outbound traffic for `airlock-engine.exe`
(`src-tauri/windows/hooks.nsh`). Extraction workers are the same executable,
so they are covered. The uninstaller removes the rules. A per-user install
cannot change the firewall; administrators can add the same rules with
`packaging/windows/firewall.ps1` (also usable from Intune or Group Policy).
The engine's in-process network guard applies in every mode.

Both modes register the engine for the browser extension: the key
`Software\Google\Chrome\NativeMessagingHosts\com.airlock.engine` and its
Edge equivalent (under HKCU for one user, HKLM for all users) point to
`native-messaging-host.json`, which allows only the Airlock extension's ID.
The uninstaller removes both keys.

## Integrity

* The release host refuses to start an engine whose SHA-256 differs from
  the one recorded at build time (`engine_tampered`, shown with "Reinstall
  Airlock"). This covers the engine executable, which contains its Python
  code; the native libraries in `_internal` are covered by the install
  folder's permissions and, when signed, by Authenticode.
* Code signing: set `AIRLOCK_SIGN_COMMAND` to a command line with `{file}`
  (for example `signtool sign /fd SHA256 /tr <timestamp URL> /td SHA256 /f
  cert.pfx /p %PASS% {file}`). The engine is signed before it is hashed;
  Tauri signs the app and the installer through `scripts/sign.py`. In CI the
  command is built from the `WINDOWS_CERTIFICATE` (base64 PFX) and
  `WINDOWS_CERTIFICATE_PASSWORD` secrets; without them the build is unsigned
  and the workflow says so.

## Clean-machine check (before a release)

On a fresh Windows 10 22H2 and Windows 11 VM with no developer tools, with
the network disconnected (use the offline installer):

1. Install for all users; confirm the two firewall rules exist.
2. Start Airlock: the status line reads "Processing locally".
3. Scan one file of each type (PDF with a scanned page, DOCX with comments
   and tracked changes, XLSX with a hidden sheet, PPTX with notes, CSV, TXT,
   PNG, an `.env` file); set blocked items to Redact; create, check and save
   each protected copy; copy the text of one for AI.
4. Add a company rule, mark one finding "not sensitive", scan again.
5. Close Airlock: no `airlock-engine.exe` remains in Task Manager.
   Load `apps/extension` unpacked in Edge (and Chrome if installed), protect
   a pasted prompt with an e-mail and a password, copy the result; after
   five idle minutes no `airlock-engine.exe` remains.
6. Uninstall: the install folder and the firewall rules are gone; user data
   in `%LOCALAPPDATA%\com.airlock.desktop` is kept, as with other apps.
7. Confirm the log (`%LOCALAPPDATA%\com.airlock.desktop\logs\airlock.log`)
   holds no document text, file names or paths.

Repeat with a per-user install (no administrator rights).
