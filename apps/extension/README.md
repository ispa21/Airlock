# Airlock browser extension (Chrome and Edge)

Protect text before you paste it into an AI tool. Paste text into the
Airlock popup, or select text on a page and right-click **Protect selected
text with Airlock**. Airlock replaces names, e-mail addresses, phone numbers
and other sensitive values with placeholders such as `EMAIL_001`, removes
passwords, keys and tokens, and gives you the protected text to copy.

The extension does not detect anything itself: the text is checked by the
Airlock engine installed on this computer, with your company rules,
"not sensitive" decisions and privacy profiles. Nothing is sent anywhere.

## How it works

```
popup ──chrome.runtime.sendMessage──▶ service worker ──connectNative("com.airlock.engine")──▶ Airlock engine
```

* The browser starts the installed engine (native messaging) and passes it
  the extension's origin; the engine refuses any other origin and offers
  only `system.hello`, `system.health`, `profiles.list` and `text.protect`
  ([docs/IPC.md](../../docs/IPC.md), "Browser extension bridge").
* The service worker answers only this extension's own pages and closes the
  engine connection after 5 idle minutes.
* The extension cannot reach the network or read pages: its CSP has
  `connect-src 'none'`, and it has no host permissions and no content
  scripts. Permissions: `nativeMessaging`, `contextMenus`, `storage` (a
  right-clicked selection waits in memory-only session storage until the
  popup takes it), `clipboardWrite` (the Copy button).

## Using it with the installed app (Windows)

The Airlock installer registers the engine for Chrome and Edge. Until the
extension is published in the stores, load it unpacked: open
`chrome://extensions` (or `edge://extensions`), turn on **Developer mode**,
choose **Load unpacked** and pick this folder. The `key` in `manifest.json`
fixes the extension ID to `cbihflandcpahjbogbficbpidmpdgcce`, which is the
ID the installed engine accepts.

If Airlock is not installed, the popup says "Airlock app not found".

## Development (any platform)

Register the development engine (`engine/.venv`) as the native-messaging
host for your browsers, then load the extension unpacked as above:

```bash
cd engine && uv sync && cd ..
python apps/extension/scripts/register_host.py                      # Chrome, Chromium, Edge
python apps/extension/scripts/register_host.py --user-data-dir DIR  # one browser profile only
python apps/extension/scripts/register_host.py --engine PATH        # a frozen engine instead
```

The script writes a small launcher to `apps/extension/.host/` (git-ignored)
and a host manifest that names only this extension's origin.

After changing the extension's files, click **Reload** on the extensions
page: the browser keeps running the previous service worker until then.

## Tests

```bash
cd apps/extension && npm test     # node --test, no dependencies
```

The engine side (framing, origin check, method allowlist, `text.protect`)
is tested in `engine/tests/test_bridge.py`, which also checks that the
extension ID derived from `manifest.json` is the one the engine accepts.
