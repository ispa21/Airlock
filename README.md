# Airlock

**The privacy layer between your data and AI.**

Your data doesn't have to leave unprotected just because your employees use AI.

Airlock is an offline-first Windows desktop app. It finds sensitive company
data in documents, spreadsheets, presentations, images and code, masks or
blocks it according to policy, verifies the result with a second scan, and
only then lets you export an AI-safe copy. Everything runs on the device; no
external LLM, OCR or NER service is ever used, and the privacy engine works
with the internet disabled.

> Status: the desktop app scans, protects, verifies and exports documents
> (Phases 0-7), installs on Windows (Phase 8), carries lifetime licences
> (Phase 10), a Chrome/Edge extension protects text through the installed
> engine (Phase 11), and prompts are protected with stable `PERSON_001`-style
> placeholders and AI responses restored on the device (Phase 12). Next: the
> local web app (Phase 13). See [docs/ROADMAP.md](docs/ROADMAP.md).

## Repository

| Path | What |
| --- | --- |
| `apps/desktop` | Tauri 2 app: React + TypeScript UI (`src/`), Rust host (`src-tauri/`) |
| `engine` | Python local privacy engine (JSON-RPC over stdio) |
| `apps/extension` | Chrome/Edge extension (Manifest V3); talks to the installed engine through native messaging |
| `licensing` | Licence issuing tool and reference activation server (never shipped) |
| `tests` | Cross-component fixtures and end-to-end suites |
| `docs` | [Architecture](docs/ARCHITECTURE.md) · [IPC](docs/IPC.md) · [Security](docs/SECURITY.md) · [Testing](docs/TESTING.md) · [Roadmap](docs/ROADMAP.md) · [Third-party](docs/THIRD_PARTY.md) |

## Development

Prerequisites: Python 3.11 with [uv](https://docs.astral.sh/uv/), Node 22,
Rust (stable), and the [Tauri prerequisites](https://v2.tauri.app/start/prerequisites/)
(WebView2 on Windows; webkit2gtk-4.1 on Linux).

```bash
# 1. Engine
cd engine
uv sync
uv run pytest

# 2. Desktop app (debug builds run the engine from engine/.venv)
cd ../apps/desktop
npm install
npm run tauri dev
```

Checks:

```bash
cd engine && uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
cd apps/desktop && npm run typecheck && npm test
cd apps/desktop/src-tauri && cargo fmt --check && cargo clippy --all-targets -- -D warnings && cargo test
cd apps/extension && npm test
```

`npm run dev` on its own opens the UI in a browser preview with a mock engine
(dev builds only; the mock is excluded from production bundles).

End users never need Python or Node: release builds bundle a frozen engine
inside the installer (Phase 8).
