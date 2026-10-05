# Airlock engine

The local privacy engine. Runs as a child process of the desktop app and speaks
JSON-RPC 2.0 over stdio (see `../docs/IPC.md`). No network access: the engine
installs a runtime network guard before doing anything else.

```bash
uv sync                      # create .venv with dev tools
uv run pytest                # unit + subprocess tests
uv run ruff check . && uv run mypy
echo '{"jsonrpc":"2.0","id":1,"method":"system.hello","params":{"protocol_version":"1.0"}}' \
  | uv run python -m airlock_engine
```
