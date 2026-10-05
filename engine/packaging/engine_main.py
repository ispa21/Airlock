"""Entry point of the frozen engine (PyInstaller).

Kept separate from ``airlock_engine.__main__`` so the frozen build has a
plain script to start from. ``main`` calls ``multiprocessing.freeze_support``
first, which is what lets extraction workers start from the frozen exe.
"""

from airlock_engine.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
