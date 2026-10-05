from airlock_engine.cli import main

# The guard matters: extraction workers are started with the "spawn" method,
# which re-imports the parent's main module under the name "__mp_main__".
if __name__ == "__main__":
    raise SystemExit(main())
