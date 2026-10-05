"""Airlock local privacy engine.

Everything in this package runs on the user's machine. Nothing in the privacy
pipeline may call a network service; ``security.network_guard`` enforces this
at runtime.
"""

__version__ = "0.1.0"
