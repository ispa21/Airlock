# Airlock browser extension (V2)

Not part of V1. This directory reserves the module boundary.

Design constraints (see docs/IPC.md, "V2: browser extension"):

* Chrome and Edge, Manifest V3.
* The extension talks **only** to the local Airlock agent through native
  messaging. It never sends content to an Airlock cloud service.
* The detection engine stays in the local agent. The extension holds UI
  logic only.
