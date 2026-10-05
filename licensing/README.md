# Licensing (Phase 10)

Airlock uses lifetime licences: signed JSON documents verified offline.

```json
{
  "license_id": "lic_...",
  "plan": "lifetime",
  "customer": "...",
  "seats": 1,
  "features": [],
  "issued_at": "2026-01-01T00:00:00Z",
  "expiry": null
}
```

* Signature: Ed25519 over the canonical JSON bytes.
* The desktop host embeds the **public** key and verifies locally. The privacy
  engine never depends on licensing; scanning keeps working offline and when
  the licence server is down.
* This directory will hold the issuer CLI. The private key is never committed
  (see `.gitignore`) and is never shipped with the app.
