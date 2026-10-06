# Licensing (Phase 10)

Airlock uses lifetime licences: signed, verified offline by the desktop host.
Today a licence only identifies the customer ("Licensed to …"); **no feature
is limited** with or without one. The privacy engine never sees licences, and
scanning never depends on a licence or on any server.

## The licence

One line of text, easy to paste from an e-mail or save as a
`.airlock-license` file:

```
AIRLOCK1.<key id>.<payload>.<signature>
```

* `payload`: base64url (no padding) of UTF-8 JSON:

  ```json
  {
    "license_id": "lic_7Q3K9X2MZD",
    "plan": "lifetime",
    "customer": "Acme Pvt Ltd",
    "email": "it@acme.example",
    "seats": 10,
    "features": [],
    "issued_at": "2026-10-06T00:00:00Z",
    "expiry": null,
    "updates_until": null,
    "machine": null
  }
  ```

* `signature`: Ed25519 over the exact payload bytes, base64url.
* `machine`: optional. A licence bound to a machine code is valid only on
  that computer. The machine code (`ABCD-EFGH-IJKL-MNOP-QRST`) is 100 bits of
  SHA-256 over the computer's ID (Windows `MachineGuid`), so the ID itself is
  never shown or sent.

The host (`apps/desktop/src-tauri/src/license.rs`) accepts licences signed by
the keys in `public-keys.json`, which is compiled into the app.

## Keys

```
python licensing/airlock_license.py keygen --id airlock-2026
```

writes the private key to `licensing/keys/airlock-2026.key` (git-ignored,
user-only) and prints the public entry to add to `public-keys.json`. Keep the
private key offline (a hardware token or an offline machine); it is never
shipped. Several keys can be listed, so a key can be rotated without
invalidating licences signed by the old one.

For development, a build can accept one extra key without editing the file:
`AIRLOCK_DEV_LICENSE_KEY="<id>:<public key>"`.

## Issuing a licence by hand (offline)

```
python licensing/airlock_license.py issue --key licensing/keys/airlock-2026.key \
    --customer "Acme Pvt Ltd" --seats 10 --email it@acme.example \
    [--machine ABCD-EFGH-IJKL-MNOP-QRST] [--updates-until 2027-10-06] \
    --out acme.airlock-license
python licensing/airlock_license.py verify acme.airlock-license
```

Customers install it in **Settings → Licence → Import Licence File…** or
**Paste Licence…**. For a computer that is never online, ask the customer for
the machine code shown there and issue a licence with `--machine`.

## Online activation (optional)

`activation_server.py` is a small reference server (standard library plus
`cryptography`). Customers type a licence key (`ALK-XXXXX-XXXXX-XXXXX-XXXXX`);
the app sends the key, the machine code and the app version, and receives a
licence bound to that machine.

```
python licensing/activation_server.py add-key --db activations.db --customer "Acme" --seats 10
python licensing/activation_server.py serve --db activations.db \
    --signing-key licensing/keys/airlock-2026.key --port 8080
python licensing/activation_server.py list --db activations.db
python licensing/activation_server.py release --db activations.db --key ALK-... --machine ABCD-...
```

* Run it behind HTTPS (a reverse proxy). Release builds of the app accept
  only `https://` URLs; set the URL at build time:
  `AIRLOCK_ACTIVATION_URL=https://activate.example.com/v1/activate`.
  Without it, the app hides online activation and offers the file import.
* Keys are stored as SHA-256 hashes; the server logs request lines only (no
  keys, no machine codes); each key covers `seats` machines; re-activating
  the same machine does not use another seat; 20 requests per minute per
  client.
* Answers: `200 {"license": "..."}`, `404 unknown_key`, `409 no_seats_left`,
  `400 bad_request`, `429 rate_limited`.

## What the app does

* On start, the host reads `<app data>/license/airlock.license` and verifies
  it offline. States: *unlicensed*, *licensed*, *invalid* (with the reason:
  changed, unknown issuer, another computer, expired).
* Online activation is the app's only network request. It happens only when
  the user clicks **Activate**, from the host (never the engine), honours a
  system proxy, and sends nothing but the key, the machine code and the app
  version.
* The host log records `license_installed`, `license_activated`,
  `license_removed` and failures by kind, never the key, the customer or the
  machine code.

Tests: `licensing/tests` (tool and server) and the host's `license` and
`licensing` modules, including a licence issued by the Python tool and
verified by the Rust host.
