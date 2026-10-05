"""Held-out corpus: realistic mixed documents written separately from the
templates the detectors were tuned on. It guards against over-fitting the
gate corpus. Spans are located by value, so each value is unique per text.
"""

from __future__ import annotations

from synthetic import Synth
from synthetic.corpus import Sample


def _sample(text: str, values: list[tuple[str, str]]) -> Sample:
    labels = []
    for value, entity_type in values:
        start = text.index(value)
        labels.append((start, start + len(value), entity_type))
    return Sample(text, labels)


def heldout(seed: int = 101, rounds: int = 15) -> list[Sample]:
    s = Synth(seed)
    out: list[Sample] = []
    for _ in range(rounds):
        name, email, mob = s.name(), s.email(), s.mobile_in()
        pan, aad, gst = s.pan(), s.aadhaar(), s.gstin()
        acct, ifsc, card = s.bank_account(), s.ifsc(), s.card()
        ip, url, dob = s.ipv4(), s.url(), s.dob()
        gh, aws, pw, jwt = s.github_token(), s.aws_key(), s.password(), s.jwt()
        uuid, sha = s.uuid(), s.sha(40)

        out.append(
            _sample(
                f"Hi team,\n\nPlease onboard the new vendor. Contact person: {email}, "
                f"phone {mob}. Their PAN is {pan} and GSTIN {gst}. Payment goes to "
                f"account {acct} (IFSC {ifsc}).\n\nThanks,\nOps",
                [
                    (email, "EMAIL"),
                    (mob, "PHONE"),
                    (pan, "PAN"),
                    (gst, "GSTIN"),
                    (acct, "BANK_ACCOUNT"),
                    (ifsc, "IFSC"),
                ],
            )
        )
        out.append(
            _sample(
                f"# production settings\nDEBUG=false\nDB_HOST={ip}\nDB_PASSWORD={pw}\n"
                f"GITHUB_TOKEN={gh}\nAWS_ACCESS_KEY_ID={aws}\nREQUEST_ID={uuid}\n"
                f"RELEASE=4.2.1\nTIMEOUT_MS=30000\n",
                [(ip, "IP_ADDRESS"), (pw, "PASSWORD"), (gh, "API_KEY"), (aws, "CLOUD_KEY")],
            )
        )
        out.append(
            _sample(
                f"2024-11-0{s.r.randint(1, 9)} 10:4{s.r.randint(0, 9)}:12,331 INFO request "
                f"from {ip} user={email} trace={uuid} commit={sha} took 182 ms",
                [(ip, "IP_ADDRESS"), (email, "EMAIL")],
            )
        )
        out.append(
            _sample(
                f'{{"customer": {{"email": "{email}", "dob": "{dob}", "aadhaar": "{aad}"}}, '
                f'"card": "{card}", "session": "{jwt}", "order_id": "ORD-{s.r.randint(10**6, 10**7)}"}}',
                [
                    (email, "EMAIL"),
                    (dob, "DATE_OF_BIRTH"),
                    (aad, "AADHAAR"),
                    (card, "CREDIT_CARD"),
                    (jwt, "ACCESS_TOKEN"),
                ],
            )
        )
        out.append(
            _sample(
                f"KYC note: applicant born {dob}; Aadhaar {aad}; mobile {mob}. "
                f"Documents uploaded to {url}. Invoice INV-{s.r.randint(10000, 99999)} total "
                f"Rs. {s.r.randint(1, 99)},{s.r.randint(100, 999)}.00 approved on "
                f"{s.r.randint(10, 28)}/0{s.r.randint(1, 9)}/2024.",
                [(dob, "DATE_OF_BIRTH"), (aad, "AADHAAR"), (mob, "PHONE"), (url, "URL")],
            )
        )
        out.append(
            _sample(
                f"Rotated keys after the incident: old token {gh} revoked; new password "
                f"stored in vault. Version 3.1.4.1 deployed to {ip}.",
                [(gh, "API_KEY"), (ip, "IP_ADDRESS")],
            )
        )
        _ = name
    return out
