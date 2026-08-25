"""Step 1: download the certificate referenced by one SIP INVITE."""

import base64
import csv
import json
import re
import time
from pathlib import Path
from urllib.request import Request, urlopen

INPUT_INVITE = "<INPUT_SIP_INVITE>"
OUTPUT_CERTIFICATE = "<OUTPUT_CERTIFICATE_PEM>"
OUTPUT_METADATA_CSV = "<OUTPUT_CERTIFICATE_METADATA_CSV>"


def sip_headers(message):
    headers = {}
    for line in message.replace("\r\n", "\n").split("\n")[1:]:
        if not line:
            break
        if ":" in line:
            name, value = line.split(":", 1)
            headers[name.lower()] = value.strip()
    return headers


invite = Path(INPUT_INVITE).read_text(encoding="utf-8")
headers = sip_headers(invite)
identity = headers["identity"]
token = identity.split(";", 1)[0]
encoded_header = token.split(".")[0]
encoded_header += "=" * (-len(encoded_header) % 4)
passport_header = json.loads(base64.urlsafe_b64decode(encoded_header))
x5u = passport_header["x5u"]
if not re.match(r"^https://", x5u, re.I):
    raise ValueError("The PASSporT x5u value must use HTTPS")
with urlopen(Request(x5u, headers={"User-Agent": "stir-shaken-artifact/1.0"}), timeout=10) as response:
    Path(OUTPUT_CERTIFICATE).write_bytes(response.read())


def telephone_number(value):
    match = re.search(r"sip:(\+?\d+)@", value or "", re.I)
    return match.group(1) if match else None


payload64 = token.split(".")[1] + "=" * (-len(token.split(".")[1]) % 4)
payload = json.loads(base64.urlsafe_b64decode(payload64))
asserted_identity = headers.get("p-asserted-identity", "")
verstat = re.search(r"verstat=([\w-]+)", asserted_identity)
row = {
    "timestamp": time.strftime("%Y-%m-%d %H:%M:%S"),
    "calling_number": telephone_number(headers.get("from")),
    "called_number": telephone_number(headers.get("to")),
    "SIP_Call_ID": headers.get("call-id", "").split("@", 1)[0],
    "custom_certificate_name": Path(OUTPUT_CERTIFICATE).name,
    "Original_cert_URL": x5u,
    "Verification_status": verstat.group(1) if verstat else None,
    "Attestation_Level": headers.get("p-attestation-indicator") or payload.get("attest"),
    "Identity": identity,
    "error": "None",
}
with open(OUTPUT_METADATA_CSV, "w", newline="", encoding="utf-8") as output:
    writer = csv.DictWriter(output, fieldnames=row)
    writer.writeheader()
    writer.writerow(row)
