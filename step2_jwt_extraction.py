"""Step 2: extract PASSporT/JWT fields from one metadata table."""

import base64
import json
import numpy as np
import pandas as pd

INPUT_CSV = "<INPUT_METADATA_CSV>"
OUTPUT_CSV = "<OUTPUT_JWT_FIELDS_CSV>"


def decode_json(value):
    value += "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value))


def nested_number(value, claim):
    node = value.get(claim, {}) if isinstance(value, dict) else {}
    number = node.get("tn") if isinstance(node, dict) else None
    return number[0] if isinstance(number, list) and number else number


def csv_safe(value):
    """Preserve nested claims as deterministic JSON rather than Python repr."""
    return json.dumps(value, sort_keys=True) if isinstance(value, (dict, list)) else value


df = pd.read_csv(INPUT_CSV)
df = df[df["Identity"].notna()].copy()
for column in ["called_number", "calling_number", "PAID"]:
    df[column] = df[column].astype(str).str.replace(r"\.0$", "", regex=True)
df["PAID"] = df["PAID"].replace(
    [r"^\s*$", r"^\s*nan\s*$", r"^\s*none\s*$"], np.nan, regex=True
)
df["timestamp"] = pd.to_datetime(df["timestamp"], errors="coerce")
df["Identity"] = df["Identity"].str.replace(r"^Identity:\s*", "", regex=True)
df["id_url"] = df["Identity"].str.extract(r"info=<([^>]+)>", expand=False)
df["id_algo"] = df["Identity"].str.extract(r"alg=([^;,\n]+)", expand=False)
df["id_ppt"] = df["Identity"].str.extract(r"ppt=([^;,\n]+)", expand=False)

parts = df["Identity"].str.split(";").str[0].str.split(".", expand=True)
df[["jwt_header", "jwt_payload", "jwt_signature"]] = parts.iloc[:, :3]
df["jwt_header_decoded"] = df["jwt_header"].apply(decode_json)
df["jwt_payload_decoded"] = df["jwt_payload"].apply(decode_json)

for claim in ["alg", "ppt", "typ", "x5u", "kid", "issuer"]:
    df[f"jwt_hdr_{claim}"] = df["jwt_header_decoded"].map(
        lambda value, key=claim: csv_safe(value.get(key)) if isinstance(value, dict) else pd.NA
    )
df["jwt_pl_orig"] = df["jwt_payload_decoded"].map(lambda value: nested_number(value, "orig"))
df["jwt_pl_dest"] = df["jwt_payload_decoded"].map(lambda value: nested_number(value, "dest"))
for claim in ["origid", "iat", "ppt", "x5u", "exp", "crn", "attest", "rcdi", "rcd"]:
    df[f"jwt_pl_{claim}"] = df["jwt_payload_decoded"].map(
        lambda value, key=claim: csv_safe(value.get(key)) if isinstance(value, dict) else pd.NA
    )

df.drop(columns=["SIP_Call_ID", "error"], errors="ignore").to_csv(OUTPUT_CSV, index=False)
