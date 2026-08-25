"""Step 4: validate PASSporT formatting and consistency with SIP metadata."""

import re
from urllib.parse import urlparse
import numpy as np
import pandas as pd

INPUT_CSV = "<INPUT_JWT_FIELDS_CSV>"
OUTPUT_CSV = "<OUTPUT_JWT_VALIDATION_CSV>"


def uuid_result(value):
    if not isinstance(value, str):
        return "format"
    compact = value.replace("-", "").lower()
    if not re.fullmatch(r"[0-9a-f]{32}", compact):
        return "format"
    if compact[16] not in "89ab":
        return "variant"
    if compact[12] not in "12345678":
        return "version"
    return "valid"


def last10(series):
    return series.astype(str).str[-10:]


df = pd.read_csv(INPUT_CSV).rename(columns={"date": "timestamp"})
for column in ["called_number", "calling_number", "PAID"]:
    df[column] = df[column].astype(str).str.replace(r"\.0$", "", regex=True)
df["PAID"] = df["PAID"].replace([r"^\s*$", r"^\s*nan\s*$", r"^\s*none\s*$"], np.nan, regex=True)

df["frmt_uuid_inval_reason"] = df["jwt_pl_origid"].apply(uuid_result)
df["frmt_uuid"] = (df["frmt_uuid_inval_reason"] == "valid").astype(int)
df["frmt_infra_to_e164"] = df["called_number"].astype(str).str.match(r"^1\d{10}$").astype(int)
df["frmt_infra_to_match"] = (last10(df["called_number"]) == last10(df["jwt_pl_dest"])).astype(int)
df["frmt_infra_from_match"] = (last10(df["calling_number"]) == last10(df["jwt_pl_orig"])).astype(int)
df["frmt_infra_PAID_match"] = (df["PAID"].isna() | (last10(df["PAID"]) == last10(df["jwt_pl_orig"]))).astype(int)
df["frmt_infra_PAID_from_match"] = (df["PAID"].isna() | (last10(df["PAID"]) == last10(df["calling_number"]))).astype(int)
df["frmt_infra_cert_url_match"] = (df["id_url"].astype(str) == df["jwt_hdr_x5u"].astype(str)).astype(int)
df["frmt_infra_attest_match"] = (df["Attestation_Level"].astype(str) == df["jwt_pl_attest"].astype(str)).astype(int)
df["frmt_infra_alg_match"] = (df["id_algo"].astype(str) == df["jwt_hdr_alg"].astype(str)).astype(int)
df["frmt_infra_ppt_shaken"] = (df["id_ppt"] == "shaken").astype(int)
df["frmt_infra_typ_pass"] = (df["jwt_hdr_typ"] == "passport").astype(int)
def valid_x5u_scheme(value):
    """Return -1 for missing, 0 for invalid, and 1 for HTTPS on 443/8443."""
    if not isinstance(value, str) or not value:
        return -1
    try:
        parsed = urlparse(value)
        return int(parsed.scheme == "https" and (parsed.port or 443) in (443, 8443))
    except ValueError:
        return 0


df["frmt_infra_x5u_scheme"] = df["jwt_hdr_x5u"].apply(valid_x5u_scheme)

df["jwt_pl_iat"] = pd.to_datetime(df["jwt_pl_iat"], unit="s", utc=True).dt.tz_convert("US/Eastern")
df["timestamp"] = pd.to_datetime(df["timestamp"])
if df["timestamp"].dt.tz is None:
    df["timestamp"] = df["timestamp"].dt.tz_localize(
        "US/Eastern", ambiguous="NaT", nonexistent="NaT"
    )
else:
    df["timestamp"] = df["timestamp"].dt.tz_convert("US/Eastern")
df["time_diff_s"] = (df["timestamp"] - df["jwt_pl_iat"]).dt.total_seconds()
df["time_diff_m"] = df["time_diff_s"] / 60
minutes = df["time_diff_m"]
df["time_diff_bracket"] = np.select(
    [minutes < -60, (minutes >= -60) & (minutes < -1),
     (minutes >= -1) & (minutes <= 0), (minutes > 0) & (minutes <= 10),
     (minutes > 10) & (minutes <= 20), minutes > 20],
    ["a: < -60", "b: -60 to -1", "c: -1 to 0", "d: 1 to 10",
     "e: 10 to 20", "f: > 20"], default="NA",
)
df.to_csv(OUTPUT_CSV, index=False)
