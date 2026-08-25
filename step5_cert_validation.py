"""Step 5: compute certificate-format checks from extracted certificate fields."""

import ast
import hashlib
import pandas as pd

INPUT_CSV = "<INPUT_CERTIFICATE_FIELDS_CSV>"
OUTPUT_CSV = "<OUTPUT_CERTIFICATE_VALIDATION_CSV>"

APPROVED_CRL_URLS = {
    "https://authenticate-api.iconectiv.com/download/v1/crl": "USA",
    "https://authenticate-ext-api.iconectiv.com/download/v1/crl": "USA",
    "https://api.man-bpco.fr/crl": "FRANCE",
    "https://stipa-cstga.ccid.neustar/api/v1/crl": "CA",
}
APPROVED_CERTIFICATE_POLICIES = {
    "2.16.840.1.114569.1.1.1", "2.16.840.1.114569.1.1.2",
    "2.16.840.1.114569.1.1.3", "2.16.840.1.114569.1.1.4",
}


def byte_value(value):
    if isinstance(value, bytes):
        return value
    if not isinstance(value, str):
        return None
    try:
        return ast.literal_eval(value) if value.startswith(("b'", 'b"')) else bytes.fromhex(value)
    except (ValueError, SyntaxError):
        return None


df = pd.read_csv(INPUT_CSV)
issuer = df["issuer_org"].replace("", pd.NA).fillna(df["issuer.common_name"])
df["u_cert_id"] = issuer.astype(str) + "_" + df["serial_number"].astype(str)
df["cc_version_3"] = (df["version"].astype(str).str.lower().isin(["v3", "3"])).astype(int)
df = df.rename(columns={
    "ext_bconstraint_critical": "cc_bcons_CA_critical",
    "ext_key_usage_critical": "cc_ext_ku_critical",
    "ext_crl_dp_critical": "cc_ext_crldp_critical",
    "ext_crl_dp_issuer": "cc_ext_crldp_issuer",
})
df["cc_bcons_CA"] = df["ext_bconstraint_CA"].astype("Int64")
df["cc_sub_cn_format"] = (
    df["subject.common_name"].str.strip() == "SHAKEN " + df["ext_spc_tnauthlist"].astype(str)
).astype(int)
df["valid_day_count"] = (pd.to_datetime(df["validity_na"]) - pd.to_datetime(df["validity_nb"])).dt.days
df["cc_validity_bracket"] = pd.cut(
    df["valid_day_count"], [0, 31, 90, 365, 370, 1000, float("inf")],
    labels=["0-31", "31-90", "90-365", "365-370", "370-1000", "1000+"], right=False,
)
df["cc_ski_hash_check"] = df.apply(
    lambda row: byte_value(row["sub_pk_value"]) is not None
    and byte_value(row["ext_ski"]) == hashlib.sha1(byte_value(row["sub_pk_value"])).digest(), axis=1
)
df["cc_ski_matches_aki"] = df["ext_ski"] == df["ext_aki"]
df["cc_ext_ku"] = df["ext_key_usage_value"] == "{'digital_signature'}"
df["cc_ext_crl_dp"] = df["ext_crl_dp"].isin(APPROVED_CRL_URLS)
df["cc_crl_dp_cn"] = df["ext_crl_dp"].map(APPROVED_CRL_URLS)
df["cc_ext_cert_policy"] = df["ext_cert_policy"].isin(APPROVED_CERTIFICATE_POLICIES).astype(int)
df.drop(columns=["issuer.organizational_unit_name"], errors="ignore").rename(
    columns={"subject_ou": "subject_org"}
).to_csv(OUTPUT_CSV, index=False)
