"""Step 8: combine individual checks into in-house validation outcomes."""

import pandas as pd

INPUT_CSV = "<INPUT_CRYPTO_VALIDATION_CSV>"
OUTPUT_CSV = "<OUTPUT_FINAL_VALIDATION_CSV>"

df = pd.read_csv(INPUT_CSV)
buckets = [
    "validation_format_issue_jwt_sip", "validation_format_issue_cert",
    "validation_crypto_error", "validation_logical_error",
]
df[buckets] = 0

for column in ["frmt_infra_to_e164", "frmt_infra_cert_url_match", "frmt_infra_ppt_shaken",
               "frmt_infra_typ_pass", "frmt_infra_x5u_scheme", "frmt_uuid"]:
    df.loc[df[column].notna() & (df[column] != 1), "validation_format_issue_jwt_sip"] = 1
for column in ["frmt_infra_to_match", "frmt_infra_from_match", "frmt_infra_PAID_match",
               "frmt_infra_PAID_from_match", "frmt_infra_attest_match"]:
    df.loc[df[column].notna() & (df[column] != 1), "validation_logical_error"] = 1

df.loc[df["issuer.common_name"].isna() & df["ext_aki"].isna(), "validation_logical_error"] = 1
df.loc[df["time_diff_m"].notna() & ~df["time_diff_m"].between(-15, 15), "validation_logical_error"] = 1

for column in ["cc_ext_crldp_issuer", "cc_ski_hash_check", "cc_ext_ku", "cc_ext_crl_dp"]:
    df.loc[df[column].notna() & (df[column] != True), "validation_format_issue_cert"] = 1
for column in ["cc_version_3", "cc_sub_cn_format", "cc_ext_cert_policy"]:
    df.loc[df[column].notna() & (df[column] != 1), "validation_format_issue_cert"] = 1
df.loc[df["cc_bcons_CA"].notna() & (df["cc_bcons_CA"] != 0), "validation_format_issue_cert"] = 1
df.loc[df["jwt_sig_valid"].notna() & (df["jwt_sig_valid"] != True), "validation_crypto_error"] = 1
df.loc[df["cert_verification_result"].notna() & (df["cert_verification_result"] != "PASS"), "validation_crypto_error"] = 1

# Map validator-specific failure labels when present.
if "shakenfailed" in df:
    failure = df["shakenfailed"].astype("string")
    df.loc[failure.isin({"CERT URLS MISMATCH", "FROM PREFIX", "JWT MISSING ATTEST", "JWT MISSING IAT", "TO PREFIX"}), "validation_format_issue_jwt_sip"] = 1
    df.loc[failure.isin({"PEM EXPIRED", "PEM INVALID", "PEM PARSE ERROR", "PEM REVOKED", "PEM REVOKED (intermediate)", "VERIFICATION FAILED"}) | failure.str.startswith("PEM NOT FOUND", na=False), "validation_crypto_error"] = 1
    df.loc[failure.isin({"FROM", "PEM IAT CONFLICT", "TIME FUTURE", "TO"}) | failure.str.startswith("TIME ", na=False), "validation_logical_error"] = 1

df["validation_result_inhouse"] = df[buckets].eq(1).any(axis=1).astype(int)
df["verification_status_inhouse"] = "No-TN-Validation"
df.loc[(df["validation_format_issue_cert"] == 1) | (df["validation_crypto_error"] == 1), "verification_status_inhouse"] = "TN-Validation-Failed"
df.loc[(df["validation_result_inhouse"] == 0) & (df["Attestation_Level"] == "A"), "verification_status_inhouse"] = "TN-Validation-Passed"

# The original SSL-error override used a second metadata file. In the public
# version the source error column is expected in the single prepared input.
if "error" in df:
    ssl_error = df["error"].astype("string").str.startswith("SSL Error", na=False)
    df.loc[ssl_error, "verification_status_inhouse"] = "TN-Validation-Failed"
    df.loc[ssl_error, "fail_reason"] = "ssl_disabled"

df.to_csv(OUTPUT_CSV, index=False)

