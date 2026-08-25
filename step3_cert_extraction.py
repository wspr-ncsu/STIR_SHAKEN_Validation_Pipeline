"""Step 3: flatten X.509 fields from one certificate table.

The input is one CSV with ``file_name`` and ``certificate_pem`` columns. A PEM
cell may contain a leaf followed by its chain; field extraction uses the first
(leaf) certificate, matching the original one-row-per-downloaded-file logic.
"""

import ast
import json
import re
from pathlib import Path
import pandas as pd
from asn1crypto import pem, x509

INPUT_CERTIFICATES_CSV = "<INPUT_CERTIFICATES_CSV>"
OUTPUT_CSV = "<OUTPUT_CERTIFICATE_FIELDS_CSV>"


def csv_safe(value):
    return json.dumps(value, sort_keys=True, default=str) if isinstance(value, (dict, list)) else value


def sanitize(value):
    return "".join(char if char.isalnum() or char in "._-" else "_" for char in value)


def flatten(value, prefix="", output=None):
    output = {} if output is None else output
    if isinstance(value, dict):
        for key, child in value.items():
            if child is not None:
                flatten(child, f"{prefix}.{key}" if prefix else str(key), output)
    elif isinstance(value, list):
        output[prefix] = csv_safe(value)
    else:
        output[prefix] = csv_safe(value)
    return output


def extension_prefix(extension):
    name = extension["extn_id"].native
    if not isinstance(name, str) or all(char.isdigit() or char == "." for char in name):
        name = f"oid_{extension['extn_id'].dotted}"
    return sanitize(f"tbs_certificate.extensions.{name}")


def flatten_certificate(certificate):
    row = {}
    try:
        row["signature_value"] = certificate["signature_value"].native.hex()
    except Exception:
        row["signature_value"] = csv_safe(certificate["signature_value"].native)
    tbs = dict(certificate["tbs_certificate"].native)
    tbs.pop("extensions", None)
    flatten(tbs, "tbs_certificate", row)
    extensions = certificate["tbs_certificate"]["extensions"]
    if extensions.native is not None:
        for extension in extensions:
            prefix = extension_prefix(extension)
            row[f"{prefix}.critical"] = bool(extension["critical"].native)
            row[f"{prefix}.extn_id.native"] = extension["extn_id"].native
            row[f"{prefix}.extn_id.dotted"] = extension["extn_id"].dotted
            try:
                value = extension["extn_value"].native
                if isinstance(value, dict):
                    flatten(value, f"{prefix}.extn_value", row)
                else:
                    row[f"{prefix}.extn_value"] = csv_safe(value)
            except Exception:
                row[f"{prefix}.extn_value"] = extension["extn_value"].contents.hex()
    return {sanitize(key): value for key, value in row.items()}


def json_value(value):
    if pd.isna(value):
        return None
    try:
        return json.loads(value) if isinstance(value, str) else value
    except (TypeError, json.JSONDecodeError):
        return None


def has_crl_issuer(value):
    parsed = json_value(value)
    return isinstance(parsed, list) and any(
        isinstance(item, dict) and item.get("crl_issuer") is not None for item in parsed
    )


def first_policy(value):
    parsed = json_value(value)
    return parsed[0].get("policy_identifier", pd.NA) if (
        isinstance(parsed, list) and parsed and isinstance(parsed[0], dict)
    ) else pd.NA


def first_crl_url(value):
    parsed = json_value(value)
    if isinstance(parsed, list) and parsed and isinstance(parsed[0], dict):
        point = parsed[0].get("distribution_point")
        if isinstance(point, list) and point:
            return point[0]
    return pd.NA


def extract_spc(value):
    if pd.isna(value):
        return pd.NA
    if isinstance(value, str) and value.startswith(("b'", 'b"')):
        try:
            value = ast.literal_eval(value)
        except (ValueError, SyntaxError):
            return pd.NA
    if not isinstance(value, (bytes, bytearray)):
        return pd.NA
    try:
        position = bytes(value).index(0x16)
        length = value[position + 1]
        return bytes(value[position + 2:position + 2 + length]).decode("ascii")
    except (ValueError, IndexError, UnicodeDecodeError):
        return pd.NA


rows = []
certificates = pd.read_csv(INPUT_CERTIFICATES_CSV)
for record in certificates.itertuples(index=False):
    raw = record.certificate_pem.encode()
    blocks = re.findall(b"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", raw, re.S)
    block = blocks[0] if blocks else raw
    der = pem.unarmor(block)[2] if pem.detect(block) else block
    row = flatten_certificate(x509.Certificate.load(der, strict=False))
    row["file_name"] = record.file_name
    rows.append(row)

df = pd.DataFrame(rows)
crl_value = "tbs_certificate.extensions.crl_distribution_points.extn_value"
df["ext_crl_dp_issuer"] = df[crl_value].apply(has_crl_issuer)
df.columns = df.columns.str.replace(r"^tbs_certificate\.", "", regex=True)
df.columns = df.columns.str.replace(r"^extensions\.", "ext_", regex=True)
df.columns = df.columns.str.replace(r"^subject_public_key_info\.", "sub_pk_", regex=True)
df["ext_cert_policy"] = df["ext_certificate_policies.extn_value"].apply(first_policy)
df["ext_crl_dp"] = df["ext_crl_distribution_points.extn_value"].apply(first_crl_url)
df["ext_spc_tnauthlist"] = df["ext_oid_1.3.6.1.5.5.7.1.26.extn_value"].apply(extract_spc)

df.rename(columns={
    "signature.algorithm": "CA_sign_algo", "signature_value": "CA_sign_value",
    "issuer.country_name": "issuer_cn", "issuer.organization_name": "issuer_org",
    "validity.not_before": "validity_nb", "validity.not_after": "validity_na",
    "subject.country_name": "subject_cn", "subject.state_or_province_name": "subject_st",
    "subject.organization_name": "subject_ou", "sub_pk_algorithm.algorithm": "sub_pk_algo",
    "sub_pk_algorithm.parameters": "sub_pk_params", "sub_pk_public_key": "sub_pk_value",
    "ext_authority_key_identifier.critical": "ext_aki_critical",
    "ext_authority_key_identifier.extn_value.key_identifier": "ext_aki",
    "ext_key_identifier.critical": "ext_ski_critical", "ext_key_identifier.extn_value": "ext_ski",
    "ext_key_usage.critical": "ext_key_usage_critical", "ext_key_usage.extn_value": "ext_key_usage_value",
    "ext_certificate_policies.critical": "ext_cert_policies_critical",
    "ext_crl_distribution_points.critical": "ext_crl_dp_critical",
    "ext_oid_1.3.6.1.5.5.7.1.26.critical": "spc_critical",
    "ext_basic_constraints.critical": "ext_bconstraint_critical",
    "ext_basic_constraints.extn_value.ca": "ext_bconstraint_CA",
    "issuer.state_or_province_name": "issuer_st",
}, inplace=True)
df.drop(columns=[
    "ext_crl_distribution_points.extn_value", "ext_certificate_policies.extn_value",
    "ext_oid_1.3.6.1.5.5.7.1.26.extn_value",
], errors="ignore").to_csv(OUTPUT_CSV, index=False)
