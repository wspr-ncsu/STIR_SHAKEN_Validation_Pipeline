"""Step 7: time, revocation, and PASSporT signature validation.

The single input CSV is the prepared join of call/JWT data, chain-validation
results, and certificate fields. This replaces the original multi-file merge.
"""

import ast
import base64
import json
import pandas as pd
from cryptography import x509
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

INPUT_CSV = "<INPUT_PREPARED_VALIDATION_CSV>"
INPUT_CRL = "<INPUT_CRL_PEM>"
OUTPUT_CSV = "<OUTPUT_CRYPTO_VALIDATION_CSV>"


def b64decode(value):
    value = str(value).strip() + "=" * (-len(str(value).strip()) % 4)
    return base64.urlsafe_b64decode(value)


def public_key_bytes(value):
    text = str(value).strip()
    return ast.literal_eval(text) if text.startswith(("b'", 'b"')) else bytes.fromhex(text.replace(":", ""))


def verify_passport(identity, encoded_key):
    try:
        token = str(identity).replace("Identity: ", "", 1).split(";", 1)[0]
        header64, payload64, signature64 = token.split(".")
        algorithm = json.loads(b64decode(header64))["alg"].upper()
        params = {"ES256": (ec.SECP256R1(), hashes.SHA256(), 32),
                  "ES384": (ec.SECP384R1(), hashes.SHA384(), 48),
                  "ES512": (ec.SECP521R1(), hashes.SHA512(), 66)}
        curve, digest, width = params[algorithm]
        key = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key_bytes(encoded_key))
        raw = b64decode(signature64)
        if len(raw) != width * 2:
            return False, f"Invalid signature length: {len(raw)}, expected {width * 2}"
        signature = encode_dss_signature(int.from_bytes(raw[:width], "big"), int.from_bytes(raw[width:], "big"))
        key.verify(signature, f"{header64}.{payload64}".encode(), ec.ECDSA(digest))
        return True, None
    except InvalidSignature:
        return False, "Signature verification failed"
    except Exception as error:
        return False, str(error)


df = pd.read_csv(INPUT_CSV)
call_time = pd.to_datetime(df["timestamp"], errors="coerce", utc=True)
not_before = pd.to_datetime(df["leaf_not_before"], errors="coerce", utc=True)
not_after = pd.to_datetime(df["leaf_not_after"], errors="coerce", utc=True)
buffer = pd.Timedelta(days=1)
df["cert_validity_status"] = "valid"
df.loc[not_before.isna() | not_after.isna(), "cert_validity_status"] = "cert_time_missing"
df.loc[call_time.isna(), "cert_validity_status"] = "call_time_missing"
df.loc[call_time < not_before - buffer, "cert_validity_status"] = "not_yet_valid"
df.loc[call_time > not_after + buffer, "cert_validity_status"] = "expired"
df.loc[df["cert_validity_status"].isin(["expired", "not_yet_valid"]), "verification_result"] = "FAIL"
df.loc[df["cert_validity_status"] == "expired", "fail_reason"] = "cert_expired"
df.loc[df["cert_validity_status"] == "not_yet_valid", "fail_reason"] = "cert_not_yet_valid"
df["cert_expired_diff"] = (call_time - not_after).dt.total_seconds().where(
    df["cert_validity_status"] == "expired"
) / 86400
df["cert_not_before_diff"] = (not_before - call_time).dt.total_seconds().where(
    df["cert_validity_status"] == "not_yet_valid"
) / 86400

crl = x509.load_pem_x509_crl(open(INPUT_CRL, "rb").read())
revocations = {format(item.serial_number, "x").lstrip("0"): pd.to_datetime(item.revocation_date_utc, utc=True) for item in crl}
serial = df["leaf_serial_number"].astype(str).str.lower().str.replace("0x", "", regex=False).str.lstrip("0")
revoked_at = serial.map(revocations)
df["revoked_used_after_revocation"] = revoked_at.notna() & (call_time > revoked_at)
df.loc[df["revoked_used_after_revocation"], ["verification_result", "fail_reason"]] = ["FAIL", "revoked_used_after_revocation"]
df.rename(columns={"verification_result": "cert_verification_result"}, inplace=True)

mask = df["Identity"].notna() & df["sub_pk_value"].notna()
df[["jwt_sig_valid", "jwt_sig_error"]] = pd.NA
df.loc[mask, ["jwt_sig_valid", "jwt_sig_error"]] = df.loc[mask].apply(
    lambda row: pd.Series(verify_passport(row["Identity"], row["sub_pk_value"])), axis=1
).values
df.to_csv(OUTPUT_CSV, index=False)
