"""Step 6: verify certificate chains against the STI-PA trust list.

The certificate input is one CSV with ``file_name`` and
``certificate_chain_pem`` columns.
"""

import re
import base64
import json
import subprocess
import tempfile
from datetime import timedelta
from pathlib import Path
import pandas as pd
from cryptography import x509

INPUT_CERTIFICATE_CHAINS_CSV = "<INPUT_CERTIFICATE_CHAINS_CSV>"
INPUT_CA_LIST_JWT = "<INPUT_CA_TRUST_LIST_JWT>"
OUTPUT_CSV = "<OUTPUT_CHAIN_VALIDATION_CSV>"


def trust_list(jwt_path):
    """Decode the STI-PA CA-list JWT and return its PEM trust anchors."""
    _, payload64, _ = Path(jwt_path).read_text().strip().split(".")
    payload64 += "=" * (-len(payload64) % 4)
    return json.loads(base64.urlsafe_b64decode(payload64))["trustList"]


def validate(file_name, chain_text, ca_certificates):
    blocks = re.findall(
        r"-----BEGIN CERTIFICATE-----.+?-----END CERTIFICATE-----",
        chain_text, re.S,
    )
    if not blocks:
        return {"general_cert_name": file_name, "chain_length": 0,
                "verification_result": "FAIL", "fail_reason": "No PEM certificates found"}
    leaf = x509.load_pem_x509_certificate(blocks[0].encode())
    row = {
        "general_cert_name": file_name,
        "chain_length": len(blocks), "leaf_not_before": leaf.not_valid_before_utc,
        "leaf_not_after": leaf.not_valid_after_utc, "leaf_serial_number": hex(leaf.serial_number).lower(),
        "leaf_issuer": leaf.issuer.rfc4514_string(), "leaf_subject": leaf.subject.rfc4514_string(),
    }
    with tempfile.TemporaryDirectory() as temporary:
        leaf_path = Path(temporary) / "leaf.pem"
        intermediate_path = Path(temporary) / "intermediates.pem"
        ca_path = Path(temporary) / "ca_bundle.pem"
        leaf_path.write_text(blocks[0] + "\n")
        ca_path.write_text("\n".join(item.strip() for item in ca_certificates) + "\n")
        command = ["openssl", "verify", "-CAfile", str(ca_path), "-attime",
                   str(int((leaf.not_valid_after_utc - timedelta(days=1)).timestamp()))]
        if len(blocks) > 1:
            intermediate_path.write_text("\n".join(blocks[1:]) + "\n")
            command += ["-untrusted", str(intermediate_path)]
        result = subprocess.run(command + [str(leaf_path)], capture_output=True, text=True, timeout=30)
    output = (result.stdout or result.stderr).strip()
    row["verification_result"] = "PASS" if result.returncode == 0 else "FAIL"
    row["fail_reason"] = None if result.returncode == 0 else output.splitlines()[-1]
    return row


anchors = trust_list(INPUT_CA_LIST_JWT)
chains = pd.read_csv(INPUT_CERTIFICATE_CHAINS_CSV)
results = [validate(row.file_name, row.certificate_chain_pem, anchors)
           for row in chains.itertuples(index=False)]
pd.DataFrame(results).to_csv(OUTPUT_CSV, index=False)
