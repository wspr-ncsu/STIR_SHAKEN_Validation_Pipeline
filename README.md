# STIR/SHAKEN measurement artifact

The scripts are numbered in execution order. Replace every path constant marked
`<...>` with a local input or output path. The scripts emphasize the analysis
logic used in the paper; they are not packaged as a turnkey pipeline.

Each table-processing step reads one CSV and writes one CSV. Where the original
notebooks combined several collections, that merge is represented by one
pre-combined input table.

The step 5 input contains one row per extracted certificate. It must retain the
original `file_name` and `source` fields and a `call_count` equal to the number
of metadata rows referencing that certificate. This replaces the original
source-specific certificate and mapping CSV reads.

The prepared step 7 input represents these original joins in one table:

- Call/JWT metadata is left-joined to chain-validation results using
  `custom_certificate_name`/`exact_cert_name` (or the already normalized
  `general_cert_name`).
- Source collections are appended row-wise.
- Certificate-format results are left-joined using normalized
  `general_cert_name`/`file_name` values (trimmed, lowercase, and without the
  `.pem` suffix).

Thus the public scripts retain the validation logic without requiring readers
to reconstruct the authors' source-specific directory layout.

1. `step1_ss_cert_downloader.py`: extract an x5u URL from one SIP INVITE and
   download its certificate.
2. `step2_jwt_extraction.py`: decode PASSporT headers and payloads.
3. `step3_cert_extraction.py`: flatten leaf X.509 fields from one CSV containing
   certificate filenames and PEM content.
4. `step4_jwt_validation.py`: compute PASSporT/SIP consistency checks.
5. `step5_cert_validation.py`: compute certificate-format checks.
6. `step6_crypto_val_cert_chain.py`: validate the chains in one CSV against the
   CA trust-list JWT.
7. `step7_crypto_val_time.py`: apply time, revocation, and JWT-signature checks
   to one prepared input table.
8. `step8_inhouse_validator.py`: combine checks into the paper's validation
   categories and final status.
