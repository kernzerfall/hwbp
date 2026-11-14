Pinned Android Key Attestation roots, matched by SubjectPublicKeyInfo.
Every `*.der` file in this directory is embedded at build time.

Source: https://android.googleapis.com/attestation/root

| File | Key | SPKI SHA-256 |
|---|---|---|
| `google-p384-ca1.der` | 384-bit EC | `3ee44512a1af2beb39c889490c60ea3f82e43f5d5a5532f5ab9419f676cd07ec` |
| `google-rsa4096.der` | 4096-bit RSA | `feb2ea7551ee316ed4bb443c8293b884dbfdea40b603ee3e4f4a897e4580fbae` |

To add a root, drop its DER certificate here and update this table. Do it deliberately: pinning only means something if roots are reviewed.
