# PKCS#11 RSA-OAEP Support

## Overview

systemd now uses RSA-OAEP (Optimal Asymmetric Encryption Padding) instead of
RSA-PKCS#1 v1.5 for NEW PKCS#11 token enrollments. RSA-PKCS#1 v1.5 is vulnerable
to Bleichenbacher padding oracle attacks (CVE-1998-0888).

## For New Enrollments

All new PKCS#11 enrollments automatically use secure RSA-OAEP with SHA-256:

```bash
systemd-cryptenroll --pkcs11-uri=pkcs11:... /dev/sdaX
```

## For Existing Volumes

Existing LUKS volumes with PKCS#11 tokens continue to work via automatic
fallback to legacy RSA-PKCS#1 v1.5 padding. You will see a deprecation warning
during boot.

### To Secure Existing Volumes

Re-enroll your PKCS#11 token to use secure OAEP padding:

```bash
# 1. Check current slots
cryptsetup luksDump /dev/sdaX

# 2. Remove old vulnerable token (replace X with actual slot number)
systemd-cryptenroll --wipe-slot=X /dev/sdaX

# 3. Enroll new secure token
systemd-cryptenroll --pkcs11-uri=pkcs11:... /dev/sdaX
```

This creates a NEW token encrypted with secure RSA-OAEP padding.

**Important:** Re-enrollment requires your PKCS#11 token to be present and
accessible. Backup your LUKS header and recovery keys before proceeding.

## Technical Details

### Encryption (New Enrollments)
- **Algorithm:** RSA-OAEP
- **Hash:** SHA-256
- **MGF:** MGF1-SHA256
- **Label:** Empty string

### Decryption (All Volumes)
The decryption process tries mechanisms in order:
1. CKM_RSA_PKCS_OAEP (SHA-256, MGF1-SHA256, empty label)
2. CKM_RSA_PKCS (PKCS#1 v1.5 fallback for legacy volumes)

If decryption succeeds with legacy padding, a deprecation warning is logged.

### Token Metadata

LUKS2 tokens include a `pkcs11-key-algorithm` field:
- **`rsa-oaep-sha256`:** New secure tokens
- **`rsa-pkcs1-v1.5`:** Legacy vulnerable tokens (or field missing)

**Note:** This field is informational only. The actual security depends on
which mechanism successfully decrypts the data, not the metadata value.

## Security Considerations

- **New tokens:** Secure against padding oracle attacks
- **Old tokens:** Vulnerable to padding oracle attacks (CVE-1998-0888)
- **Backward compatibility:** Old tokens continue to work but are deprecated
- **Upgrade path:** Re-enrollment required to gain security benefits

## See Also

- CVE-1998-0888 (Bleichenbacher attack on RSA PKCS#1 v1.5)
- RFC 8017 Section 7.1 (RSAES-OAEP)
- systemd-cryptenroll(1)
- cryptsetup(8)
