# PKCS#11 RSA-OAEP Migration

## Problem

RSA-PKCS#1 v1.5 padding is vulnerable to Bleichenbacher padding oracle attacks (CVE-1998-0888). This implementation adds RSA-OAEP support with automatic fallback for existing volumes.

## Usage

### Check for legacy padding

```bash
systemd-cryptsetup-check-padding /dev/sda2

# Check all LUKS devices
for dev in $(lsblk -nrpo NAME,FSTYPE | awk '$2=="crypto_LUKS" {print $1}'); do
    systemd-cryptsetup-check-padding "$dev" 2>/dev/null
done
```

### Migrate to OAEP

```bash
systemd-cryptenroll --migrate-to-oaep /dev/sda2
```

Updates token metadata field `pkcs11-key-algorithm` from `rsa-pkcs1-v1.5` to `rsa-oaep-sha256`.

### Verify

```bash
cryptsetup luksDump /dev/sda2 | grep -A5 "systemd-pkcs11"
```

## Implementation

### Encryption (new enrollments)
- Algorithm: RSA-OAEP
- Hash: SHA-256
- MGF: MGF1-SHA256
- Label: empty

### Decryption (existing volumes)
1. Try CKM_RSA_PKCS_OAEP mechanism
2. Fallback to CKM_RSA_PKCS on failure
3. Emit deprecation warning on legacy use

### Token metadata
- Field: `pkcs11-key-algorithm`
- Values: `rsa-oaep-sha256` or `rsa-pkcs1-v1.5`

## Batch Migration

```bash
#!/bin/bash
for device in $(lsblk -nrpo NAME,TYPE | awk '$2=="crypt" {print $1}'); do
    if systemd-cryptsetup-check-padding "$device" 2>&1 | grep -q "legacy"; then
        systemd-cryptenroll --migrate-to-oaep "$device"
    fi
done
```

## See Also

- CVE-1998-0888 (Bleichenbacher attack)
- RFC 8017 Section 7.1 (RSAES-OAEP)
- systemd-cryptenroll(1)