# PKCS#11 RSA-OAEP Migration Guide

## Background

Starting with systemd v257, PKCS#11 encrypted volumes use RSA-OAEP padding instead of the legacy RSA-PKCS#1 v1.5 padding. This change addresses the Bleichenbacher padding oracle vulnerability (CVE-1998-0888) that affects RSA-PKCS#1 v1.5.

## Timeline

- **v257**: RSA-OAEP becomes default for new enrollments, automatic fallback for existing volumes
- **v258**: Migration tools available, deprecation warnings enabled
- **v259**: Stronger deprecation warnings, automatic migration prompts
- **v260**: Legacy RSA-PKCS#1 v1.5 support removed

## Security Impact

RSA-PKCS#1 v1.5 padding is vulnerable to padding oracle attacks where an attacker with access to a decryption oracle can recover the plaintext. RSA-OAEP provides provable security against these attacks.

## Migration Steps

### Check Current Status

Check if your volumes need migration:

```bash
# Check specific device
systemd-cryptsetup-check-padding /dev/mapper/myvolume

# Check all LUKS volumes
for dev in /dev/mapper/*; do
    systemd-cryptsetup-check-padding "$dev" 2>/dev/null
done
```

### Migrate Volumes

Migrate a single volume:

```bash
# Migrate specific device
sudo systemd-cryptenroll --migrate-to-oaep /dev/sda2

# The command will:
# 1. Scan all PKCS#11 tokens in the LUKS header
# 2. Update their metadata to indicate RSA-OAEP
# 3. Report migration status
```

### Enable Automatic Checking

Enable the check service for a volume:

```bash
# Enable for specific volume
sudo systemctl enable systemd-cryptsetup-check-padding@myvolume.service

# The service will run at boot and warn about legacy padding
```

### Verify Migration

After migration, verify the status:

```bash
# List tokens with their algorithms
cryptsetup luksDump /dev/sda2 | grep -A5 "systemd-pkcs11"

# Check for warnings during unlock
journalctl -u systemd-cryptsetup@myvolume -p warning
```

## Backward Compatibility

- **v257+**: Automatic fallback ensures existing volumes continue working
- **Migration is non-destructive**: Original keys remain valid
- **Performance impact**: Minimal (one extra decryption attempt for legacy keys)

## Troubleshooting

### Migration Fails

If migration fails:

1. Ensure you have write access to the LUKS header
2. Check that the device is not in use
3. Verify PKCS#11 tokens are accessible

### Volume Won't Unlock After Migration

This should not happen, but if it does:

1. Boot with systemd v257+ (has automatic fallback)
2. Check token metadata: `cryptsetup luksDump /dev/device`
3. Report issue with debug logs: `SYSTEMD_LOG_LEVEL=debug systemd-cryptsetup`

### Performance Degradation

If you notice slower unlock times:

1. Complete migration to eliminate fallback attempts
2. Check PKCS#11 token connectivity
3. Verify token performance with: `pkcs11-tool --test`

## Technical Details

### What Changes

- **Encryption**: Now uses RSA-OAEP with SHA-256 and empty label
- **Token Metadata**: New field `pkcs11-key-algorithm` indicates padding type
- **Decryption**: Tries OAEP first, falls back to PKCS#1 v1.5 if needed

### What Doesn't Change

- Key material remains the same
- PKCS#11 URI unchanged
- Token PINs unchanged
- Slot assignments unchanged

## For System Administrators

### Mass Migration Script

```bash
#!/bin/bash
# Migrate all LUKS devices with PKCS#11 tokens

for device in $(lsblk -nrpo NAME,TYPE | awk '$2=="crypt" {print $1}'); do
    echo "Checking $device..."
    if systemd-cryptsetup-check-padding "$device" 2>&1 | grep -q "legacy"; then
        echo "Migrating $device..."
        systemd-cryptenroll --migrate-to-oaep "$device"
    fi
done
```

### Monitoring

Add to monitoring systems:

```bash
# Nagios/Icinga check
check_pkcs11_padding() {
    local device=$1
    if systemd-cryptsetup-check-padding "$device" 2>&1 | grep -q "legacy"; then
        echo "WARNING: $device uses legacy PKCS#11 padding"
        return 1
    fi
    echo "OK: $device uses secure padding"
    return 0
}
```

## References

- [CVE-1998-0888](https://nvd.nist.gov/vuln/detail/CVE-1998-0888): Original Bleichenbacher attack
- [RFC 8017](https://tools.ietf.org/html/rfc8017): PKCS #1 v2.2 specification
- [systemd-cryptenroll(1)](https://www.freedesktop.org/software/systemd/man/systemd-cryptenroll.html): Manual page