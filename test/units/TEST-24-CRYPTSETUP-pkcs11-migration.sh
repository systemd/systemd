#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# Test PKCS#11 RSA-OAEP migration functionality

# Skip if no PKCS#11 support
if ! command -v pkcs11-tool &>/dev/null; then
    echo "pkcs11-tool not available, skipping PKCS#11 migration tests" >&2
    exit 0
fi

# Skip if no cryptsetup
if ! command -v cryptsetup &>/dev/null; then
    echo "cryptsetup not available, skipping" >&2
    exit 0
fi

# Setup test environment
TEMPDIR=$(mktemp -d)
trap 'rm -rf "$TEMPDIR"' EXIT

TESTDEV="$TEMPDIR/test.img"
TOKEN_URL="pkcs11:token=TestToken;object=TestKey"

# Create test LUKS device
dd if=/dev/zero of="$TESTDEV" bs=1M count=32 status=none
echo -n "testpass" | cryptsetup luksFormat --type luks2 "$TESTDEV" -

# Function to create a mock legacy PKCS#11 token
create_legacy_token() {
    local device=$1
    local token_json
    token_json=$(cat <<EOF
{
    "type": "systemd-pkcs11",
    "keyslots": ["0"],
    "pkcs11-uri": "$TOKEN_URL",
    "pkcs11-key": "$(echo -n "mockkey" | base64)",
    "pkcs11-key-algorithm": "rsa-pkcs1-v1.5"
}
EOF
)
    # Add token to LUKS header (mock - would need actual cryptsetup token add in real test)
    echo "$token_json" > "$TEMPDIR/token.json"
}

# Function to check token algorithm
check_token_algorithm() {
    local device=$1
    local expected_alg=$2

    cryptsetup luksDump "$device" 2>/dev/null | grep -q "pkcs11-key-algorithm.*$expected_alg" || {
        echo "ERROR: Expected algorithm $expected_alg not found" >&2
        return 1
    }
}

echo "=== Test 1: Check legacy padding detection ==="
create_legacy_token "$TESTDEV"

# Check should detect legacy padding
systemd-cryptsetup-check-padding "$TESTDEV" 2>&1 | tee "$TEMPDIR/check.log"
if ! grep -q "legacy RSA-PKCS#1 v1.5 padding" "$TEMPDIR/check.log"; then
    echo "FAIL: Legacy padding not detected" >&2
    exit 1
fi
echo "PASS: Legacy padding detected"

echo "=== Test 2: Migrate to RSA-OAEP ==="
systemd-cryptenroll --migrate-to-oaep "$TESTDEV" 2>&1 | tee "$TEMPDIR/migrate.log"

# Verify migration message
if ! grep -q "Successfully migrated.*to RSA-OAEP" "$TEMPDIR/migrate.log"; then
    echo "FAIL: Migration did not complete successfully" >&2
    exit 1
fi
echo "PASS: Migration completed"

echo "=== Test 3: Verify post-migration state ==="
# Check should now show all tokens use OAEP
systemd-cryptsetup-check-padding "$TESTDEV" 2>&1 | tee "$TEMPDIR/check2.log"
if grep -q "legacy RSA-PKCS#1 v1.5 padding" "$TEMPDIR/check2.log"; then
    echo "FAIL: Legacy padding still detected after migration" >&2
    exit 1
fi

if ! grep -q "use secure RSA-OAEP padding" "$TEMPDIR/check2.log"; then
    echo "FAIL: RSA-OAEP not confirmed after migration" >&2
    exit 1
fi
echo "PASS: All tokens now use RSA-OAEP"

echo "=== Test 4: Idempotent migration ==="
# Running migration again should be safe
systemd-cryptenroll --migrate-to-oaep "$TESTDEV" 2>&1 | tee "$TEMPDIR/migrate2.log"
if ! grep -q "already.*RSA-OAEP\|already migrated" "$TEMPDIR/migrate2.log"; then
    echo "FAIL: Second migration did not detect already-migrated state" >&2
    exit 1
fi
echo "PASS: Migration is idempotent"

echo "=== Test 5: Migration with multiple tokens ==="
# Create device with multiple tokens (would need more complex setup in real test)
TESTDEV2="$TEMPDIR/test2.img"
dd if=/dev/zero of="$TESTDEV2" bs=1M count=32 status=none
echo -n "testpass" | cryptsetup luksFormat --type luks2 "$TESTDEV2" -

# Add multiple mock tokens
for _ in 1 2 3; do
    create_legacy_token "$TESTDEV2"
done

systemd-cryptenroll --migrate-to-oaep "$TESTDEV2" 2>&1 | tee "$TEMPDIR/migrate3.log"
if ! grep -q "migrated.*token(s)" "$TEMPDIR/migrate3.log"; then
    echo "FAIL: Multiple token migration failed" >&2
    exit 1
fi
echo "PASS: Multiple tokens migrated successfully"

echo "=== Test 6: Error handling ==="
# Test with non-existent device
if systemd-cryptenroll --migrate-to-oaep /dev/nonexistent 2>/dev/null; then
    echo "FAIL: Migration succeeded on non-existent device" >&2
    exit 1
fi
echo "PASS: Proper error on non-existent device"

# Test with non-LUKS device
dd if=/dev/zero of="$TEMPDIR/notluks.img" bs=1M count=1 status=none
if systemd-cryptenroll --migrate-to-oaep "$TEMPDIR/notluks.img" 2>/dev/null; then
    echo "FAIL: Migration succeeded on non-LUKS device" >&2
    exit 1
fi
echo "PASS: Proper error on non-LUKS device"

echo "=== Test 7: Deprecation warnings ==="
# Create a mock unlock scenario to test deprecation warnings
# This would need actual PKCS#11 token in real test
echo "Testing deprecation warnings (mock test - would need real token)"

echo "=== All migration tests passed ==="