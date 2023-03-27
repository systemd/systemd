#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck disable=SC2016
set -eux
set -o pipefail

# shellcheck source=test/units/assert.sh
. "$(dirname "$0")"/assert.sh

: >/failed

EXPECTED_KEY_LENGTH=59

LOOP_DEV=$(losetup --find --show "$(mktemp)")
trap "losetup -d $LOOP_DEV" EXIT

echo -n "password" | cryptsetup luksFormat --type luks2 --cipher aes-xts-plain64 --key-size 512 --hash sha256 --iter-time 2000 --use-random --batch-mode "$LOOP_DEV"

echo -n "password" | cryptsetup open "$LOOP_DEV" test-volume

systemd-cryptenroll --recovery-key test-volume

ENCRYPTED_KEY=$(sudo systemctl show-environment | grep CRYPTENROLL_KEY | cut -d= -f2-)
RECOVERY_KEY=$(sudo systemctl show-environment | grep CRYPTENROLL_RECOVERY_KEY | cut -d= -f2-)
NORMALIZED_KEY=$(normalize_recovery_key "$RECOVERY_KEY")

assert_eq "${#NORMALIZED_KEY}" "$EXPECTED_KEY_LENGTH"

NEW_RECOVERY_KEY=$(make_recovery_key)
assert_not_in "$NEW_RECOVERY_KEY" "RECOVERY_KEY"

modhex_alphabet="cbdefghijklnrtuv"
for (( i=0; i<16; i++ )); do
    char=$(echo "${modhex_alphabet:$i:1}")
    result=$(decode_modhex_char "${char}")
    assert_eq "${result}" "${i}"
done

RANDOM_BYTES=$(systemd-random-util --bytes=32 --hex)
assert_eq "${#RANDOM_BYTES}" "64"  # 32 bytes in hexadecimal should have 64 characters

sudo cryptsetup close test-volume
losetup -d "$LOOP_DEV"

touch /testok
rm /failed
