#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

STATE=/var/lib/TEST-70-TPM2-pcrlock-secureboot-update
IMAGE="$STATE/pcrlock.img"
KEY_FILE="$STATE/pcrlock.key"
POLICY_DIR=/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d
AUTHORITY_DIR=/var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d
DB_VARIABLE=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
VOLUME=pcrlock-secureboot-update

if ! test -x /usr/lib/systemd/systemd-pcrlock; then
    echo "systemd-pcrlock not found, skipping."
    exit 77
fi

if ! command -v bootctl >/dev/null; then
    echo "bootctl not found, skipping."
    exit 77
fi

if ! command -v efi-updatevar >/dev/null; then
    echo "efi-updatevar not found, skipping."
    exit 77
fi

if [[ ! -d /usr/lib/systemd/boot/efi ]]; then
    echo "sd-boot is not installed, skipping."
    exit 77
fi

if ! cmp /sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c <(printf '\6\0\0\0\1'); then
    echo "secure boot not enabled, skipping."
    exit 77
fi

if systemd-detect-virt -cq; then
    echo "running in a container, skipping."
    exit 77
fi

mask_for_reboot() {
    local state unit="${1:?}"

    systemctl cat "$unit" >/dev/null 2>&1 || return 0
    state="$(systemctl is-enabled "$unit" 2>/dev/null || :)"
    if [[ "$state" != masked* ]]; then
        systemctl mask "$unit"
        touch "$STATE/masked-$unit"
    fi
}

restore_masks() {
    local marker unit

    for marker in "$STATE"/masked-*; do
        [[ -e "$marker" ]] || continue
        unit="${marker##*/masked-}"
        systemctl unmask "$unit"
    done
    systemctl daemon-reload
}

cleanup_on_failure() {
    local rc=$? esp

    trap - EXIT
    ((rc != 0)) || exit 0

    set +e
    echo "Test failed, cleaning up persistent pcrlock Secure Boot update test state" >&2

    if [[ ! -d "$STATE" ]]; then
        exit "$rc"
    fi

    systemd-cryptsetup detach "$VOLUME"

    if [[ -f "$STATE/original.addon.efi" ]]; then
        esp="$(bootctl --print-esp-path 2>/dev/null)"
        if [[ -n "$esp" ]]; then
            install -m 0644 "$STATE/original.addon.efi" "$esp/loader/addons/test.addon.efi"
        fi
    fi

    if [[ -e "$STATE/update-mutating" ]]; then
        rm -f "$POLICY_DIR"/systemd-*.pcrlock
        rm -f "$AUTHORITY_DIR"/systemd-*.pcrlock
    fi
    if [[ -e "$STATE/pcrlock-mutating" ]]; then
        /usr/lib/systemd/systemd-pcrlock remove-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
    fi

    restore_masks
    rm -rf "$STATE"
    exit "$rc"
}

trap cleanup_on_failure EXIT

unlock_volume() {
    systemd-cryptsetup attach "$VOLUME" "$IMAGE" - "tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless"
    systemd-cryptsetup detach "$VOLUME"
}

normalize_pcrlock() {
    jq --sort-keys --compact-output \
       '{records: [.records[] | {pcr: .pcr, digests: [.digests[] | select(.hashAlg == "sha256")]}]}' \
       "${1:?}"
}

assert_prediction_matches() {
    local actual="${1:?}"
    local directory="${2:?}"
    local actual_json candidate

    actual_json="$(normalize_pcrlock "$actual")"
    for candidate in "$directory"/*.pcrlock; do
        [[ -e "$candidate" ]] || continue
        if [[ "$(normalize_pcrlock "$candidate")" == "$actual_json" ]]; then
            return 0
        fi
    done

    echo "No prediction in $directory matches $actual" >&2
    return 1
}

case "${REBOOT_COUNT:-0}" in
    0)
        esp="$(bootctl --print-esp-path)"
        addon="$esp/loader/addons/test.addon.efi"
        test -f "$addon"

        mkdir -p "$STATE/predicted-policy" "$STATE/predicted-authority"
        cp "$addon" "$STATE/original.addon.efi"

        mask_for_reboot systemd-pcrlock-secureboot-policy.service
        mask_for_reboot systemd-pcrlock-secureboot-authority.service
        mask_for_reboot systemd-pcrlock-make-policy.service

        touch "$STATE/pcrlock-mutating"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        cp "$POLICY_DIR/generated.pcrlock" "$POLICY_DIR/systemd-test.pcrlock"
        cp "$AUTHORITY_DIR/generated.pcrlock" "$AUTHORITY_DIR/systemd-test.pcrlock"
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        test ! -e "$POLICY_DIR/generated.pcrlock"
        test ! -e "$POLICY_DIR/systemd-test.pcrlock"
        test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        test ! -e "$AUTHORITY_DIR/systemd-test.pcrlock"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        systemctl start systemd-pcrlock.socket

        truncate -s 20M "$IMAGE"
        printf pcrlock-secureboot-update >"$KEY_FILE"
        chmod 0600 "$KEY_FILE"
        cryptsetup luksFormat --batch-mode --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom "$IMAGE" "$KEY_FILE"
        systemd-cryptenroll --unlock-key-file="$KEY_FILE" --tpm2-device=auto \
                           --tpm2-pcrlock=/var/lib/systemd/pcrlock.json --tpm2-public-key= \
                           --wipe-slot=tpm2 "$IMAGE"
        unlock_volume

        openssl req -new -x509 -newkey rsa:2048 -sha256 -nodes -days 3650 \
                    -subj=/CN=TEST-70-TPM2-pcrlock-secureboot-update-addon/ \
                    -keyout "$STATE/addon.key" -out "$STATE/addon.crt"
        cert-to-efi-sig-list -g 70a4cb5e-9e92-4bb8-86f9-8aee0f3d70db \
                             "$STATE/addon.crt" "$STATE/db.esl"
        sign-efi-sig-list -a -c /usr/share/mkosi.crt -k /usr/share/mkosi.key \
                           db "$STATE/db.esl" "$STATE/db.auth"

        python3 - "$STATE/db.esl" >"$STATE/authority.sha256" <<'PY'
import hashlib
import struct
import sys

esl = open(sys.argv[1], "rb").read()
list_size, header_size, signature_size = struct.unpack_from("<III", esl, 16)
assert list_size == len(esl)
entry_offset = 28 + header_size
entry = esl[entry_offset:entry_offset + signature_size]
database_guid = bytes.fromhex("cbb219d73a3d9645a3bcdad00e67656f")
event = database_guid + struct.pack("<QQ", 2, len(entry)) + "db".encode("utf-16-le") + entry
print(hashlib.sha256(event).hexdigest())
PY

        ukify build --cmdline=pcrlock-secureboot-update-addon \
                    --output="$STATE/test.addon.efi" \
                    --secureboot-certificate="$STATE/addon.crt" \
                    --secureboot-private-key="$STATE/addon.key"
        sbverify --cert "$STATE/addon.crt" "$STATE/test.addon.efi"
        ! sbverify --cert /usr/share/mkosi.crt "$STATE/test.addon.efi"

        authenticated_update="$(base64 --wrap=0 "$STATE/db.auth")"
        touch "$STATE/update-mutating"
        # efi-updatevar does not clear the immutable bit
        chattr -i "$DB_VARIABLE"
        efi-updatevar -a -f "$STATE/db.auth" db
        chattr +i "$DB_VARIABLE"
        varlinkctl call /run/systemd/io.systemd.PCRLock \
                   io.systemd.PCRLock.PrepareSecureBootUpdate \
                   "{\"variable\":\"db\",\"data\":\"$authenticated_update\"}"

        # The policy prediction must remain active. Authority prediction may instead fall back to
        # removing that component if the complete set would exceed the TPM's eight-outcome limit.
        test -f "$POLICY_DIR/generated.pcrlock"
        mapfile -t policy_predictions < <(compgen -G "$POLICY_DIR/systemd-*.pcrlock")
        mapfile -t authority_predictions < <(compgen -G "$AUTHORITY_DIR/systemd-*.pcrlock")
        ((${#policy_predictions[@]} > 0))
        cp "${policy_predictions[@]}" "$STATE/predicted-policy/"
        if [[ -f "$AUTHORITY_DIR/generated.pcrlock" ]]; then
            ((${#authority_predictions[@]} > 0))
            cp "${authority_predictions[@]}" "$STATE/predicted-authority/"
        else
            ((${#authority_predictions[@]} == 0))
            touch "$STATE/authority-fallback"
        fi

        # The resealed policy must retain the current path as well as the predicted next path.
        unlock_volume

        install -m 0644 "$STATE/test.addon.efi" "$addon"
        sync "$addon"
        touch "$STATE/prepared"

        systemctl_final reboot
        trap - EXIT
        exec sleep infinity
        ;;

    1)
        test -e "$STATE/prepared"

        # This is the key assertion: unlock with the policy prepared before the db and addon changed,
        # before regenerating any policy from the measurements of this boot.
        unlock_volume

        grep -q pcrlock-secureboot-update-addon /proc/cmdline
        bootctl status | grep test.addon.efi

        if [[ -e "$STATE/authority-fallback" ]]; then
            test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        fi
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        assert_prediction_matches "$POLICY_DIR/generated.pcrlock" "$STATE/predicted-policy"
        if [[ ! -e "$STATE/authority-fallback" ]]; then
            assert_prediction_matches "$AUTHORITY_DIR/generated.pcrlock" "$STATE/predicted-authority"
        fi

        expected_authority="$(<"$STATE/authority.sha256")"
        jq --exit-status --arg digest "$expected_authority" \
           'any(.records[].digests[]; .hashAlg == "sha256" and .digest == $digest)' \
           "$AUTHORITY_DIR/generated.pcrlock"

        duplicate_update="$(base64 --wrap=0 "$STATE/db.auth")"
        varlinkctl call /run/systemd/io.systemd.PCRLock \
                   io.systemd.PCRLock.PrepareSecureBootUpdate \
                   "{\"variable\":\"db\",\"data\":\"$duplicate_update\"}"
        if compgen -G "$AUTHORITY_DIR/systemd-*.pcrlock" >/dev/null; then
            echo "Duplicate db entry unexpectedly created an authority prediction" >&2
            exit 1
        fi
        unlock_volume

        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        varlinkctl call /run/systemd/io.systemd.PCRLock \
                   io.systemd.PCRLock.PrepareSecureBootUpdate \
                   "{\"variable\":\"db\",\"data\":\"$duplicate_update\"}"
        test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        if compgen -G "$AUTHORITY_DIR/systemd-*.pcrlock" >/dev/null; then
            echo "Inactive Secure Boot authority component was unexpectedly enabled" >&2
            exit 1
        fi
        unlock_volume

        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7

        # Regenerating the components above must remove previous-boot prediction variants and leave the
        # refreshed policy unlockable.
        if compgen -G "$POLICY_DIR/systemd-*.pcrlock" >/dev/null; then
            echo "Stale systemd Secure Boot policy variants remain" >&2
            exit 1
        fi
        if compgen -G "$AUTHORITY_DIR/systemd-*.pcrlock" >/dev/null; then
            echo "Stale systemd Secure Boot authority variants remain" >&2
            exit 1
        fi
        unlock_volume

        esp="$(bootctl --print-esp-path)"
        install -m 0644 "$STATE/original.addon.efi" "$esp/loader/addons/test.addon.efi"
        restore_masks
        /usr/lib/systemd/systemd-pcrlock remove-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        rm -rf "$STATE"
        ;;

    *)
        assert_not_reached
        ;;
esac
