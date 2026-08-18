#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

# shellcheck source=test/units/util.sh
. "$(dirname "$0")"/util.sh

STATE=/var/lib/TEST-95-PCRLOCK-SB
IMAGE="$STATE/pcrlock.img"
KEY_FILE="$STATE/pcrlock.key"
POLICY_DIR=/var/lib/pcrlock.d/240-secureboot-policy.pcrlock.d
AUTHORITY_DIR=/var/lib/pcrlock.d/620-secureboot-authority.pcrlock.d
SECUREBOOT_SEPARATOR_DIR=/etc/pcrlock.d/400-secureboot-separator.pcrlock.d
SEPARATOR_DIR=/etc/pcrlock.d/500-separator.pcrlock.d
KEK_VARIABLE=/sys/firmware/efi/efivars/KEK-8be4df61-93ca-11d2-aa0d-00e098032b8c
DB_VARIABLE=/sys/firmware/efi/efivars/db-d719b2cb-3d3a-4596-a3bc-dad00e67656f
DBX_VARIABLE=/sys/firmware/efi/efivars/dbx-d719b2cb-3d3a-4596-a3bc-dad00e67656f
FIRMWARE_EVENT_LOG=/sys/kernel/security/tpm0/binary_bios_measurements
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

if [[ ! -e "$FIRMWARE_EVENT_LOG" ]]; then
    echo "TPM firmware event log not found, skipping."
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

install_separator_error_overrides() {
    mkdir -p "$SECUREBOOT_SEPARATOR_DIR" "$SEPARATOR_DIR"
    ln -sfn /dev/null "$SECUREBOOT_SEPARATOR_DIR/600-0xffffffff.pcrlock"
    ln -sfn /dev/null "$SEPARATOR_DIR/600-0xffffffff.pcrlock"
}

remove_separator_error_overrides() {
    rm -f "$SECUREBOOT_SEPARATOR_DIR/600-0xffffffff.pcrlock"
    rm -f "$SEPARATOR_DIR/600-0xffffffff.pcrlock"
    rmdir "$SECUREBOOT_SEPARATOR_DIR" 2>/dev/null || :
    rmdir "$SEPARATOR_DIR" 2>/dev/null || :
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
        rm -f "$POLICY_DIR"/generated-prediction-*.pcrlock
        rm -f "$AUTHORITY_DIR"/generated-prediction-*.pcrlock
    fi
    if [[ -e "$STATE/pcrlock-mutating" ]]; then
        /usr/lib/systemd/systemd-pcrlock remove-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
    fi

    remove_separator_error_overrides
    restore_masks
    rm -rf "$STATE"
    exit "$rc"
}

trap cleanup_on_failure EXIT

unlock_volume() {
    systemd-cryptsetup attach "$VOLUME" "$IMAGE" - "tpm2-device=auto,tpm2-pcrlock=/var/lib/systemd/pcrlock.json,headless"
    systemd-cryptsetup detach "$VOLUME"
}

apply_efi_update() {
    local auth="${2:?}" attributes immutable=no name="${3:?}" rc=0 variable="${1:?}"

    if [[ -e "$variable" ]]; then
        attributes="$(lsattr -d "$variable")"
        if [[ "${attributes%% *}" == *i* ]]; then
            chattr -i "$variable"
            immutable=yes
        fi
    fi

    efi-updatevar -a -f "$auth" "$name" || rc=$?

    if [[ "$immutable" == yes ]]; then
        chattr +i "$variable"
    fi
    return "$rc"
}

assert_invalid_update_data() {
    local output parameters="${1:?}"

    output="$(varlinkctl --json=short --graceful=org.varlink.service.InvalidParameter \
                         call /run/systemd/io.systemd.PCRLock \
                         io.systemd.PCRLock.NotifySecureBootUpdate \
                         "$parameters" 2>&1)"
    grep 'returned expected error: org.varlink.service.InvalidParameter' <<<"$output" >/dev/null
    grep '"parameter":"data"' <<<"$output" >/dev/null
}

assert_update_not_applied() {
    local parameters="${1:?}"

    if varlinkctl call /run/systemd/io.systemd.PCRLock \
                   io.systemd.PCRLock.NotifySecureBootUpdate \
                   "$parameters"; then
        echo "Pre-write Secure Boot update notification unexpectedly succeeded" >&2
        return 1
    fi

    varlinkctl --graceful=io.systemd.PCRLock.UpdateNotApplied \
               call /run/systemd/io.systemd.PCRLock \
               io.systemd.PCRLock.NotifySecureBootUpdate \
               "$parameters"
}

notify_secure_boot_update() {
    local parameters="${1:?}"

    varlinkctl call /run/systemd/io.systemd.PCRLock \
               io.systemd.PCRLock.NotifySecureBootUpdate \
               "$parameters"
}

assert_policy_pins_pcr7() {
    jq --exit-status 'any(.pcrValues[]?; .pcr == 7)' /var/lib/systemd/pcrlock.json
}

assert_policy_omits_pcr7() {
    jq --exit-status 'all(.pcrValues[]?; .pcr != 7)' /var/lib/systemd/pcrlock.json
}

assert_bounded_pcr7_outcomes() {
    local prediction

    prediction="$(/usr/lib/systemd/systemd-pcrlock predict --pcr=7 --json=short)"
    jq --exit-status \
         '.sha256 | length == 1 and .[0].pcr == 7 and ((.[0].values | length) >= 1 and (.[0].values | length) <= 8)' \
       <<<"$prediction"
}

assert_prediction_matches() {
    local actual="${1:?}"
    local directory="${2:?}"
    local candidate

    for candidate in "$directory"/*.pcrlock; do
        [[ -e "$candidate" ]] || continue
        if jq --exit-status --slurp '
            ([.[0].records[].digests[].hashAlg] | unique) as $actual_algs |
            ([.[1].records[].digests[].hashAlg] | unique) as $candidate_algs |
            ([$actual_algs[] | select(. as $alg | $candidate_algs | index($alg))]) as $common_algs |
            def normalize:
                [.records[] | {
                    pcr,
                    digests: [.digests[] | select(.hashAlg as $alg | $common_algs | index($alg))] |
                        sort_by(.hashAlg)
                }];
            (.[0] | normalize) as $actual_records |
            (.[1] | normalize) as $candidate_records |
            ($common_algs | length) > 0 and
                ($actual_records | all(.digests | length > 0)) and
                ($candidate_records | all(.digests | length > 0)) and
                $actual_records == $candidate_records
        ' "$actual" "$candidate" >/dev/null; then
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

        # Collapse separator alternatives so authority prediction can use the remaining PCR outcome budget.
        install_separator_error_overrides
        if /usr/lib/systemd/systemd-pcrlock list-components --pcr=7 --no-pager | \
                grep '600-0xffffffff\.pcrlock' >/dev/null; then
            echo "Secure Boot separator error variant was not masked" >&2
            exit 1
        fi

        touch "$STATE/pcrlock-mutating"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        cp "$POLICY_DIR/generated.pcrlock" "$POLICY_DIR/systemd-test.pcrlock"
        cp "$AUTHORITY_DIR/generated.pcrlock" "$AUTHORITY_DIR/systemd-test.pcrlock"
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        test ! -e "$POLICY_DIR/generated.pcrlock"
        test -e "$POLICY_DIR/systemd-test.pcrlock"
        test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        test -e "$AUTHORITY_DIR/systemd-test.pcrlock"
        rm "$POLICY_DIR/systemd-test.pcrlock" "$AUTHORITY_DIR/systemd-test.pcrlock"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        current_db_authorities="$(
            /usr/lib/systemd/systemd-pcrlock log --pcr=7 --json=short | \
                jq '[.log[] | select((.description // "") | startswith("Authority: db-"))] | length'
        )"
        current_authorities="$(jq '.records | length' "$AUTHORITY_DIR/generated.pcrlock")"
        expected_authority_predictions="$((current_authorities + current_db_authorities + 1))"
        planned_pcr7_combinations="$(
            /usr/lib/systemd/systemd-pcrlock list-components --pcr=7 --json=short | \
                jq --argjson authority_predictions "$expected_authority_predictions" '
                    map(select(.variants | split("/")[-1] | startswith("generated-prediction-") | not)) |
                    group_by(.id) |
                    map(
                        if .[0].id == "240-secureboot-policy" then length + 1
                        elif .[0].id == "620-secureboot-authority" then length + $authority_predictions
                        else length
                        end
                    ) |
                    reduce .[] as $variants (1; . * $variants)
                '
        )"
        cp "$AUTHORITY_DIR/generated.pcrlock" "$STATE/authority-before-outcome-fallback.pcrlock"
        if ((planned_pcr7_combinations > 8)); then
            touch "$STATE/authority-budget-fallback"
        fi
        assert_bounded_pcr7_outcomes
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
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
                    -subj=/CN=TEST-95-PCRLOCK-SB-addon/ \
                    -keyout "$STATE/addon.key" -out "$STATE/addon.crt"
        cert-to-efi-sig-list -g 70a4cb5e-9e92-4bb8-86f9-8aee0f3d70db \
                             "$STATE/addon.crt" "$STATE/db.esl"
        sign-efi-sig-list -a -c /usr/share/mkosi.crt -k /usr/share/mkosi.key \
                           db "$STATE/db.esl" "$STATE/db.auth"
        sign-efi-sig-list -a -c /usr/share/mkosi.crt -k /usr/share/mkosi.key \
                   KEK "$STATE/db.esl" "$STATE/kek.auth"

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

        assert_update_not_applied '{"variable":"kek"}'
        authenticated_update="$(base64 --wrap=0 "$STATE/db.auth")"
        assert_update_not_applied "{\"variable\":\"db\",\"data\":\"$authenticated_update\"}"
        touch "$STATE/update-mutating"
        apply_efi_update "$DB_VARIABLE" "$STATE/db.auth" db

        policy_checksum="$(sha256sum /var/lib/systemd/pcrlock.json)"
        notify_secure_boot_update \
            "{\"variable\":\"db\",\"data\":\"$authenticated_update\",\"regenerate\":false}"
        test -f "$POLICY_DIR/generated.pcrlock"
        compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock" >/dev/null
        if [[ -e "$STATE/authority-budget-fallback" ]]; then
            test ! -e "$AUTHORITY_DIR/generated.pcrlock"
            if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
                echo "Authority prediction survived preflight outcome-count fallback" >&2
                exit 1
            fi
        else
            assert_bounded_pcr7_outcomes
            test -f "$AUTHORITY_DIR/generated.pcrlock"
            compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null
        fi
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" = "$policy_checksum"

        mkdir "$STATE/components-before-invalid"
        cp -a "$POLICY_DIR" "$STATE/components-before-invalid/policy"
        cp -a "$AUTHORITY_DIR" "$STATE/components-before-invalid/authority"
        assert_invalid_update_data '{"variable":"db","data":"%%%"}'
        head -c 32 "$STATE/db.auth" >"$STATE/db-truncated.auth"
        truncated_update="$(base64 --wrap=0 "$STATE/db-truncated.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$truncated_update\"}"
        python3 - "$STATE/db.auth" "$STATE/db.esl" "$STATE/db-malformed-list.auth" <<'PY'
import struct
import sys

auth = bytearray(open(sys.argv[1], "rb").read())
esl = open(sys.argv[2], "rb").read()
payload_offset = len(auth) - len(esl)
assert auth[payload_offset:] == esl
struct.pack_into("<I", auth, payload_offset + 16, len(esl) + 1)
open(sys.argv[3], "wb").write(auth)
PY
        malformed_list_update="$(base64 --wrap=0 "$STATE/db-malformed-list.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$malformed_list_update\"}"
        diff -r "$STATE/components-before-invalid/policy" "$POLICY_DIR"
        diff -r "$STATE/components-before-invalid/authority" "$AUTHORITY_DIR"
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" = "$policy_checksum"
        unlock_volume

        if [[ ! -e "$STATE/authority-budget-fallback" ]]; then
            remove_separator_error_overrides
            notify_secure_boot_update \
                "{\"variable\":\"db\",\"data\":\"$authenticated_update\"}"
            assert_policy_omits_pcr7
            test -f "$POLICY_DIR/generated.pcrlock"
            compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock" >/dev/null
            test ! -e "$AUTHORITY_DIR/generated.pcrlock"
            if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
                echo "Authority prediction survived outcome-count fallback" >&2
                exit 1
            fi
            unlock_volume
        fi

        install_separator_error_overrides
        mkdir -p "$AUTHORITY_DIR"
        cp "$STATE/authority-before-outcome-fallback.pcrlock" "$AUTHORITY_DIR/generated.pcrlock"

        notify_secure_boot_update \
            "{\"variable\":\"db\",\"data\":\"$authenticated_update\"}"
        if [[ -e "$STATE/authority-budget-fallback" ]]; then
            assert_policy_omits_pcr7
        else
            assert_policy_pins_pcr7
            assert_bounded_pcr7_outcomes
        fi

        # A policy-only update must preserve either the db authority variants or their preflight fallback.
        apply_efi_update "$KEK_VARIABLE" "$STATE/kek.auth" KEK
        notify_secure_boot_update '{"variable":"kek"}'
        if [[ -e "$STATE/authority-budget-fallback" ]]; then
            assert_policy_omits_pcr7
        else
            assert_policy_pins_pcr7
            assert_bounded_pcr7_outcomes
        fi

        # The policy component must have a prediction, and the authority component must either fit or fall back.
        test -f "$POLICY_DIR/generated.pcrlock"
        mapfile -t policy_predictions < <(compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock")
        ((${#policy_predictions[@]} == 1))
        cp "${policy_predictions[@]}" "$STATE/predicted-policy/"
        if [[ -e "$STATE/authority-budget-fallback" ]]; then
            test ! -e "$AUTHORITY_DIR/generated.pcrlock"
            if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
                echo "Authority prediction survived preflight outcome-count fallback" >&2
                exit 1
            fi
        else
            test -f "$AUTHORITY_DIR/generated.pcrlock"
            mapfile -t authority_predictions < <(compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock")
            ((${#authority_predictions[@]} == expected_authority_predictions))
            cp "${authority_predictions[@]}" "$STATE/predicted-authority/"
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

        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        assert_prediction_matches "$POLICY_DIR/generated.pcrlock" "$STATE/predicted-policy"
        if [[ -e "$STATE/authority-budget-fallback" ]]; then
            test -z "$(find "$STATE/predicted-authority" -mindepth 1 -print -quit)"
        else
            assert_prediction_matches "$AUTHORITY_DIR/generated.pcrlock" "$STATE/predicted-authority"
        fi

        expected_authority="$(<"$STATE/authority.sha256")"
        jq --exit-status --arg digest "$expected_authority" \
           'any(.records[].digests[]; .hashAlg == "sha256" and .digest == $digest)' \
           "$AUTHORITY_DIR/generated.pcrlock"

        duplicate_update="$(base64 --wrap=0 "$STATE/db.auth")"
        notify_secure_boot_update "{\"variable\":\"db\",\"data\":\"$duplicate_update\"}"
        assert_policy_pins_pcr7
        test -f "$AUTHORITY_DIR/generated.pcrlock"
        if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Duplicate db entry unexpectedly created an authority prediction" >&2
            exit 1
        fi
        unlock_volume

        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        notify_secure_boot_update "{\"variable\":\"db\",\"data\":\"$duplicate_update\"}"
        assert_policy_omits_pcr7
        test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Inactive Secure Boot authority component was unexpectedly enabled" >&2
            exit 1
        fi
        unlock_volume

        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7

        # Regenerating the components above must remove previous-boot prediction variants and leave the
        # refreshed policy unlockable.
        if compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Stale systemd Secure Boot policy variants remain" >&2
            exit 1
        fi
        if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Stale systemd Secure Boot authority variants remain" >&2
            exit 1
        fi
        unlock_volume

        hash-to-efi-sig-list "$STATE/test.addon.efi" "$STATE/dbx.esl"
        sign-efi-sig-list -a -c /usr/share/mkosi.crt -k /usr/share/mkosi.key \
                           dbx "$STATE/dbx.esl" "$STATE/dbx.auth"
        dbx_update="$(base64 --wrap=0 "$STATE/dbx.auth")"
        apply_efi_update "$DBX_VARIABLE" "$STATE/dbx.auth" dbx

        mkdir "$STATE/components-before-rollback"
        cp -a "$POLICY_DIR" "$STATE/components-before-rollback/policy"
        cp -a "$AUTHORITY_DIR" "$STATE/components-before-rollback/authority"
        mv /var/lib/systemd/pcrlock.json "$STATE/pcrlock-before-rollback.json"
        mkdir /var/lib/systemd/pcrlock.json
        if varlinkctl call /run/systemd/io.systemd.PCRLock \
                       io.systemd.PCRLock.NotifySecureBootUpdate \
                       "{\"variable\":\"dbx\",\"data\":\"$dbx_update\"}"; then
            rmdir /var/lib/systemd/pcrlock.json
            mv "$STATE/pcrlock-before-rollback.json" /var/lib/systemd/pcrlock.json
            echo "dbx update unexpectedly succeeded with an invalid policy path" >&2
            exit 1
        fi
        rmdir /var/lib/systemd/pcrlock.json
        mv "$STATE/pcrlock-before-rollback.json" /var/lib/systemd/pcrlock.json
        diff -r "$STATE/components-before-rollback/policy" "$POLICY_DIR"
        diff -r "$STATE/components-before-rollback/authority" "$AUTHORITY_DIR"
        if compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Policy prediction survived a failed update" >&2
            exit 1
        fi
        if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "Authority prediction survived a failed update" >&2
            exit 1
        fi
        test -d /run/systemd/pcrlock-secureboot-update
        test -n "$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -print -quit)"

        notify_secure_boot_update "{\"variable\":\"dbx\",\"data\":\"$dbx_update\"}"
        assert_policy_omits_pcr7
        if [[ -d /run/systemd/pcrlock-secureboot-update ]]; then
            test -z "$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -print -quit)"
        fi
        test -f "$POLICY_DIR/generated.pcrlock"
        mapfile -t dbx_policy_predictions < <(compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock")
        ((${#dbx_policy_predictions[@]} == 1))
        mkdir "$STATE/predicted-policy-dbx"
        cp "${dbx_policy_predictions[@]}" "$STATE/predicted-policy-dbx/"
        test ! -e "$AUTHORITY_DIR/generated.pcrlock"
        if compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null; then
            echo "dbx update unexpectedly created an authority prediction" >&2
            exit 1
        fi
        unlock_volume

        touch "$STATE/dbx-prepared"
        systemctl_final reboot
        trap - EXIT
        exec sleep infinity
        ;;

    2)
        test -e "$STATE/dbx-prepared"

        unlock_volume
        ! grep pcrlock-secureboot-update-addon /proc/cmdline >/dev/null

        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        assert_prediction_matches "$POLICY_DIR/generated.pcrlock" "$STATE/predicted-policy-dbx"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
        unlock_volume

        esp="$(bootctl --print-esp-path)"
        install -m 0644 "$STATE/original.addon.efi" "$esp/loader/addons/test.addon.efi"
        remove_separator_error_overrides
        restore_masks
        /usr/lib/systemd/systemd-pcrlock remove-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-policy
        /usr/lib/systemd/systemd-pcrlock unlock-secureboot-authority
        rm -rf "$STATE"

        touch /testok
        ;;

    *)
        assert_not_reached
        ;;
esac
