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
POLICY_MASK=/etc/pcrlock.d/240-secureboot-policy.pcrlock.d
AUTHORITY_MASK=/etc/pcrlock.d/620-secureboot-authority.pcrlock.d
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

mask_prediction_component() {
    local mask="${1:?}"

    [[ ! -e "$mask" && ! -L "$mask" ]]
    ln -s /dev/null "$mask"
}

unmask_prediction_components() {
    rm -f "$POLICY_MASK" "$AUTHORITY_MASK"
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

    unmask_prediction_components
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
    local output parameters="${1:--}"

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

generate_bounded_update_predictions() {
    local authenticated_update="${1:?}" candidate expected_outcomes="${2:?}"
    local -a authority_predictions bounded_authority_predictions policy_predictions

    rm -rf "$STATE/bounded-policy" "$STATE/bounded-authority"
    mkdir "$STATE/bounded-policy" "$STATE/bounded-authority"

    mask_prediction_component "$AUTHORITY_MASK"
    notify_secure_boot_update \
        "{\"variable\":\"db\",\"data\":\"$authenticated_update\",\"regenerate\":false}"
    mapfile -t policy_predictions < <(compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock")
    ((${#policy_predictions[@]} == 1))
    cp "${policy_predictions[@]}" "$STATE/bounded-policy/"

    unmask_prediction_components
    mask_prediction_component "$POLICY_MASK"
    notify_secure_boot_update \
        "{\"variable\":\"db\",\"data\":\"$authenticated_update\",\"regenerate\":false}"
    mapfile -t authority_predictions < <(compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock")
    ((${#authority_predictions[@]} == expected_authority_predictions))
    for candidate in "${authority_predictions[@]}"; do
        if jq --exit-status --argjson records "$((current_authorities + 1))" \
              '(.records | length) == $records' "$candidate" >/dev/null; then
            cp "$candidate" "$STATE/bounded-authority/"
        fi
    done
    mapfile -t bounded_authority_predictions < <(compgen -G "$STATE/bounded-authority/*.pcrlock")
    ((${#bounded_authority_predictions[@]} == expected_insertion_predictions))

    unmask_prediction_components
    rm -f "$POLICY_DIR"/generated-prediction-*.pcrlock
    rm -f "$AUTHORITY_DIR"/generated-prediction-*.pcrlock
    cp "$STATE/bounded-policy"/*.pcrlock "$POLICY_DIR/"
    cp "$STATE/bounded-authority"/*.pcrlock "$AUTHORITY_DIR/"

    assert_pcr7_outcome_count "$expected_outcomes"
}

remove_first_authority_insertion_prediction() {
    local candidate expected_authority prediction=

    expected_authority="$(<"$STATE/authority.sha256")"
    for candidate in "$AUTHORITY_DIR"/generated-prediction-*.pcrlock; do
        if jq --exit-status \
              --arg digest "$expected_authority" \
              --argjson records "$((current_authorities + 1))" \
              '(.records | length) == $records and
                  any(.records[0].digests[]?; .hashAlg == "sha256" and .digest == $digest)' \
              "$candidate" >/dev/null; then
            [[ -z "$prediction" ]]
            prediction="$candidate"
        fi
    done
    [[ -n "$prediction" ]]
    rm "$prediction"
}

assert_policy_pins_pcr7() {
    jq --exit-status 'any(.pcrValues[]?; .pcr == 7)' /var/lib/systemd/pcrlock.json
}

assert_policy_omits_pcr7() {
    jq --exit-status '(.pcrValues | length) > 0 and all(.pcrValues[]; .pcr != 7)' /var/lib/systemd/pcrlock.json
}

pcr7_outcome_count() {
    /usr/lib/systemd/systemd-pcrlock predict --pcr=7 --json=short | \
        jq --raw-output --exit-status '
            if (.sha256 | length) == 1 and .sha256[0].pcr == 7 and (.sha256[0].values | length) > 0 then
                .sha256[0].values | length
            else
                error("PCR 7 prediction has an unexpected shape")
            end
        '
}

assert_pcr7_outcome_count() {
    local expected="${1:?}"

    test "$(pcr7_outcome_count)" -eq "$expected"
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
        rm -f /testok

        esp="$(bootctl --print-esp-path)"
        addon="$esp/loader/addons/test.addon.efi"
        test -f "$addon"

        mkdir -p "$STATE/predicted-policy" "$STATE/predicted-authority"
        cp "$addon" "$STATE/original.addon.efi"

        mask_for_reboot systemd-pcrlock-secureboot-policy.service
        mask_for_reboot systemd-pcrlock-secureboot-authority.service
        mask_for_reboot systemd-pcrlock-make-policy.service

        # Collapse separator alternatives so each prediction phase fits the PCR outcome budget.
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
        authority_layout="$(
            /usr/lib/systemd/systemd-pcrlock log --pcr=7 --json=short | \
                jq --slurpfile authority "$AUTHORITY_DIR/generated.pcrlock" '
                    .log as $log |
                    [$log[] | select(.component == "620-secureboot-authority")] as $mapped |
                    $authority[0].records as $records |
                    (if ($mapped | length) != ($records | length) then
                        error("authority component does not map one-to-one to the event log")
                    else
                        [range(0; $records | length) as $i |
                            ([$records[$i].digests[] |
                                select(.hashAlg == "sha256") |
                                .digest
                            ] | first) as $digest |
                            if $mapped[$i].sha256 != $digest then
                                error("authority component order differs from the event log")
                            else
                                (($mapped[$i].description // "") | startswith("Authority: db-"))
                            end
                        ]
                    end) as $from_db |
                    {
                        current: ($records | length),
                        predictions: (($records | length) + 1 + ($from_db | map(select(.)) | length))
                    }
                '
        )"
        current_authorities="$(jq --raw-output '.current' <<<"$authority_layout")"
        ((current_authorities >= 1))
        expected_authority_predictions="$(jq --raw-output '.predictions' <<<"$authority_layout")"
        expected_insertion_predictions="$((current_authorities + 1))"
        cp "$AUTHORITY_DIR/generated.pcrlock" "$STATE/authority-before-outcome-fallback.pcrlock"
        baseline_pcr7_outcomes="$(pcr7_outcome_count)"
        ((baseline_pcr7_outcomes >= 1 && baseline_pcr7_outcomes <= 8))
        expected_predicted_pcr7_outcomes="$((baseline_pcr7_outcomes * 2 * (expected_insertion_predictions + 1)))"
        expected_reboot_authority_predictions="$((expected_insertion_predictions - 1))"
        expected_reboot_pcr7_outcomes="$((
            baseline_pcr7_outcomes * 2 * (expected_reboot_authority_predictions + 1)
        ))"
        ((expected_reboot_pcr7_outcomes <= 8))
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
        generate_bounded_update_predictions \
            "$authenticated_update" "$expected_predicted_pcr7_outcomes"
        test -f "$POLICY_DIR/generated.pcrlock"
        compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock" >/dev/null
        test -f "$AUTHORITY_DIR/generated.pcrlock"
        compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock" >/dev/null
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" = "$policy_checksum"

        mkdir "$STATE/components-before-invalid"
        cp -a "$POLICY_DIR" "$STATE/components-before-invalid/policy"
        cp -a "$AUTHORITY_DIR" "$STATE/components-before-invalid/authority"
        assert_invalid_update_data '{"variable":"db","data":"%%%"}'
        assert_invalid_update_data "{\"variable\":\"dbx\",\"data\":\"$authenticated_update\"}"
        bare_update="$(base64 --wrap=0 "$STATE/db.esl")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$bare_update\"}"
        python3 - "$STATE/db-oversized.json" "$STATE/db-encoded-oversized.json" <<'PY'
import base64
import json
import sys

for path, size in zip(sys.argv[1:], (1024 * 1024 + 1, 1024 * 1024 + 3)):
    with open(path, "w") as request:
        json.dump({"variable": "db", "data": base64.b64encode(bytes(size)).decode()}, request)
PY
        assert_invalid_update_data <"$STATE/db-oversized.json"
        assert_invalid_update_data <"$STATE/db-encoded-oversized.json"
        head -c 32 "$STATE/db.auth" >"$STATE/db-truncated.auth"
        truncated_update="$(base64 --wrap=0 "$STATE/db-truncated.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$truncated_update\"}"
        python3 - "$STATE/db.auth" "$STATE/db.esl" \
            "$STATE/db-malformed-list.auth" "$STATE/db-short-sha256.auth" "$STATE/db-empty.auth" <<'PY'
import struct
import sys

auth = bytearray(open(sys.argv[1], "rb").read())
esl = open(sys.argv[2], "rb").read()
payload_offset = len(auth) - len(esl)
assert auth[payload_offset:] == esl
struct.pack_into("<I", auth, payload_offset + 16, len(esl) + 1)
open(sys.argv[3], "wb").write(auth)

sha256_guid = bytes.fromhex("2616c4c14c509240aca941f936934328")
signature_size = 20
malformed_esl = sha256_guid + struct.pack("<III", 28 + signature_size, 0, signature_size) + bytes(signature_size)
open(sys.argv[4], "wb").write(auth[:payload_offset] + malformed_esl)
open(sys.argv[5], "wb").write(auth[:payload_offset])
PY
        malformed_list_update="$(base64 --wrap=0 "$STATE/db-malformed-list.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$malformed_list_update\"}"
        short_sha256_update="$(base64 --wrap=0 "$STATE/db-short-sha256.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$short_sha256_update\"}"
        empty_update="$(base64 --wrap=0 "$STATE/db-empty.auth")"
        assert_invalid_update_data "{\"variable\":\"db\",\"data\":\"$empty_update\"}"
        diff -r "$STATE/components-before-invalid/policy" "$POLICY_DIR"
        diff -r "$STATE/components-before-invalid/authority" "$AUTHORITY_DIR"
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" = "$policy_checksum"
        unlock_volume

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

        install_separator_error_overrides
        mkdir -p "$AUTHORITY_DIR"
        cp "$STATE/authority-before-outcome-fallback.pcrlock" "$AUTHORITY_DIR/generated.pcrlock"

        generate_bounded_update_predictions \
            "$authenticated_update" "$expected_predicted_pcr7_outcomes"
        # The addon is loaded after an already authenticated boot application, so its authority
        # cannot be the first authority event.
        remove_first_authority_insertion_prediction
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
        assert_pcr7_outcome_count "$expected_reboot_pcr7_outcomes"

        # A policy-only update must preserve the db authority variants.
        apply_efi_update "$KEK_VARIABLE" "$STATE/kek.auth" KEK
        notify_secure_boot_update '{"variable":"kek"}'
        assert_policy_pins_pcr7
        assert_pcr7_outcome_count "$expected_reboot_pcr7_outcomes"

        # Both Secure Boot components must have predictions for the next boot.
        test -f "$POLICY_DIR/generated.pcrlock"
        mapfile -t policy_predictions < <(compgen -G "$POLICY_DIR/generated-prediction-*.pcrlock")
        ((${#policy_predictions[@]} == 1))
        cp "${policy_predictions[@]}" "$STATE/predicted-policy/"
        test -f "$AUTHORITY_DIR/generated.pcrlock"
        mapfile -t authority_predictions < <(compgen -G "$AUTHORITY_DIR/generated-prediction-*.pcrlock")
        ((${#authority_predictions[@]} == expected_reboot_authority_predictions))
        cp "${authority_predictions[@]}" "$STATE/predicted-authority/"

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
        assert_prediction_matches "$AUTHORITY_DIR/generated.pcrlock" "$STATE/predicted-authority"

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

        authority_backup="$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -maxdepth 1 \
                            -name '*.authority.regenerate' -print -quit)"
        test -n "$authority_backup"
        transaction_prefix="${authority_backup%.authority.regenerate}"
        policy_backup="$transaction_prefix.policy.regenerate"
        policy_backup_no_regenerate="$transaction_prefix.policy.no-regenerate"
        authority_backup_no_regenerate="$transaction_prefix.authority.no-regenerate"
        test -d "$policy_backup"

        ambiguous_backup=/run/systemd/pcrlock-secureboot-update/11111111111111111111111111111111.authority.regenerate
        test ! -e "$ambiguous_backup"
        mv "$authority_backup" "$authority_backup_no_regenerate"
        cp -a "$authority_backup_no_regenerate" "$ambiguous_backup"
        notify_secure_boot_update "{\"variable\":\"dbx\",\"data\":\"$dbx_update\"}"
        assert_policy_omits_pcr7
        if [[ -d /run/systemd/pcrlock-secureboot-update ]]; then
            test -z "$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -print -quit)"
        fi

        rm -rf "$POLICY_DIR" "$AUTHORITY_DIR"
        cp -a "$STATE/components-before-rollback/policy" "$POLICY_DIR"
        cp -a "$STATE/components-before-rollback/authority" "$AUTHORITY_DIR"
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
        cp -a "$STATE/components-before-rollback/policy" "$policy_backup"
        cp -a "$STATE/components-before-rollback/authority" "$authority_backup"

        mv "$authority_backup" "$authority_backup.saved"
        touch "$authority_backup"
        if notify_secure_boot_update "{\"variable\":\"dbx\",\"data\":\"$dbx_update\"}"; then
            rm "$authority_backup"
            mv "$authority_backup.saved" "$authority_backup"
            echo "Interrupted update recovery unexpectedly succeeded with an invalid authority backup" >&2
            exit 1
        fi
        rm "$authority_backup"
        mv "$authority_backup.saved" "$authority_backup"
        diff -r "$STATE/components-before-rollback/policy" "$POLICY_DIR"
        diff -r "$STATE/components-before-rollback/authority" "$AUTHORITY_DIR"

        mv "$authority_backup" "$authority_backup_no_regenerate"
        mv "$policy_backup" "$policy_backup_no_regenerate"
        test -d "$policy_backup_no_regenerate"
        test -d "$authority_backup_no_regenerate"
        policy_checksum="$(sha256sum /var/lib/systemd/pcrlock.json)"
        notify_secure_boot_update \
            "{\"variable\":\"dbx\",\"data\":\"$dbx_update\",\"regenerate\":false}"
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" = "$policy_checksum"
        if [[ -d /run/systemd/pcrlock-secureboot-update ]]; then
            test -z "$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -print -quit)"
        fi

        regenerate_prefix=/run/systemd/pcrlock-secureboot-update/22222222222222222222222222222222
        regenerate_policy_backup="$regenerate_prefix.policy.regenerate"
        regenerate_authority_backup="$regenerate_prefix.authority.regenerate"
        mkdir -p /run/systemd/pcrlock-secureboot-update
        cp -a "$STATE/components-before-rollback/policy" "$regenerate_policy_backup"
        cp -a "$STATE/components-before-rollback/authority" "$regenerate_authority_backup"
        jq '(.records[0].digests[] | select(.hashAlg == "sha256").digest) =
                "0000000000000000000000000000000000000000000000000000000000000000"' \
           "$regenerate_authority_backup/generated.pcrlock" >"$STATE/regenerate-authority.pcrlock"
        mv "$STATE/regenerate-authority.pcrlock" "$regenerate_authority_backup/generated.pcrlock"
        policy_checksum="$(sha256sum /var/lib/systemd/pcrlock.json)"
        varlinkctl --graceful=io.systemd.PCRLock.UpdateNotApplied \
                   call /run/systemd/io.systemd.PCRLock \
                   io.systemd.PCRLock.NotifySecureBootUpdate \
                   '{"variable":"pk"}'
        test "$(sha256sum /var/lib/systemd/pcrlock.json)" != "$policy_checksum"
        if [[ -d /run/systemd/pcrlock-secureboot-update ]]; then
            test -z "$(find /run/systemd/pcrlock-secureboot-update -mindepth 1 -print -quit)"
        fi

        rm -rf "$POLICY_DIR" "$AUTHORITY_DIR"
        cp -a "$STATE/components-before-rollback/policy" "$POLICY_DIR"
        cp -a "$STATE/components-before-rollback/authority" "$AUTHORITY_DIR"
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7

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
        # Workaround for the CI issue where extra reboots are randomly done by qemu
        if [[ -e /testok ]]; then
            exit 0
        fi

        test -e "$STATE/dbx-prepared"

        unlock_volume
        esp="$(bootctl --print-esp-path)"
        cmp "$STATE/test.addon.efi" "$esp/loader/addons/test.addon.efi"
        ! grep pcrlock-secureboot-update-addon /proc/cmdline >/dev/null

        /usr/lib/systemd/systemd-pcrlock lock-secureboot-policy
        assert_prediction_matches "$POLICY_DIR/generated.pcrlock" "$STATE/predicted-policy-dbx"
        /usr/lib/systemd/systemd-pcrlock lock-secureboot-authority
        /usr/lib/systemd/systemd-pcrlock make-policy --pcr=7
        assert_policy_pins_pcr7
        unlock_volume

        install -m 0644 "$STATE/original.addon.efi" "$esp/loader/addons/test.addon.efi"
        unmask_prediction_components
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
