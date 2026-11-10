#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -eux
set -o pipefail

export SYSTEMD_LOG_LEVEL=debug

if ! systemd-analyze has-tpm2; then
    echo "Full TPM2 support not available, skipping the test"
    exit 0
fi

bootctl

STUB_PATH=$(bootctl --print-stub-path)
CURRENT_UKI=$STUB_PATH
# With boot counting, systemd-bless-boot may already have renamed the UKI.
if [[ ! -f "$CURRENT_UKI" ]]; then
    CURRENT_UKI="${CURRENT_UKI%+*}.efi"
fi
MEASURE=/usr/lib/systemd/systemd-measure
LOADER_GUID=4a67b082-0a4c-41cf-b6c7-440b29bb8c4f
TOFU_STAGE=/root/tofu-stage
# The TOFU record is in NVRAM and cannot be removed from the OS, hence remember that the TOFU stages ran, so
# that a rerun of the test doesn't expect to enroll again. Not removed by tofu_cleanup on purpose.
TOFU_TESTED=/root/tofu-tested
# The test provisions this certificate via the key addon. The TOFU stages only check the keyring if this
# file exists, because systemd-keyring-setup is not built everywhere.
TOFU_CRT=/root/tofu-keyring.crt
# The modified stage replaces the key addon with one that contains this certificate instead.
TOFU_PLANTED_CRT=/root/tofu-planted.crt

# Prints a string (list) EFI variable of systemd-stub, one entry per line
stub_variable() {
    local f="/sys/firmware/efi/efivars/$1-$LOADER_GUID"

    [[ -f "$f" ]] || return 1
    # Skip the 4 byte attribute header, the rest is UTF-16, possibly a list of NUL terminated strings.
    # NB: dd, because efivarfs does not support seeking on older kernels, which tail -c +5 would do.
    dd if="$f" bs=1 skip=4 status=none | iconv -f UTF-16LE -t UTF-8 | tr '\0' '\n' | sed '/^$/d'
}

# Whether trusting addons on first use can be tested: it needs Secure Boot (unsigned addons are loaded by the
# firmware otherwise), a stub that supports it, and the tools to build addons.
tofu_supported() {
    local sb="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    local features="/sys/firmware/efi/efivars/StubFeatures-$LOADER_GUID"

    [[ -f "$sb" && "$(od -An -tu1 -j4 -N1 "$sb" | tr -d ' ')" == 1 ]] || return 1
    [[ -f "$features" ]] || return 1
    (( ($(od -An -tu8 -j4 -N8 "$features" | tr -d ' ') >> 14) & 1 )) || return 1
    [[ -f "/usr/lib/systemd/boot/efi/addon$(bootctl --print-efi-architecture).efi.stub" ]] || return 1
    command -v openssl >/dev/null || return 1
    command -v systemd-sbsign >/dev/null || command -v /usr/lib/systemd/systemd-sbsign >/dev/null || return 1
}

tofu_addon() {
    local name="${1:?}" cmdline="${2:?}"
    shift 2

    ukify build \
        --stub="/usr/lib/systemd/boot/efi/addon$(bootctl --print-efi-architecture).efi.stub" \
        --cmdline="$cmdline" \
        --output="$(bootctl --print-esp-path)/loader/addons/$name.addon.efi" \
        "$@"
}

# This function succeeds if the test can provision a certificate in an addon and check that it arrives in
# the kernel keyring. That needs systemd-keyring-setup, a kernel with a .dm-verity keyring, and the tools to
# build the addon with systemd-firstboot.
tofu_keys_supported() {
    [[ -x /usr/lib/systemd/systemd-keyring-setup ]] || return 1
    # The tofu profile boots with dm_verity.keyring_unsealed=1, so that systemd-keyring-setup may provision
    # the keyring. The parameter only exists if the kernel has a .dm-verity keyring.
    modinfo -p dm_verity 2>/dev/null | grep keyring_unsealed >/dev/null \
        || [[ -e /sys/module/dm_verity/parameters/keyring_unsealed ]] || return 1
    command -v systemd-firstboot >/dev/null || return 1
    command -v systemd-repart >/dev/null || return 1
    command -v keyctl >/dev/null || return 1
    command -v mcopy >/dev/null || return 1
    command -v sfdisk >/dev/null || return 1
    command -v jq >/dev/null || return 1
}

# This function provisions a certificate for the .dm-verity keyring in an unsigned addon that
# systemd-firstboot builds. systemd-firstboot --addon= only writes into a disk image file, hence the function
# builds the addon in a scratch image and copies it onto the mounted ESP.
tofu_key_addon() {
    local crt="${1:?}" wrk start
    wrk="$(mktemp -d)"

    mkdir "$wrk/defs"
    cat >"$wrk/defs/10-esp.conf" <<EOF
[Partition]
Type=esp
Format=vfat
EOF
    systemd-repart --empty=create --size=auto --dry-run=no --offline=yes \
        --definitions="$wrk/defs" "$wrk/image.raw"
    systemd-firstboot --image="$wrk/image.raw" --addon=tofu-keys --key=dm-verity:tofu-key="$crt"

    start="$(sfdisk --json "$wrk/image.raw" | jq -r '.partitiontable.partitions[0].start')"
    mcopy -n -i "$wrk/image.raw@@$((start * 512))" ::/loader/addons/tofu-keys.addon.efi \
        "$(bootctl --print-esp-path)/loader/addons/tofu-keys.addon.efi"
    rm -rf "$wrk"
}

# This function checks that the certificate from the trusted key addon is a system credential, and that
# systemd-keyring-setup enrolled it into the .dm-verity keyring before the switch to the host.
tofu_keys_check() {
    local enrolled switched
    local pem="/run/voa/[^/]+/kernel-keyring/dm-verity/x509/tofu-key-certificate.pem"
    local re="^Enrolled .$pem. into keyring .dm-verity"

    cmp <(systemd-creds --system cat keyring-setup.dm-verity.tofu-key) "$TOFU_CRT"
    keyctl list %:.dm-verity >/tmp/tofu-keyring.list
    grep -F tofu-enrolled-key /tmp/tofu-keyring.list >/dev/null

    # journalctl -u does not find the messages of the initrd run, because the process has exited by the
    # time journald reads them, and they hence carry no _SYSTEMD_UNIT= field.
    journalctl -b -o json -t systemd-keyring-setup >/tmp/tofu-keyring-setup.json
    enrolled="$(jq -rn --arg re "$re" 'first(inputs | select(.MESSAGE | test($re)) | .__MONOTONIC_TIMESTAMP)' \
        /tmp/tofu-keyring-setup.json)"
    journalctl -b -o json _PID=1 >/tmp/tofu-pid1.json
    switched="$(jq -rn 'first(inputs | select(.MESSAGE | startswith("Switching root")) | .__MONOTONIC_TIMESTAMP)' \
        /tmp/tofu-pid1.json)"
    rm -f /tmp/tofu-keyring.list /tmp/tofu-keyring-setup.json /tmp/tofu-pid1.json
    [[ -n "$enrolled" && -n "$switched" && "$enrolled" -lt "$switched" ]]
}

# This function checks which addons the stub trusted on first use on a boot where the modified addon is
# not on the ESP yet.
tofu_addons_check() {
    if [[ -e "$TOFU_CRT" ]]; then
        [[ "$(stub_variable StubTofuAddons)" == "$(printf '%s\n' \
            '\loader\addons\tofu-keys.addon.efi' '\loader\addons\tofu-unsigned.addon.efi')" ]]
        tofu_keys_check
    else
        [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-unsigned.addon.efi' ]]
    fi
}

tofu_cleanup() {
    rm -f "$(bootctl --print-esp-path)"/loader/addons/tofu-*.addon.efi "$TOFU_STAGE" \
        "$TOFU_CRT" "$TOFU_PLANTED_CRT"
}

tofu_done() {
    tofu_cleanup
    touch "$TOFU_TESTED"
    bootctl set-default ""
    touch /testok
    exit 0
}

echo "CURRENT UKI ($CURRENT_UKI):"
ukify inspect "$CURRENT_UKI"
if test -f /run/systemd/stub/profile; then
    echo "CURRENT PROFILE:"
    cat /run/systemd/stub/profile
fi

# systemd-measure is optional
if [ -x "$MEASURE" ]; then
    echo "CURRENT MEASUREMENT:"
    "$MEASURE" --current
fi
if test -f /run/systemd/tpm2-pcr-signature.json; then
    echo "CURRENT SIGNATURE:"
    jq </run/systemd/tpm2-pcr-signature.json
fi

echo "CURRENT EVENT LOG + PCRS:"
/usr/lib/systemd/systemd-pcrlock

test -f /run/systemd/stub/profile

# shellcheck source=/dev/null
. /run/systemd/stub/profile

if [[ "$ID" == "tofu" ]]; then
    grep testprofiletofu=1 /proc/cmdline
    stub_variable StubTofuState
    stub_variable StubTofuAddons || :

    case "$(cat "$TOFU_STAGE")" in
        enroll)
            # The unsigned addon is trusted on first use and used, the one signed with an untrusted key
            # isn't, even though it was there on the first boot too.
            [[ "$(stub_variable StubTofuState)" == enrolled ]]
            tofu_addons_check
            grep tofuunsigned=1 /proc/cmdline
            (! grep tofuwrongkey=1 /proc/cmdline)
            echo verify >"$TOFU_STAGE"
            reboot
            exit 0
            ;;
        verify)
            # The same addon is trusted again via the record
            [[ "$(stub_variable StubTofuState)" == verified ]]
            tofu_addons_check
            grep tofuunsigned=1 /proc/cmdline
            (! grep tofuwrongkey=1 /proc/cmdline)

            # Replace it with a modified one, which must not be trusted
            tofu_addon tofu-unsigned tofuunsigned=2
            echo modified >"$TOFU_STAGE"
            reboot
            exit 0
            ;;
        modified)
            [[ "$(stub_variable StubTofuState)" == verified ]]
            (! grep tofuunsigned= /proc/cmdline)
            (! grep tofuwrongkey=1 /proc/cmdline)

            if [[ -e "$TOFU_CRT" ]]; then
                # The untouched key addon is unaffected by the rejection of its modified neighbour
                [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-keys.addon.efi' ]]
                tofu_keys_check

                # Replace the key addon with one carrying a different certificate, as an attacker with
                # access to the ESP would. Nothing of it may reach the OS on the next boot.
                openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
                    -subj /CN=tofu-planted-key -days 2 -keyout /dev/null -out "$TOFU_PLANTED_CRT"
                rm -f "$(bootctl --print-esp-path)/loader/addons/tofu-keys.addon.efi"
                tofu_key_addon "$TOFU_PLANTED_CRT"
                echo planted >"$TOFU_STAGE"
                reboot
                exit 0
            fi

            (! stub_variable StubTofuAddons)
            tofu_done
            ;;
        planted)
            [[ "$(stub_variable StubTofuState)" == verified ]]
            (! stub_variable StubTofuAddons)
            (! grep tofuunsigned= /proc/cmdline)
            (! grep tofuwrongkey=1 /proc/cmdline)

            # The planted certificate and the certificate enrolled on the earlier boots are neither a
            # credential nor in the keyring. keyctl writes into a file, so that a failure to list the
            # keyring fails the test.
            (! systemd-creds --system cat keyring-setup.dm-verity.tofu-key)
            keyctl list %:.dm-verity >/tmp/tofu-keyring.list
            (! grep tofu- /tmp/tofu-keyring.list)
            rm -f /tmp/tofu-keyring.list

            tofu_done
            ;;
        *)
            exit 1
            ;;
    esac
fi

if [[ "$ID" == "main" ]]; then
    if [[ -f /root/encrypted.raw ]]; then
        exit 1
    fi

    # Prepare a disk image, locked to the PCR measurements of the current UKI
    truncate -s 32M /root/encrypted.raw
    echo -n "geheim" >/root/encrypted.secret
    cryptsetup luksFormat -q --pbkdf pbkdf2 --pbkdf-force-iterations 1000 --use-urandom /root/encrypted.raw --key-file=/root/encrypted.secret
    systemd-cryptenroll --tpm2-device=auto --tpm2-pcrs= --unlock-key-file=/root/encrypted.secret /root/encrypted.raw
    rm -f /root/encrypted.secret
fi

# Validate that with the current profile we can fulfill the PCR 11 policy
systemd-cryptsetup attach multiprof /root/encrypted.raw - tpm2-device=auto,headless=1
systemd-cryptsetup detach multiprof

if [[ "$ID" == "main" ]]; then
    # Give the UKI a mixed case name with a boot counter. Entry IDs are matched case insensitively
    # and without the counter, so the lower case ID without counter has to keep working.
    mv "$CURRENT_UKI" "$(dirname "$CURRENT_UKI")/Multi-Profile+3.efi"
    bootctl set-default "multi-profile.efi@profile1"
    reboot
    exit 0
elif [[ "$ID" == "profile1" ]]; then
    grep testprofile1=1 /proc/cmdline
    # The renamed UKI with the boot counter has to be what systemd-boot booted.
    [[ "$(basename "$STUB_PATH")" == Multi-Profile+* ]]
    # The profile ID is "Profile2", the lower case entry ID has to match it anyway.
    bootctl set-default "multi-profile.efi@profile2"
    reboot
    exit 0
elif [[ "$ID" == "Profile2" ]]; then
    grep testprofile2=1 /proc/cmdline
    rm /root/encrypted.raw

    if [[ -e "$TOFU_TESTED" ]]; then
        echo "Trusting addons on first use was tested on a previous run already, its record persists, skipping it"
    elif tofu_supported; then
        # An unsigned addon to trust on first use, and one signed with a key the firmware doesn't trust,
        # which must never be trusted on first use.
        tofu_cleanup
        tofu_addon tofu-unsigned tofuunsigned=1
        openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=tofu -days 1 \
            -keyout /tmp/tofu.key -out /tmp/tofu.crt
        tofu_addon tofu-wrongkey tofuwrongkey=1 \
            --signtool=systemd-sbsign --secureboot-private-key=/tmp/tofu.key --secureboot-certificate=/tmp/tofu.crt
        if tofu_keys_supported; then
            # A certificate provisioned for the kernel keyring, in an addon built by systemd-firstboot
            openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
                -subj /CN=tofu-enrolled-key -days 2 -keyout /dev/null -out "$TOFU_CRT"
            tofu_key_addon "$TOFU_CRT"
        fi
        echo enroll >"$TOFU_STAGE"
        bootctl set-default "multi-profile.efi@tofu"
        reboot
        exit 0
    else
        echo "Trusting addons on first use cannot be tested here, skipping it"
    fi

    # Reset the default boot entry so a subsequent re-run of the test does not
    # boot straight back into @profile2 (where encrypted.raw is now gone) and fail.
    bootctl set-default ""
else
    exit 1
fi

touch /testok
