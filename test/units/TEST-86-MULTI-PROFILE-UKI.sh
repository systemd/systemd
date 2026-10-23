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

# Prints a string (list) EFI variable of systemd-stub, one entry per line
stub_variable() {
    local f="/sys/firmware/efi/efivars/$1-$LOADER_GUID"

    [[ -f "$f" ]] || return 1
    # Skip the 4 byte attribute header, the rest is UTF-16, possibly a list of NUL terminated strings
    tail -c +5 "$f" | iconv -f UTF-16LE -t UTF-8 | tr '\0' '\n' | sed '/^$/d'
}

# Whether trusting addons on first use can be tested: it needs Secure Boot (unsigned addons are loaded by the
# firmware otherwise), a stub that supports it, and the tools to build addons.
tofu_supported() {
    local sb="/sys/firmware/efi/efivars/SecureBoot-8be4df61-93ca-11d2-aa0d-00e098032b8c"
    local features="/sys/firmware/efi/efivars/StubFeatures-$LOADER_GUID"

    [[ -f "$sb" && "$(od -An -tu1 -j4 -N1 "$sb" | tr -d ' ')" == 1 ]] || return 1
    [[ -f "$features" ]] || return 1
    (( ($(od -An -tu8 -j4 -N8 "$features" | tr -d ' ') >> 13) & 1 )) || return 1
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

tofu_cleanup() {
    rm -f "$(bootctl --print-esp-path)"/loader/addons/tofu-*.addon.efi "$TOFU_STAGE"
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
        enrol)
            # The unsigned addon is trusted on first use and used, the one signed with an untrusted key
            # isn't, even though it was there on the first boot too.
            [[ "$(stub_variable StubTofuState)" == enrolled ]]
            [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-unsigned.addon.efi' ]]
            grep tofuunsigned=1 /proc/cmdline
            (! grep tofuwrongkey=1 /proc/cmdline)
            echo verify >"$TOFU_STAGE"
            reboot
            exit 0
            ;;
        verify)
            # The same addon is trusted again via the record
            [[ "$(stub_variable StubTofuState)" == verified ]]
            [[ "$(stub_variable StubTofuAddons)" == '\loader\addons\tofu-unsigned.addon.efi' ]]
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
            (! stub_variable StubTofuAddons)
            (! grep tofuunsigned= /proc/cmdline)
            (! grep tofuwrongkey=1 /proc/cmdline)

            tofu_cleanup
            bootctl set-default ""
            touch /testok
            exit 0
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

    if tofu_supported; then
        # An unsigned addon to trust on first use, and one signed with a key the firmware doesn't trust,
        # which must never be trusted on first use.
        tofu_cleanup
        tofu_addon tofu-unsigned tofuunsigned=1
        openssl req -x509 -newkey rsa:2048 -nodes -subj /CN=tofu -days 1 \
            -keyout /tmp/tofu.key -out /tmp/tofu.crt
        tofu_addon tofu-wrongkey tofuwrongkey=1 \
            --signtool=systemd-sbsign --secureboot-private-key=/tmp/tofu.key --secureboot-certificate=/tmp/tofu.crt
        echo enrol >"$TOFU_STAGE"
        bootctl set-default "multi-profile.efi@tofu"
        reboot
        exit 0
    fi

    echo "Trusting addons on first use cannot be tested here, skipping it"
    # Reset the default boot entry so a subsequent re-run of the test does not
    # boot straight back into @profile2 (where encrypted.raw is now gone) and fail.
    bootctl set-default ""
else
    exit 1
fi

touch /testok
