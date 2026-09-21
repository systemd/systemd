# SPDX-License-Identifier: LGPL-2.1-or-later
# shellcheck shell=bash
#
# Guest-side checks for the confidential computing integration test (TEST-94-COCO). Sourced by
# guest-test-runner.sh inside the confidential guest; each testcase_coco_* function is one
# sub-subtest, and a boot scenario selects the applicable subset via $TEST_MATCH_TESTCASE.

if [[ "${BASH_SOURCE[0]}" -ef "$0" ]]; then
    echo >&2 "This file should not be executed directly"
    exit 1
fi

# shellcheck source=test/units/TEST-94-COCO/fixtures.sh
. "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")/fixtures.sh"

# _coco_assert_cred_absent ID
# Assert no credential named ID reached the guest at all, neither trusted nor encrypted.
_coco_assert_cred_absent() {
    local id="${1:?}"
    local system_creds_dir=/run/credentials/@system
    local encrypted_creds_dir=/run/credentials/@encrypted

    assert_fail test -e "$system_creds_dir/$id"
    assert_fail test -e "$encrypted_creds_dir/$id"
}

# _coco_smbios_supported
# Whether the guest can read SMBIOS type #11 OEM strings at all. Without dmi-sysfs a check that looks
# for an injection there cannot run, which is a skip rather than a failure.
_coco_smbios_supported() {
    local dmi_entries_dir=/sys/firmware/dmi/entries

    # The DMI entries come from the dmi-sysfs module, which is not always loaded.
    [[ -d "$dmi_entries_dir" ]] || modprobe dmi-sysfs || :
    [[ -d "$dmi_entries_dir" ]]
}

# _coco_assert_smbios_injected ID
# Assert the guest received an SMBIOS type #11 OEM string carrying credential ID. The scenario
# injected it, so a miss means the injection was lost on the way in and concluding anything from the
# credential's absence afterwards would be meaningless.
_coco_assert_smbios_injected() {
    local id="${1:?}" raw

    for raw in /sys/firmware/dmi/entries/11-*/raw; do
        [[ -e "$raw" ]] || continue
        # The entry is a blob of NUL-separated strings: --text to search it anyway, --fixed-strings
        # because credential names contain dots. Redirect rather than -q, which would exit early and
        # risk SIGPIPE on the reader.
        if grep --text --fixed-strings "io.systemd.credential:$id=" "$raw" >/dev/null; then
            return 0
        fi
    done

    echo "FAIL: no SMBIOS OEM string for credential '$id' in the guest's DMI type #11 tables" >&2
    return 1
}

# Assert the guest observes the confidential-virtualization technology the host launched it with.
# COCO_TYPE is provided by the injected guest unit (Environment=, see lib.sh).
testcase_coco_detect_virt() {
    assert_eq "$(systemd-detect-virt --cvm)" "${COCO_TYPE:?}"
}

# Assert a credential handed to systemd-vmspawn --set-credential lands in the trusted bucket.
#
# SNP: creds should be delivered via the initrd cpio channel.
testcase_coco_creds_vmspawn() {
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_TRUSTED_ID")" "$COCO_CRED_TRUSTED_VALUE"
    assert_not_in "$COCO_CRED_TRUSTED_ID" "$(</proc/cmdline)"
}

# Assert a credential passed on the kernel command line lands in the trusted bucket.
#
# Credentials passed on the cmdline should be accepted on every coco platform.
testcase_coco_creds_cmdline() {
    assert_in "systemd.set_credential=$COCO_CRED_CMDLINE_ID:$COCO_CRED_CMDLINE_VALUE" "$(</proc/cmdline)"
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_CMDLINE_ID")" "$COCO_CRED_CMDLINE_VALUE"
}

# fw_cfg is unmeasured on every platform and import_credentials_qemu() drops it for any confidential
# guest, so this applies to SNP and TDX alike.
testcase_coco_creds_hostile_fwcfg() {
    local fwcfg_dir=/sys/firmware/qemu_fw_cfg/by_name

    [[ -d "$fwcfg_dir" ]] || modprobe qemu_fw_cfg || :
    if [[ ! -d "$fwcfg_dir" ]]; then
        echo "No fw_cfg sysfs interface in this image, skipping"
        return 77
    fi

    assert_ok test -e "$fwcfg_dir/opt/io.systemd.credentials/$COCO_CRED_FWCFG_ID/raw"
    _coco_assert_cred_absent "$COCO_CRED_FWCFG_ID"
}

# SNP only: the SMBIOS tables are not covered by the launch measurement, so
# import_credentials_smbios() bails out. Under TDX they are measured into RTMR0 and thus trusted.
testcase_coco_creds_hostile_snp_smbios() {
    _coco_smbios_supported || { echo "No SMBIOS OEM strings in this image, skipping"; return 77; }

    _coco_assert_smbios_injected "$COCO_CRED_SMBIOS_ID"
    _coco_assert_cred_absent "$COCO_CRED_SMBIOS_ID"
}

# SNP only: injecting a name the measured channel already delivered must not overwrite it. The probe
# is what makes this more than a repeat of creds_vmspawn: it proves the overwrite was attempted.
testcase_coco_creds_hostile_snp_shadow() {
    _coco_smbios_supported || { echo "No SMBIOS OEM strings in this image, skipping"; return 77; }

    _coco_assert_smbios_injected "$COCO_CRED_TRUSTED_ID"
    assert_eq "$(systemd-creds --system cat "$COCO_CRED_TRUSTED_ID")" "$COCO_CRED_TRUSTED_VALUE"
}
