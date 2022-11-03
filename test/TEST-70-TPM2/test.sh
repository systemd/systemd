#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="cryptenroll/cryptsetup with TPM2 devices"
IMAGE_NAME="tpm2"
TEST_NO_NSPAWN=1
TEST_REQUIRE_INSTALL_TESTS=0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

command -v swtpm >/dev/null 2>&1 || exit 0
command -v tpm2_pcrextend >/dev/null 2>&1 || exit 0

test_append_files() {
        local workspace="${1:?}"

        instmods tpm tpm_tis tpm_ibmvtpm
        install_dmevent
        generate_module_dependencies
        inst_binary tpm2_pcrextend
        inst_binary openssl
}

TEST_70_TPM_DEVICE="tpm-tis"
if [[ "$(uname -m)" == "ppc64le" ]]; then
    # tpm-spapr support was introduced in qemu 5.0.0. Skip test for old qemu versions.
    qemu_min_version "5.0.0" || exit 0
    TEST_70_TPM_DEVICE="tpm-spapr"
fi

TEST_70_at_exit() {
    [[ -n "${TEST_70_SWTPM_PID:-}" ]] && kill "$TEST_70_SWTPM_PID" &>/dev/null
    [[ -n "${TEST_70_TPM_STATE:-}" ]] && rm -rf "$TEST_70_TPM_STATE"
}

TEST_70_TPM_STATE="$(mktemp -d)"
swtpm socket --tpm2 --tpmstate dir="$TEST_70_TPM_STATE" --ctrl type=unixio,path="$TEST_70_TPM_STATE/sock" &
TEST_70_SWTPM_PID=$!
add_at_exit_handler TEST_70_at_exit
QEMU_OPTIONS+=" -chardev socket,id=chrtpm,path=$TEST_70_TPM_STATE/sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device $TEST_70_TPM_DEVICE,tpmdev=tpm0"

do_test "$@"
