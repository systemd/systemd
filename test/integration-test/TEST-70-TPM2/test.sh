#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="cryptenroll/cryptsetup with TPM2 devices"
IMAGE_NAME="tpm2"
TEST_NO_NSPAWN=1
TEST_SETUP_SWTPM=1
TEST_REQUIRE_INSTALL_TESTS=0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

test_require_bin openssl swtpm tpm2_createprimary tpm2_dictionarylockout tpm2_evictcontrol tpm2_flushcontext tpm2_pcrextend tpm2_pcrread tpm2_readpublic

test_append_files() {
    local workspace="${1:?}"

    instmods tpm tpm_tis
    machine="$(uname -m)"
    if [ "${machine}" = "ppc64le" ]; then
        # This module is only available on PPC hw
        instmods tpm_ibmvtpm
    fi
    install_dmevent
    generate_module_dependencies
    inst_binary openssl
    inst_binary tpm2_createprimary
    inst_binary tpm2_dictionarylockout
    inst_binary tpm2_evictcontrol
    inst_binary tpm2_flushcontext
    inst_binary tpm2_pcrextend
    inst_binary tpm2_pcrread
    inst_binary tpm2_readpublic
}

do_test "$@"
