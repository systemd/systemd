#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later
set -e

TEST_DESCRIPTION="cryptenroll/cryptsetup with TPM2 devices"
IMAGE_NAME="cryptenrolltpm2"
TEST_NO_NSPAWN=1
TEST_REQUIRE_INSTALL_TESTS=0

# shellcheck source=test/test-functions
. "${TEST_BASE_DIR:?}/test-functions"

command -v swtpm >/dev/null 2>&1 || exit 0
command -v tpm2_pcrextend >/dev/null 2>&1 || exit 0

test_append_files() {
    (
        local workspace="${1:?}"

        install_dmevent
        generate_module_dependencies
        inst_binary tpm2_pcrextend
        # XXX: Needs a better way to install libraries
        cp -a /usr/lib64/libtss2-tcti-* "$workspace/usr/lib64"
    )
}

check_result_qemu() {
    local ret=1

    mount_initdir
    [[ -e "${initdir:?}/testok" ]] && ret=0

    return $ret
}

tpmstate=$(mktemp -d)
swtpm socket --tpm2 --tpmstate dir=$tpmstate --ctrl type=unixio,path=$tpmstate/sock &
trap "kill %%; rm -rf $tpmstate" SIGINT EXIT
QEMU_OPTIONS="-chardev socket,id=chrtpm,path=$tpmstate/sock -tpmdev emulator,id=tpm0,chardev=chrtpm -device tpm-tis,tpmdev=tpm0"

do_test "$@"
