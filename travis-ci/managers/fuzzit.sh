#!/bin/bash

set -e
set -x
set -u

REPO_ROOT=${REPO_ROOT:-$(pwd)}

sudo bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse' >>/etc/apt/sources.list"
sudo apt-get update -y
sudo apt-get build-dep systemd -y
sudo apt-get install -y ninja-build python3-pip python3-setuptools
pip3 install meson

cd $REPO_ROOT
export PATH="$HOME/.local/bin/:$PATH"

# We use a subset of https://clang.llvm.org/docs/UndefinedBehaviorSanitizer.html#available-checks instead of "undefined"
# because our fuzzers crash with "pointer-overflow" and "float-cast-overflow":
# https://github.com/systemd/systemd/pull/12771#issuecomment-502139157
# https://github.com/systemd/systemd/pull/12812#issuecomment-502780455
# TODO: figure out what to do about unsigned-integer-overflow: https://github.com/google/oss-fuzz/issues/910
export SANITIZER="address -fsanitize=alignment,array-bounds,bool,bounds,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,nonnull-attribute,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,unsigned-integer-overflow,vla-bound,vptr -fno-sanitize-recover=alignment,array-bounds,bool,bounds,builtin,enum,float-divide-by-zero,function,integer-divide-by-zero,nonnull-attribute,null,object-size,return,returns-nonnull-attribute,shift,signed-integer-overflow,unreachable,vla-bound,vptr"
tools/oss-fuzz.sh

FUZZING_TYPE=${1:-sanity}
if [ "$TRAVIS_PULL_REQUEST" = "false" ]; then
    FUZZIT_BRANCH="${TRAVIS_BRANCH}"
else
    FUZZIT_BRANCH="PR-${TRAVIS_PULL_REQUEST}"
fi

# Because we want Fuzzit to run on every pull-request and Travis/Azure doesnt support encrypted keys
# on pull-request we use a write-only key which is ok for now. maybe there will be a better solution in the future
FUZZIT_API_KEY=6a8445a23c4a8ef6743ddecf8ab368300976dae9313bbe54f1cbf30801773b2a3095d4c34daab8d308b6f2e8b254c90e
FUZZIT_ADDITIONAL_FILES="./out/src/shared/libsystemd-shared-*.so"

# ASan options are borrowed almost verbatim from OSS-Fuzz
ASAN_OPTIONS=redzone=32:print_summary=1:handle_sigill=1:allocator_release_to_os_interval_ms=500:print_suppressions=0:strict_memcmp=1:allow_user_segv_handler=0:allocator_may_return_null=1:use_sigaltstack=1:handle_sigfpe=1:handle_sigbus=1:detect_stack_use_after_return=1:alloc_dealloc_mismatch=0:detect_leaks=1:print_scariness=1:max_uar_stack_size_log=16:handle_abort=1:check_malloc_usable_size=0:quarantine_size_mb=64:detect_odr_violation=0:handle_segv=1:fast_unwind_on_fatal=0
UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1:silence_unsigned_overflow=1
FUZZIT_ARGS="--type ${FUZZING_TYPE} --branch ${FUZZIT_BRANCH} --revision ${TRAVIS_COMMIT} --asan_options ${ASAN_OPTIONS} --ubsan_options ${UBSAN_OPTIONS}"
wget -O fuzzit https://bin.fuzzit.dev/fuzzit-1.1
chmod +x fuzzit

./fuzzit auth ${FUZZIT_API_KEY}

# The following was generated with
# ./fuzzit get targets | jq --raw-output '.target_name + " " + .id' | grep -v -- '-msan$' | perl -alne '$F[0] =~ s/-asan-ubsan$//; printf("./fuzzit c job \${FUZZIT_ARGS} %s ./out/%s \${FUZZIT_ADDITIONAL_FILES}\n", $F[1], $F[0])'
./fuzzit c job ${FUZZIT_ARGS} fuzz-bus-label-asan-ubsan ./out/fuzz-bus-label ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-bus-message-asan-ubsan ./out/fuzz-bus-message ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-calendarspec-asan-ubsan ./out/fuzz-calendarspec ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-catalog-asan-ubsan ./out/fuzz-catalog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-compress-asan-ubsan ./out/fuzz-compress ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dhcp-server-asan-ubsan ./out/fuzz-dhcp-server ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dhcp6-client-asan-ubsan ./out/fuzz-dhcp6-client ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dns-packet-asan-ubsan ./out/fuzz-dns-packet ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-env-file-asan-ubsan ./out/fuzz-env-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-hostname-util-asan-ubsan ./out/fuzz-hostname-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journal-remote-asan-ubsan ./out/fuzz-journal-remote ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-audit-asan-ubsan ./out/fuzz-journald-audit ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-kmsg-asan-ubsan ./out/fuzz-journald-kmsg ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-native-asan-ubsan ./out/fuzz-journald-native ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-native-fd-asan-ubsan ./out/fuzz-journald-native-fd ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-stream-asan-ubsan ./out/fuzz-journald-stream ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-syslog-asan-ubsan ./out/fuzz-journald-syslog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-json-asan-ubsan ./out/fuzz-json ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-link-parser-asan-ubsan ./out/fuzz-link-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-lldp-asan-ubsan ./out/fuzz-lldp ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-ndisc-rs-asan-ubsan ./out/fuzz-ndisc-rs ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-netdev-parser-asan-ubsan ./out/fuzz-netdev-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-network-parser-asan-ubsan ./out/fuzz-network-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-nspawn-oci-asan-ubsan ./out/fuzz-nspawn-oci ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-nspawn-settings-asan-ubsan ./out/fuzz-nspawn-settings ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-time-util-asan-ubsan ./out/fuzz-time-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-udev-database-asan-ubsan ./out/fuzz-udev-database ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-udev-rules-asan-ubsan ./out/fuzz-udev-rules ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-unit-file-asan-ubsan ./out/fuzz-unit-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-varlink-asan-ubsan ./out/fuzz-varlink ${FUZZIT_ADDITIONAL_FILES}

export SANITIZER="memory"
FUZZIT_ARGS="--type ${FUZZING_TYPE} --branch ${FUZZIT_BRANCH} --revision ${TRAVIS_COMMIT}"
tools/oss-fuzz.sh

# The following was generated with
# ./fuzzit get targets | jq --raw-output '.target_name + " " + .id' | grep  -- '-msan$' | perl -alne '$F[0] =~ s/-msan$//; printf("./fuzzit c job \${FUZZIT_ARGS} %s ./out/%s \${FUZZIT_ADDITIONAL_FILES}\n", $F[1], $F[0])'
./fuzzit c job ${FUZZIT_ARGS} fuzz-bus-label-msan ./out/fuzz-bus-label ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-bus-message-msan ./out/fuzz-bus-message ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-calendarspec-msan ./out/fuzz-calendarspec ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-catalog-msan ./out/fuzz-catalog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-compress-msan ./out/fuzz-compress ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dhcp-server-msan ./out/fuzz-dhcp-server ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dhcp6-client-msan ./out/fuzz-dhcp6-client ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-dns-packet-msan ./out/fuzz-dns-packet ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-env-file-msan ./out/fuzz-env-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-hostname-util-msan ./out/fuzz-hostname-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journal-remote-msan ./out/fuzz-journal-remote ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-audit-msan ./out/fuzz-journald-audit ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-kmsg-msan ./out/fuzz-journald-kmsg ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-native-fd-msan ./out/fuzz-journald-native-fd ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-native-msan ./out/fuzz-journald-native ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-stream-msan ./out/fuzz-journald-stream ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-journald-syslog-msan ./out/fuzz-journald-syslog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-json-msan ./out/fuzz-json ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-link-parser-msan ./out/fuzz-link-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-lldp-msan ./out/fuzz-lldp ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-ndisc-rs-msan ./out/fuzz-ndisc-rs ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-netdev-parser-msan ./out/fuzz-netdev-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-network-parser-msan ./out/fuzz-network-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-nspawn-oci-msan ./out/fuzz-nspawn-oci ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-nspawn-settings-msan ./out/fuzz-nspawn-settings ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-time-util-msan ./out/fuzz-time-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-udev-database-msan ./out/fuzz-udev-database ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-udev-rules-msan ./out/fuzz-udev-rules ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-unit-file-msan ./out/fuzz-unit-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} fuzz-varlink-msan ./out/fuzz-varlink ${FUZZIT_ADDITIONAL_FILES}
