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
FUZZIT_API_KEY=7c1bd82fe0927ffe1b4bf1e2e86cc812b28dfe08a7080a7bf498e98715884a163402ee37ba95d4b1637247deffcea43e
FUZZIT_ADDITIONAL_FILES="./out/src/shared/libsystemd-shared-242.so"

# ASan options are borrowed almost verbatim from OSS-Fuzz
ASAN_OPTIONS=redzone=32:print_summary=1:handle_sigill=1:allocator_release_to_os_interval_ms=500:print_suppressions=0:strict_memcmp=1:allow_user_segv_handler=0:allocator_may_return_null=1:use_sigaltstack=1:handle_sigfpe=1:handle_sigbus=1:detect_stack_use_after_return=1:alloc_dealloc_mismatch=0:detect_leaks=1:print_scariness=1:max_uar_stack_size_log=16:handle_abort=1:check_malloc_usable_size=0:quarantine_size_mb=64:detect_odr_violation=0:handle_segv=1:fast_unwind_on_fatal=0
UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1:silence_unsigned_overflow=1
FUZZIT_ARGS="--type ${FUZZING_TYPE} --branch ${FUZZIT_BRANCH} --revision ${TRAVIS_COMMIT} --asan_options ${ASAN_OPTIONS} --ubsan_options ${UBSAN_OPTIONS}"
wget -O fuzzit https://bin.fuzzit.dev/fuzzit-1.1
chmod +x fuzzit

./fuzzit auth ${FUZZIT_API_KEY}

# The following was generated with
# ./fuzzit get targets | jq --raw-output '.target_name + " " + .id' | perl -alne 'printf("./fuzzit c job \${FUZZIT_ARGS} %s ./out/%s \${FUZZIT_ADDITIONAL_FILES}\n", $F[1], $F[0])'
./fuzzit c job ${FUZZIT_ARGS} 2ODbhEjfRF2AZtrUotMh ./out/fuzz-bus-label ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 62XnUyWTLAvIRh1vFkEw ./out/fuzz-journald-stream ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 6AdGwIiI3l1Edu9V4fvF ./out/fuzz-env-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 7ubB4DVu2EiYgPVtRUNV ./out/fuzz-calendarspec ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 8D0NrVtSwTpl23a9k0vv ./out/fuzz-nspawn-oci ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 8tbrzwxsaIPalIRBHtK8 ./out/fuzz-link-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} 9T5He9cANxHTBLaBURpz ./out/fuzz-journald-kmsg ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} BRaEBuU7QVlSp1HOjlDb ./out/fuzz-udev-database ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} DcE70rAA2mhrxdyBRH90 ./out/fuzz-udev-rules ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} KH6VEpV0ZoWynASJHm8z ./out/fuzz-dhcp6-client ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} MZNs1JG5UQstaIvfHYgb ./out/fuzz-netdev-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} P1MpkewCNQCYLdMFggnU ./out/fuzz-journald-audit ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} RmD47BxVRbAZlq07XW30 ./out/fuzz-unit-file ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} S0dGMaaGwkvsLc0IqIJ7 ./out/fuzz-catalog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} X7qIoGLAoBgjVf19SfvY ./out/fuzz-compress ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} YAfecldFs2xaXn0Ws1BE ./out/fuzz-dns-packet ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} bgRZAE9E5uXRbUX76tId ./out/fuzz-ndisc-rs ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} cXCm75EhdDf5t2sSBLRC ./out/fuzz-hostname-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} cbgsYEyX6776MHFotO9O ./out/fuzz-nspawn-settings ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} d8lokp0LCLYgQwI7vyx6 ./out/fuzz-journald-native-fd ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} eoc9rbm2jKqIEg6Kdonv ./out/fuzz-network-parser ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} ezQIlJWCX3xPUJdhLnWM ./out/fuzz-dhcp-server ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} ge3eTzephghWD3Stw2TE ./out/fuzz-journald-syslog ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} nPIt1SCDkGkSFDth5RlG ./out/fuzz-json ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} nU0lRNNkQrXirDMNOpR1 ./out/fuzz-varlink ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} pzrzgLQY2cG8Iexb0tOt ./out/fuzz-journal-remote ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} qCWFcENjlfWJX0Q3cIOT ./out/fuzz-journald-native ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} s7d3LuRbkETCPSyxUvW8 ./out/fuzz-time-util ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} udjVYJfH4N01vaHNF5Kv ./out/fuzz-lldp ${FUZZIT_ADDITIONAL_FILES}
./fuzzit c job ${FUZZIT_ARGS} vbYVccyWoDdgqzrQeln8 ./out/fuzz-bus-message ${FUZZIT_ADDITIONAL_FILES}
