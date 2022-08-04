#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# shellcheck disable=SC2206
PHASES=(${@:-SETUP RUN RUN_ASAN_UBSAN CLEANUP})
RELEASE="$(lsb_release -cs)"
ADDITIONAL_DEPS=(
    clang
    expect
    fdisk
    jekyll
    libbpf-dev
    libfdisk-dev
    libfido2-dev
    libp11-kit-dev
    libpwquality-dev
    libqrencode-dev
    libssl-dev
    libtss2-dev
    libxkbcommon-dev
    libzstd-dev
    perl
    python3-libevdev
    python3-pyparsing
    rpm
    zstd
)

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

function run_meson() {
    if ! meson "$@"; then
        find . -type f -name meson-log.txt -exec cat '{}' +
        return 1
    fi
}

set -ex

MESON_ARGS=(-Dcryptolib=${CRYPTOLIB:-auto})

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"
            # PPA with some newer build dependencies
            add-apt-repository -y ppa:upstream-systemd-ci/systemd-ci
            apt-get -y update
            apt-get -y build-dep systemd
            apt-get -y install "${ADDITIONAL_DEPS[@]}"
            pip3 install -r .github/workflows/requirements.txt --require-hashes
            ;;
        RUN|RUN_GCC|RUN_CLANG|RUN_CLANG_RELEASE)
            if [[ "$phase" =~ ^RUN_CLANG ]]; then
                export CC=clang
                export CXX=clang++
                if [[ "$phase" == RUN_CLANG ]]; then
                    # The docs build is slow and is not affected by compiler/flags, so do it just once
                    MESON_ARGS+=(-Dman=true)
                else
                    MESON_ARGS+=(-Dmode=release --optimization=2)
                fi
            fi
            # The install_tag feature introduced in 0.60 causes meson to fail with fatal-meson-warnings
            # "Project targeting '>= 0.53.2' but tried to use feature introduced in '0.60.0': install_tag arg in custom_target"
            # It can be safely removed from the CI since it isn't actually used anywhere to test anything.
            find . -type f -name meson.build -exec sed -i '/install_tag/d' '{}' '+'
            MESON_ARGS+=(--fatal-meson-warnings)
            run_meson -Dnobody-group=nogroup --werror -Dtests=unsafe -Dslow-tests=true -Dfuzz-tests=true "${MESON_ARGS[@]}" build
            ninja -C build -v
            meson test -C build --print-errorlogs
            ;;
        RUN_ASAN_UBSAN|RUN_GCC_ASAN_UBSAN|RUN_CLANG_ASAN_UBSAN|RUN_CLANG_ASAN_UBSAN_NO_DEPS)
            MESON_ARGS=(--optimization=1)

            if [[ "$phase" =~ ^RUN_CLANG_ASAN_UBSAN ]]; then
                export CC=clang
                export CXX=clang++
                # Build fuzzer regression tests only with clang (for now),
                # see: https://github.com/systemd/systemd/pull/15886#issuecomment-632689604
                # -Db_lundef=false: See https://github.com/mesonbuild/meson/issues/764
                MESON_ARGS+=(-Db_lundef=false -Dfuzz-tests=true)

                if [[ "$phase" == "RUN_CLANG_ASAN_UBSAN_NO_DEPS" ]]; then
                    MESON_ARGS+=(-Dskip-deps=true)
                fi
            fi
            # The install_tag feature introduced in 0.60 causes meson to fail with fatal-meson-warnings
            # "Project targeting '>= 0.53.2' but tried to use feature introduced in '0.60.0': install_tag arg in custom_target"
            # It can be safely removed from the CI since it isn't actually used anywhere to test anything.
            find . -type f -name meson.build -exec sed -i '/install_tag/d' '{}' '+'
            MESON_ARGS+=(--fatal-meson-warnings)
            run_meson -Dnobody-group=nogroup --werror -Dtests=unsafe -Db_sanitize=address,undefined "${MESON_ARGS[@]}" build
            ninja -C build -v

            export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1

            # FIXME
            # For some strange reason the GH Actions VM stops responding after
            # executing first ~150 tests, _unless_ there's something producing
            # output (either running `meson test` in verbose mode, or something
            # else in background). Despite my efforts so far I haven't been able
            # to identify the culprit (since the issue is not reproducible
            # during debugging, wonderful), so let's at least keep a workaround
            # here to make the builds stable for the time being.
            (set +x; while :; do echo -ne "\n[WATCHDOG] $(date)\n"; sleep 30; done) &
            meson test --timeout-multiplier=3 -C build --print-errorlogs
            ;;
        CLEANUP)
            info "Cleanup phase"
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
