#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# shellcheck disable=SC2206
PHASES=(${@:-SETUP RUN RUN_ASAN_UBSAN CLEANUP})
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
    linux-tools-generic
    python3-libevdev
    python3-pip
    python3-pyelftools
    python3-pyparsing
    python3-pytest
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

MESON_ARGS=()

if [ "$(uname -m)" = "aarch64" ] || [ "$(uname -m)" = "x86_64" ]; then
    ADDITIONAL_DEPS+=(python3-pefile)
    ADDITIONAL_DEPS+=(systemd-boot-efi)
fi

# (Re)set the current oom-{score-}adj. For some reason root on GH actions is able to _decrease_
# its oom-score even after dropping all capabilities (including CAP_SYS_RESOURCE), until the
# score is explicitly changed after sudo. No idea what's going on, but it breaks
# exec-oomscoreadjust-negative.service from test-execute when running unprivileged.
choom -p $$ -n 0

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            # This is added by default, and it is often broken, but we don't need anything from it
            rm -f /etc/apt/sources.list.d/microsoft-prod.{list,sources}
            # add-apt-repository --enable-source does not work on deb822 style sources.
            for f in /etc/apt/sources.list.d/*.sources; do
                sed -i "s/Types: deb/Types: deb deb-src/g" "$f"
            done
            apt-get -y update
            apt-get -y build-dep systemd
            apt-get -y install "${ADDITIONAL_DEPS[@]}"
            pip3 install -r .github/workflows/requirements.txt --require-hashes --break-system-packages

            # Make sure the build dir is accessible even when drop privileges, otherwise the unprivileged
            # part of test-execute gets skipped, since it can't run systemd-executor
            chmod o+x /home/runner
            capsh --drop=all -- -c "stat $PWD/meson.build"
            ;;
        RUN|RUN_GCC|RUN_CLANG|RUN_CLANG_RELEASE)
            # TODO: drop after we switch to ubuntu 26.04
            bpftool_dir=$(dirname "$(find /usr/lib/linux-tools/ /usr/lib/linux-tools-* -name 'bpftool' -perm /u=x 2>/dev/null | sort -r | head -n1)")
            if [ -n "$bpftool_dir" ]; then
                export PATH="$bpftool_dir:$PATH"
            fi

            if [[ "$phase" =~ ^RUN_CLANG ]]; then
                export CC=clang
                export CXX=clang++
                export CFLAGS="-fno-sanitize=function"
                export CXXFLAGS="-fno-sanitize=function"
                if [[ "$phase" == RUN_CLANG ]]; then
                    # The docs build is slow and is not affected by compiler/flags, so do it just once
                    MESON_ARGS+=(-Dman=enabled)
                else
                    MESON_ARGS+=(-Dmode=release --optimization=2)
                fi

                # Some variation: remove machine-id, like on Debian builders to ensure unit tests still work.
                if [ -w /etc/machine-id ]; then
                    mv /etc/machine-id /etc/machine-id.bak
                fi
            fi

            # On ppc64le the workers are slower and some slow tests time out
            MESON_TEST_ARGS=()
            if [[ "$(uname -m)" != "x86_64" ]] && [[ "$(uname -m)" != "aarch64" ]]; then
                MESON_TEST_ARGS+=(--timeout-multiplier=3)
            fi

            MESON_ARGS+=(--fatal-meson-warnings)
            run_meson -Dnobody-group=nogroup --werror -Dtests=unsafe -Dslow-tests=true -Dfuzz-tests=true "${MESON_ARGS[@]}" build
            ninja -C build -v
            # Ensure setting a timezone (like the reproducible build tests do) does not break time/date unit tests
            TZ=GMT+12 meson test "${MESON_TEST_ARGS[@]}" -C build --print-errorlogs --no-stdsplit
            ;;
        RUN_ASAN_UBSAN|RUN_GCC_ASAN_UBSAN|RUN_CLANG_ASAN_UBSAN|RUN_CLANG_ASAN_UBSAN_NO_DEPS)
            # TODO: drop after we switch to ubuntu 26.04
            bpftool_dir=$(dirname "$(find /usr/lib/linux-tools/ /usr/lib/linux-tools-* -name 'bpftool' -perm /u=x 2>/dev/null | sort -r | head -n1)")
            if [ -n "$bpftool_dir" ]; then
                export PATH="$bpftool_dir:$PATH"
            fi

            MESON_ARGS=(--optimization=1)

            if [[ "$phase" =~ ^RUN_CLANG_ASAN_UBSAN ]]; then
                export CC=clang
                export CXX=clang++
                export CFLAGS="-fno-sanitize=function"
                export CXXFLAGS="-fno-sanitize=function"
                # Build fuzzer regression tests only with clang (for now),
                # see: https://github.com/systemd/systemd/pull/15886#issuecomment-632689604
                # -Db_lundef=false: See https://github.com/mesonbuild/meson/issues/764
                MESON_ARGS+=(-Db_lundef=false -Dfuzz-tests=true)

                if [[ "$phase" == "RUN_CLANG_ASAN_UBSAN_NO_DEPS" ]]; then
                    MESON_ARGS+=(--auto-features=disabled -Dnspawn=enabled)
                fi
            fi
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
            meson test --timeout-multiplier=3 -C build --print-errorlogs --no-stdsplit
            ;;
        CLEANUP)
            info "Cleanup phase"
            if [ ! -f /etc/machine-id ] && [ -w /etc/machine-id.bak ]; then
                mv /etc/machine-id.bak /etc/machine-id
            fi
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
