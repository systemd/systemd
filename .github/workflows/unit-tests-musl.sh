#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

# shellcheck disable=SC2206
PHASES=(${@:-SETUP BUILD RUN CLEANUP})

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

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"

            # Alpine still uses split-usr.
            for i in /bin/* /sbin/*; do
                ln -rs "$i" "/usr/$i";
            done
            ;;
        BUILD)
            info "Build systemd phase"

            run_meson setup --werror -Dtests=unsafe -Dslow-tests=true -Dfuzz-tests=true -Dlibc=musl build
            ninja -v -C build
            ;;
        RUN)
            info "Run phase"

            # Create dummy machine ID.
            echo '052e58f661f94bd080e258b96aea3f7b' >/etc/machine-id

            # Start dbus for several unit tests.
            mkdir -p /var/run/dbus
            /usr/bin/dbus-daemon --system || :

            # Here, we explicitly set SYSTEMD_IN_CHROOT=yes as unfortunately runnin_in_chroot() does not
            # correctly detect the environment.
            env \
                SYSTEMD_IN_CHROOT=yes \
                meson test -C build --print-errorlogs --no-stdsplit
            ;;
        CLEANUP)
            info "Cleanup phase"
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
