#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -eux
set -o pipefail

# default to Debian testing
DISTRO="${DISTRO:-debian}"
RELEASE="${RELEASE:-bullseye}"
BRANCH="${BRANCH:-upstream-ci}"
ARCH="${ARCH:-amd64}"
CONTAINER="${RELEASE}-${ARCH}"
CACHE_DIR="${SEMAPHORE_CACHE_DIR:-/tmp}"
AUTOPKGTEST_DIR="${CACHE_DIR}/autopkgtest"
# semaphore cannot expose these, but useful for interactive/local runs
ARTIFACTS_DIR=/tmp/artifacts
# shellcheck disable=SC2206
PHASES=(${@:-SETUP RUN})
UBUNTU_RELEASE="$(lsb_release -cs)"

create_container() {
    sudo lxc-create -n "$CONTAINER" -t download -- -d "$DISTRO" -r "$RELEASE" -a "$ARCH"

    # unconfine the container, otherwise some tests fail
    echo 'lxc.apparmor.profile = unconfined' | sudo tee -a "/var/lib/lxc/$CONTAINER/config"

    sudo lxc-start -n "$CONTAINER"

    # enable source repositories so that apt-get build-dep works
    sudo lxc-attach -n "$CONTAINER" -- sh -ex <<EOF
sed 's/^deb/deb-src/' /etc/apt/sources.list >> /etc/apt/sources.list.d/sources.list
# We might attach the console too soon
while ! systemctl --quiet --wait is-system-running; do sleep 1; done
# Manpages database trigger takes a lot of time and is not useful in a CI
echo 'man-db man-db/auto-update boolean false' | debconf-set-selections
# Speed up dpkg, image is thrown away after the test
mkdir -p /etc/dpkg/dpkg.cfg.d/
echo 'force-unsafe-io' > /etc/dpkg/dpkg.cfg.d/unsafe_io
# For some reason, it is necessary to run this manually or the interface won't be configured
# Note that we avoid networkd, as some of the tests will break it later on
dhclient
apt-get -q --allow-releaseinfo-change update
apt-get -y dist-upgrade
apt-get install -y eatmydata
# The following four are needed as long as these deps are not covered by Debian's own packaging
apt-get install -y fdisk tree libfdisk-dev libp11-kit-dev libssl-dev libpwquality-dev rpm
apt-get purge --auto-remove -y unattended-upgrades
systemctl unmask systemd-networkd
systemctl enable systemd-networkd
EOF
    sudo lxc-stop -n "$CONTAINER"
}

for phase in "${PHASES[@]}"; do
    case "$phase" in
        SETUP)
            # remove semaphore repos, some of them don't work and cause error messages
            sudo rm -rf /etc/apt/sources.list.d/*

            # enable backports for latest LXC
            echo "deb http://archive.ubuntu.com/ubuntu $UBUNTU_RELEASE-backports main restricted universe multiverse" | sudo tee -a /etc/apt/sources.list.d/backports.list
            sudo apt-get -q update
            sudo apt-get install -y -t "$UBUNTU_RELEASE-backports" lxc
            sudo apt-get install -y python3-debian git dpkg-dev fakeroot python3-jinja2

            [ -d "$AUTOPKGTEST_DIR" ] || git clone --quiet --depth=1 https://salsa.debian.org/ci-team/autopkgtest.git "$AUTOPKGTEST_DIR"

            create_container
        ;;
        RUN)
            # add current debian/ packaging
            git fetch --depth=1 https://salsa.debian.org/systemd-team/systemd.git "$BRANCH"
            git checkout FETCH_HEAD debian

            # craft changelog
            UPSTREAM_VER="$(git describe | sed 's/^v//;s/-/./g')"
            cat << EOF > debian/changelog.new
systemd (${UPSTREAM_VER}.0) UNRELEASED; urgency=low

  * Automatic build for upstream test

 -- systemd test <pkg-systemd-maintainers@lists.alioth.debian.org>  $(date -R)

EOF
            cat debian/changelog >>debian/changelog.new
            mv debian/changelog.new debian/changelog

            # clean out patches
            rm -rf debian/patches
            # disable autopkgtests which are not for upstream
            sed -i '/# NOUPSTREAM/ q' debian/tests/control
            # enable more unit tests
            sed -i '/^CONFFLAGS =/ s/=/= --werror -Dtests=unsafe -Dsplit-usr=true -Dslow-tests=true -Dfuzz-tests=true -Dman=true /' debian/rules
            # no orig tarball
            echo '1.0' > debian/source/format

            # build source package
            dpkg-buildpackage -S -I -I"$(basename "$CACHE_DIR")" -d -us -uc -nc

            # now build the package and run the tests
            rm -rf "$ARTIFACTS_DIR"
            # autopkgtest exits with 2 for "some tests skipped", accept that
            sudo "$AUTOPKGTEST_DIR/runner/autopkgtest" --env DEB_BUILD_OPTIONS=noudeb \
                                                       --env TEST_UPSTREAM=1 ../systemd_*.dsc \
                                                       -o "$ARTIFACTS_DIR" \
                                                       -- lxc -s "$CONTAINER" \
                || [ $? -eq 2 ]
        ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
