#!/bin/bash
set -e
set -x

PACKAGES=(cryptsetup-bin
          gettext
          iptables-dev
          iputils-ping
          isc-dhcp-client
          itstool
          kbd
          libblkid-dev
          libcap-dev
          libcurl4-gnutls-dev
          libgpg-error-dev
          liblz4-dev
          liblzma-dev
          libmicrohttpd-dev
          libmount-dev
          libmount-dev
          libqrencode-dev
          libxkbcommon-dev
          linux-image-virtual
          mount
          net-tools
          ninja-build
          perl
          python-lxml
          python3-evdev
          python3-lxml
          python3-pip
          python3-pyparsing
          python3-setuptools
          qemu-system-x86
          quota
          strace
          unifont
          util-linux)

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ xenial main restricted universe multiverse' >>/etc/apt/sources.list"

apt-get update
apt-get build-dep systemd -y
apt-get install -y "${PACKAGES[@]}"
pip3 install meson

cd ${REPO_ROOT:-$PWD}

sed -i 's/2\.30/2.27/' meson.build

meson --werror -Db_sanitize=address,undefined -Dsplit-usr=true -Dman=true build
ninja -v -C build

make -C test/TEST-01-BASIC clean setup run NSPAWN_TIMEOUT=600 TEST_NO_QEMU=yes NSPAWN_ARGUMENTS=--keep-unit RUN_IN_UNPRIVILEGED_CONTAINER=no

# Now that we're more or less sure that ASan isn't going to crash systemd and cause a kernel panic
# let's also run the test with QEMU to cover udevd, sysctl and everything else that isn't run
# in containers.

# This should be turned on once `journalctl --flush` isn't flaky any more
#make -C test/TEST-01-BASIC clean setup run QEMU_TIMEOUT=900 TEST_NO_NSPAWN=yes
