#!/bin/bash
set -ex

RELEASE="${1:-bionic}"

PACKAGES=(clang
          cryptsetup-bin
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
#          libmount-dev
          libqrencode-dev
          libxkbcommon-dev
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
          quota
          strace
          unifont
          util-linux)

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"

apt-get update
apt-get build-dep systemd -y
apt-get install -y "${PACKAGES[@]}"
pip3 install meson

cd ${REPO_ROOT:-$PWD}

sed -i 's/2\.30/2.27/' meson.build

# Sanitizer-specific options
#export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
#export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
#export CC=clang
#export CXX=clang++

systemd-detect-virt
cat /proc/1/mountinfo
unshare -m bash -x -c "
mount -t tmpfs tmpfs /tmp/
mount -t tmpfs tmpfs /var/tmp/

meson --werror \
      --optimization=0 \
      --buildtype=debug \
      -Dc_args='-fno-omit-frame-pointer -ftrapv' \
      -Dtests=unsafe \
      -Dsplit-usr=true \
      -Dman=true \
      build
ninja -v -C build
meson test -C build --print-errorlogs --timeout-multiplier=4"
