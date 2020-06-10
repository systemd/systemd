#!/bin/bash

set -e

info() { echo -e "\033[33;1m$1\033[0m"; }
error() { echo >&2 -e "\033[31;1m$1\033[0m"; }
success() { echo >&2 -e "\033[32;1m$1\033[0m"; }

ARGS=(
    "--optimization=0"
    "--optimization=2"
    "--optimization=3"
    "--optimization=s"
    "-Db_lto=true"
    "-Db_ndebug=true"
)
PACKAGES=(
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
    libmount-dev
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
    expect
    util-linux
)
CC="${CC:?}"
CXX="${CXX:?}"
AR="${AR:-""}"
RELEASE="$(lsb_release -cs)"

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"

apt-get update
apt-get build-dep systemd -y
apt-get install -y "${PACKAGES[@]}"
# Install latest meson from pip, as the distro-one doesn't support
# --optimization=
pip3 install meson

$CC --version

for args in "${ARGS[@]}"; do
    SECONDS=0

    info "Checking build with $args"
    if ! AR="$AR" CC="$CC" CXX="$CXX" meson --werror $args build; then
        error "meson failed with $args"
        exit 1
    fi

    if ! ninja -C build; then
        error "ninja failed with $args"
        exit 1
    fi

    git clean -dxf

    success "Build with $args passed in $SECONDS seconds"
done
