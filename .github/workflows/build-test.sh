#!/usr/bin/env bash
# SPDX-License-Identifier: LGPL-2.1-or-later

set -ex

shopt -s nullglob

info() { echo -e "\033[33;1m$1\033[0m"; }
fatal() { echo >&2 -e "\033[31;1m$1\033[0m"; exit 1; }
success() { echo >&2 -e "\033[32;1m$1\033[0m"; }

ARGS=(
    "--optimization=0 -Dopenssl=disabled -Dtpm=true -Dtpm2=enabled"
    "--optimization=s -Dutmp=false -Dc_args='-DOPENSSL_NO_UI_CONSOLE=1'"
    "--optimization=2 -Dc_args=-Wmaybe-uninitialized -Ddns-over-tls=openssl"
    "--optimization=3 -Db_lto=true -Ddns-over-tls=false"
    "--optimization=3 -Db_lto=false -Dtpm2=disabled -Dlibfido2=disabled -Dp11kit=disabled -Defi=false -Dbootloader=disabled"
    "--optimization=3 -Dfexecve=true -Dstandalone-binaries=true -Dstatic-libsystemd=true -Dstatic-libudev=true"
    "-Db_ndebug=true"
)
# Packages that are always native (i.e.: tools that run on the host) go in this list
PACKAGES=(
    cryptsetup-bin
    expect
    fdisk
    gettext
    iputils-ping
    isc-dhcp-client
    itstool
    kbd
    linux-tools-generic
    mold
    mount
    net-tools
    python3-evdev
    python3-jinja2
    python3-lxml
    python3-pefile
    python3-pip
    python3-pyelftools
    python3-pyparsing
    python3-setuptools
    quota
    strace
    unifont
    util-linux
    zstd
)
# Packages that are needed for the target architecture (i.e.: libraries) go in this list
DEVEL_PACKAGES=(
    libarchive-dev
    libblkid-dev
    libbpf-dev
    libcurl4-gnutls-dev
    libfdisk-dev
    libfido2-dev
    libgpg-error-dev
    liblz4-dev
    liblzma-dev
    libmicrohttpd-dev
    libmount-dev
    libp11-kit-dev
    libpwquality-dev
    libqrencode-dev
    libssl-dev
    libtss2-dev
    libxkbcommon-dev
    libxtables-dev
    libzstd-dev
)
FEATURES=()
COMPILER="${COMPILER:?}"
COMPILER_VERSION="${COMPILER_VERSION:?}"
LINKER="${LINKER:?}"
RELEASE="$(lsb_release -cs)"
CROSS_ARCH="${CROSS_ARCH:-}"
CROSS_FILE=()

if [[ -z "$CROSS_ARCH" ]] && [[ "$(uname -m)" =~ ^(aarch64|x86_64)$ ]]; then
    DEVEL_PACKAGES+=(libxen-dev)
fi

# If CROSS_ARCH is set, append :<arch> to the packages so they get installed for the target
PACKAGES+=("${DEVEL_PACKAGES[@]/%/${CROSS_ARCH:+:$CROSS_ARCH}}")

# Note: As we use postfixed clang/gcc binaries, we need to override $AR
#       as well, otherwise meson falls back to ar from binutils which
#       doesn't work with LTO
if [[ -n "$CROSS_ARCH" ]]; then
    if [[ "$COMPILER" != gcc ]]; then
        fatal "$CROSS_ARCH cross builds are only supported with gcc"
    fi

    case "$CROSS_ARCH" in
        armhf)
            triplet=arm-linux-gnueabihf
            ;;
        riscv64)
            triplet=riscv64-linux-gnu
            ;;
        *)
            fatal "Unsupported cross architecture: $CROSS_ARCH"
            ;;
    esac

    CC="$triplet-gcc"
    CXX="$triplet-g++"
    AR="$triplet-gcc-ar"
    CFLAGS="-Wno-maybe-uninitialized"
    CXXFLAGS=""
    CROSS_FILE=(--cross-file ".github/workflows/$CROSS_ARCH-gcc.cross")
    FEATURES+=(-Ddbus-interfaces-dir=no -Dsbat-distro=)
    PACKAGES+=("crossbuild-essential-$CROSS_ARCH")
elif [[ "$COMPILER" == clang ]]; then
    CC="clang-$COMPILER_VERSION"
    CXX="clang++-$COMPILER_VERSION"
    AR="llvm-ar-$COMPILER_VERSION"

    if systemd-analyze compare-versions "$COMPILER_VERSION" ge 17; then
        CFLAGS="-fno-sanitize=function"
        CXXFLAGS="-fno-sanitize=function"
    else
        CFLAGS=""
        CXXFLAGS=""
    fi

    # Prefer the distro version if available
    if ! apt-get -y install --dry-run "llvm-$COMPILER_VERSION" >/dev/null; then
        # Latest LLVM stack deb packages provided by https://apt.llvm.org/
        # Following snippet was partly borrowed from https://apt.llvm.org/llvm.sh
        wget -O - https://apt.llvm.org/llvm-snapshot.gpg.key | \
            sudo gpg --yes --dearmor --output /usr/share/keyrings/apt-llvm-org.gpg
        echo "deb [signed-by=/usr/share/keyrings/apt-llvm-org.gpg] http://apt.llvm.org/$RELEASE/ llvm-toolchain-$RELEASE-$COMPILER_VERSION main" | \
            sudo tee /etc/apt/sources.list.d/llvm-toolchain.list
    fi

    PACKAGES+=("clang-$COMPILER_VERSION" "lldb-$COMPILER_VERSION" "python3-lldb-$COMPILER_VERSION" "lld-$COMPILER_VERSION" "clangd-$COMPILER_VERSION" "llvm-$COMPILER_VERSION")
elif [[ "$COMPILER" == gcc ]]; then
    CC="gcc-$COMPILER_VERSION"
    CXX="g++-$COMPILER_VERSION"
    AR="gcc-ar-$COMPILER_VERSION"
    CFLAGS=""
    CXXFLAGS=""

    if ! apt-get -y install --dry-run "gcc-$COMPILER_VERSION" >/dev/null; then
        # Latest gcc stack deb packages provided by
        # https://launchpad.net/~ubuntu-toolchain-r/+archive/ubuntu/test
        sudo add-apt-repository -y --no-update ppa:ubuntu-toolchain-r/test
    fi

    PACKAGES+=("gcc-$COMPILER_VERSION")
    if [ "$(uname -m)" = "x86_64" ]; then
        # Only needed for ia32 EFI builds
        PACKAGES+=("gcc-$COMPILER_VERSION-multilib")
    fi
else
    fatal "Unknown compiler: $COMPILER"
fi

# This is added by default, and it is often broken, but we don't need anything from it
sudo rm -f /etc/apt/sources.list.d/microsoft-prod.{list,sources}
if grep -q 'VERSION_CODENAME=jammy' /usr/lib/os-release; then
    sudo add-apt-repository -y --no-update ppa:upstream-systemd-ci/systemd-ci
    sudo add-apt-repository -y --no-update --enable-source
    # Jammy's kernel is too old and there's no vmlinux.h
    FEATURES+=("-Dbpf-framework=disabled")
else
    # add-apt-repository --enable-source does not work on deb822 style sources.
    for f in /etc/apt/sources.list.d/*.sources; do
        sudo sed -i "s/Types: deb/Types: deb deb-src/g" "$f"
    done
fi
if [[ -n "$CROSS_ARCH" ]]; then
    sudo dpkg --add-architecture "$CROSS_ARCH"
fi
sudo apt-get -y update
sudo apt-get -y build-dep systemd ${CROSS_ARCH:+--host-architecture=$CROSS_ARCH}
sudo apt-get -y install "${PACKAGES[@]}"
# Install more or less recent meson and ninja with pip, since the distro versions don't
# always support all the features we need (like --optimization=). Since the build-dep
# command above installs the distro versions, let's install the pip ones just
# locally and add the local bin directory to the $PATH.
pip3 install --user -r .github/workflows/requirements.txt --require-hashes --break-system-packages
export PATH="$HOME/.local/bin:$PATH"

# TODO: drop after we switch to ubuntu 26.04
bpftool_dir=$(dirname "$(find /usr/lib/linux-tools/ /usr/lib/linux-tools-* -name 'bpftool' -perm /u=x 2>/dev/null | sort -r | head -n1)")
if [ -n "$bpftool_dir" ]; then
    export PATH="$bpftool_dir:$PATH"
fi

if [[ -n "$CUSTOM_PYTHON" ]]; then
    # If CUSTOM_PYTHON is set we need to pull dependencies from pip, as a local interpreter is used
    pip3 install --user --break-system-packages jinja2 pefile
fi

$CC --version
meson --version
ninja --version

for args in "${ARGS[@]}"; do
    SECONDS=0

    if [[ "$COMPILER" == clang && "$args" =~ Wmaybe-uninitialized ]]; then
        # -Wmaybe-uninitialized is not implemented in clang
        continue
    fi

    info "Checking build with $args"
    # shellcheck disable=SC2086
    if ! AR="$AR" \
         CC="$CC" CC_LD="$LINKER" CFLAGS="$CFLAGS" \
         CXX="$CXX" CXX_LD="$LINKER" CXXFLAGS="$CXXFLAGS" \
         meson setup \
               -Dtests=unsafe -Dslow-tests=true -Dfuzz-tests=true --werror \
               -Dnobody-group=nogroup -Ddebug=false \
               "${FEATURES[@]}" \
               "${CROSS_FILE[@]}" \
               $args build; then

        cat build/meson-logs/meson-log.txt
        fatal "meson failed with $args"
    fi

    if ! meson compile -C build -v; then
        fatal "'meson compile' failed with '$args'"
    fi

    for loader in build/src/boot/efi/*{.efi,.efi.stub}; do
        if [[ "$(sbverify --list "$loader" 2>&1)" != "No signature table present" ]]; then
            fatal "$loader: Gaps found in section table"
        fi
    done

    git clean -dxf

    success "Build with '$args' passed in $SECONDS seconds"
done
