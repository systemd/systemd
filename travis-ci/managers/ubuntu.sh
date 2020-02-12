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
          expect
          util-linux)

bash -c "echo 'deb-src http://archive.ubuntu.com/ubuntu/ $RELEASE main restricted universe multiverse' >>/etc/apt/sources.list"

apt-get update
apt-get build-dep systemd -y
apt-get install -y "${PACKAGES[@]}"
pip3 install meson

cd ${REPO_ROOT:-$PWD}

sed -i 's/2\.30/2.27/' meson.build

# Sanitizer-specific options
export ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1
export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
export CC=clang
export CXX=clang++

# Blacklist for leaking libmount on Ubuntu Bionic
LSAN_SUPPRESSIONS="$PWD/lsan.supp"
cat > "$LSAN_SUPPRESSIONS" << EOF
# test-libmount
leak:mnt_new_fs
# test-umount
leak:vsscanf
EOF

export LSAN_OPTIONS=suppressions=$LSAN_SUPPRESSIONS

WRAPPER="$PWD/wrapper.sh"
cat > "$WRAPPER" << EOF
#!/bin/bash

export ASAN_OPTIONS=$ASAN_OPTIONS
export UBSAN_OPTIONS=$UBSAN_OPTIONS


if [[ \$(basename "\$1") == 'test-systemd-tmpfiles.py' ]]; then
    export SYSTEMD_LOG_LEVEL=debug
    echo "--- STAGE 1 ---" >> /tmp/tmpfiles.log
    timeout 10s python3 -uc 'print("hello world")' &>> /tmp/tmpfiles.log
    echo "--- STAGE 2 ---" >> /tmp/tmpfiles.log
    timeout 100s python3 -u -m trace -t "\$@" &>> /tmp/tmpfiles.log
    return \$?

    #export ASAN_OPTIONS=$ASAN_OPTIONS:detect_leaks=0
    #exec timeout 60s strace -s 500 "\$@" &> /tmp/tmpfiles.log
else
    exec "\$@"
fi
EOF

chmod +x "$WRAPPER"

# Temporary workaround for bugged shiftfs used in Travis LXD containers
# See:
#   - https://github.com/systemd/systemd/issues/14861
#   - https://github.com/systemd/systemd/pull/13785#issuecomment-585148492
unshare -m bash -x -c "
mount -t tmpfs tmpfs /tmp/
mount -t tmpfs tmpfs /var/tmp/

meson --werror \
      --optimization=2 \
      --buildtype=debug \
      -Dc_args='-fno-omit-frame-pointer -ftrapv' \
      -Db_sanitize=address,undefined \
      -Db_lundef=false \
      -Dtests=unsafe \
      -Dsplit-usr=true \
      -Dman=true \
      build
ninja -v -C build

#time python3 -u /home/travis/build/systemd/systemd/src/test/test-systemd-tmpfiles.py /home/travis/build/systemd/systemd/build/systemd-tmpfiles

export SYSTEMD_LOG_LEVEL=debug
export ASAN_OPTIONS=$ASAN_OPTIONS:debug=true:atexit=true:print_stats=true
echo 'f++ /too/many/plusses' > systemd-tmpfiles-test.conf
time unbuffer /home/travis/build/systemd/systemd/build/systemd-tmpfiles --create \$PWD/systemd-tmpfiles-test.conf

exit 1

if ! meson test -C build --print-errorlogs --timeout-multiplier=4 --wrapper=$WRAPPER; then
    tail -n500 /tmp/tmpfiles.log
    EC=1
else
    tail -n500 /tmp/tmpfiles.log
    EC=0
fi

time python3 -u /home/travis/build/systemd/systemd/src/test/test-systemd-tmpfiles.py /home/travis/build/systemd/systemd/build/systemd-tmpfiles

exit \$EC
"
