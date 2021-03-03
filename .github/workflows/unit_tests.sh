#!/bin/bash

PHASES=(${@:-SETUP RUN CLEANUP})
CENTOS_RELEASE="${CENTOS_RELEASE:-latest}"
CONT_NAME="${CONT_NAME:-centos-$CENTOS_RELEASE-$RANDOM}"
DOCKER_EXEC="${DOCKER_EXEC:-docker exec $CONT_NAME}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(libasan libubsan net-tools strace nc e2fsprogs quota dnsmasq diffutils)
# RHEL8 options
CONFIGURE_OPTS=(
    -Dsysvinit-path=/etc/rc.d/init.d
    -Drc-local=/etc/rc.d/rc.local
    -Ddns-servers=''
    -Ddev-kvm-mode=0666
    -Dkmod=true
    -Dxkbcommon=true
    -Dblkid=true
    -Dseccomp=true
    -Dima=true
    -Dselinux=true
    -Dapparmor=false
    -Dpolkit=true
    -Dxz=true
    -Dzlib=true
    -Dbzip2=true
    -Dlz4=true
    -Dpam=true
    -Dacl=true
    -Dsmack=true
    -Dgcrypt=true
    -Daudit=true
    -Delfutils=true
    -Dlibcryptsetup=true
    -Delfutils=true
    -Dqrencode=false
    -Dgnutls=true
    -Dmicrohttpd=true
    -Dlibidn2=true
    -Dlibiptc=true
    -Dlibcurl=true
    -Defi=true
    -Dtpm=true
    -Dhwdb=true
    -Dsysusers=true
    -Ddefault-kill-user-processes=false
    -Dtests=unsafe
    -Dinstall-tests=true
    -Dtty-gid=5
    -Dusers-gid=100
    -Dnobody-user=nobody
    -Dnobody-group=nobody
    -Dsplit-usr=false
    -Dsplit-bin=true
    -Db_lto=false
    -Dnetworkd=false
    -Dtimesyncd=false
    -Ddefault-hierarchy=legacy
)

# CentOS 8 Stream still doesn't provide SRPMs, so we can't use dnf's builddep
# command to fetch this list for us. Hopefully, we'll be able to get rid
# of this in the future.
# See: https://bugs.centos.org/view.php?id=16715
SYSTEMD_BUILD_DEPS=(
        audit-libs-devel
        bzip2-devel
        cryptsetup-devel
        dbus-devel
        docbook-style-xsl
        elfutils-devel
        firewalld-filesystem
        gcc
        gcc-c++
        gettext
        git
        gnu-efi
        gnu-efi-devel
        gnutls-devel
        gobject-introspection-devel
        gperf
        iptables-devel
        kmod-devel
        libacl-devel
        libblkid-devel
        libcap-devel
        libcurl-devel
        libgcrypt-devel
        libgpg-error-devel
        libidn2-devel
        libmicrohttpd-devel
        libmount-devel
        libseccomp-devel
        libselinux-devel
        libxkbcommon-devel
        libxslt
        lz4
        lz4-devel
        meson
        pam-devel
        pkgconf-pkg-config
        python3-lxml
        python36-devel
        tree
        xz-devel
)

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

set -ex

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            info "Using $CENTOS_RELEASE image"
            # Pull a Docker image and start a new container
            docker pull quay.io/centos/centos:$CENTOS_RELEASE
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host quay.io/centos/centos:$CENTOS_RELEASE /sbin/init

            # Beautiful workaround for Fedora's version of Docker
            sleep 1
            $DOCKER_EXEC dnf makecache
            # Install and enable EPEL
            $DOCKER_EXEC dnf -q -y install epel-release dnf-utils "${ADDITIONAL_DEPS[@]}"
            $DOCKER_EXEC dnf config-manager -q --enable epel
            # Upgrade the container to get the most recent environment
            $DOCKER_EXEC dnf -y upgrade
            # Install systemd's build dependencies
            if ! $DOCKER_EXEC dnf -q -y --enablerepo "powertools" builddep systemd; then
                    # See the $SYSTEMD_BUILD_DEPS above for reasoning
                    $DOCKER_EXEC dnf -q -y --enablerepo "powertools" install "${SYSTEMD_BUILD_DEPS[@]}"
            fi
            ;;
        RUN|RUN_GCC)
            info "Run phase"
            # Build systemd
            docker exec -e CFLAGS='-g -O0 -ftrapv' $CONT_NAME meson build -Dtests=unsafe -Dslow-tests=true "${CONFIGURE_OPTS[@]}"
            $DOCKER_EXEC ninja -v -C build
            # Let's install the new systemd and "reboot" the container to avoid
            # unexpected fails due to incompatibilities with older systemd
            $DOCKER_EXEC ninja -C build install
            docker restart $CONT_NAME
            $DOCKER_EXEC ninja -C build test
            ;;
        RUN_ASAN|RUN_GCC_ASAN|RUN_CLANG_ASAN)
            if [[ "$phase" = "RUN_CLANG_ASAN" ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                MESON_ARGS="-Db_lundef=false" # See https://github.com/mesonbuild/meson/issues/764
            fi
            docker exec $ENV_VARS $CONT_NAME meson build --werror -Dtests=unsafe -Db_sanitize=address,undefined $MESON_ARGS "${CONFIGURE_OPTS[@]}"
            docker exec $CONT_NAME ninja -v -C build

            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            docker exec --interactive=false \
                -e UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1 \
                -e ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1 \
                -t $CONT_NAME \
                meson test --timeout-multiplier=3 -C ./build/ --print-errorlogs
            ;;
        CLEANUP)
            info "Cleanup phase"
            docker stop $CONT_NAME
            docker rm -f $CONT_NAME
            ;;
        *)
            echo >&2 "Unknown phase '$phase'"
            exit 1
    esac
done
