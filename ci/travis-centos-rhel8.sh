#!/bin/bash

# Run this script from the root of the systemd's git repository
# or set REPO_ROOT to a correct path.
#
# Example execution on Fedora:
# dnf install docker
# systemctl start docker
# export CONT_NAME="my-fancy-container"
# ci/travis-centos.sh SETUP RUN CLEANUP

PHASES=(${@:-SETUP RUN CLEANUP})
CENTOS_RELEASE="${CENTOS_RELEASE:-latest}"
CONT_NAME="${CONT_NAME:-centos-$CENTOS_RELEASE-$RANDOM}"
DOCKER_EXEC="${DOCKER_EXEC:-docker exec -it $CONT_NAME}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(systemd-ci-environment libidn2-devel python-lxml python36 ninja-build libasan net-tools strace nc busybox e2fsprogs quota dnsmasq)
# Repo with additional depencencies to compile newer systemd on CentOS 7
COPR_REPO="https://copr.fedorainfracloud.org/coprs/mrc0mmand/systemd-centos-ci/repo/epel-7/mrc0mmand-systemd-centos-ci-epel-7.repo"
COPR_REPO_PATH="/etc/yum.repos.d/${COPR_REPO##*/}"
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
    # Custom options
    -Dslow-tests=true
    -Dtests=unsafe
    -Dinstall-tests=true
)

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

set -e

source "$(dirname $0)/travis_wait.bash"

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            info "Using Travis $CENTOS_RELEASE"
            # Pull a Docker image and start a new container
            docker pull centos:$CENTOS_RELEASE
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host centos:$CENTOS_RELEASE /sbin/init
            # Beautiful workaround for Fedora's version of Docker
            sleep 1
            $DOCKER_EXEC yum makecache
            $DOCKER_EXEC curl "$COPR_REPO" -o "$COPR_REPO_PATH"
            $DOCKER_EXEC yum -q -y install epel-release yum-utils
            $DOCKER_EXEC yum-config-manager -q --enable epel
            $DOCKER_EXEC yum -y upgrade
            # Install necessary build/test requirements
            $DOCKER_EXEC yum -y install "${ADDITIONAL_DEPS[@]}"
            $DOCKER_EXEC python3.6 -m ensurepip
            $DOCKER_EXEC python3.6 -m pip install meson
            # Create necessary symlinks
            $DOCKER_EXEC ln --force -s /usr/bin/python3.6 /usr/bin/python3
            $DOCKER_EXEC ln --force -s /usr/bin/ninja-build /usr/bin/ninja
            ;;
        RUN)
            info "Run phase"
            # Build systemd
            docker exec -it -e CFLAGS='-g -O0 -ftrapv' $CONT_NAME meson build "${CONFIGURE_OPTS[@]}"
            $DOCKER_EXEC ninja -v -C build
            # Let's install the new systemd and "reboot" the container to avoid
            # unexpected fails due to incompatibilities with older systemd
            $DOCKER_EXEC ninja -C build install
            docker restart $CONT_NAME
            # "Mask" the udev-test.pl, as it requires newer version of systemd-detect-virt
            # and it's pointless to run it on a VM in a Docker container...
            echo -ne "#!/usr/bin/perl\nexit(0);\n" > "test/udev-test.pl"
            $DOCKER_EXEC ninja -C build test
            ;;
        RUN_ASAN|RUN_CLANG_ASAN)
            # Let's install newer gcc for proper ASan/UBSan support
            $DOCKER_EXEC yum -y install centos-release-scl
            $DOCKER_EXEC yum -y install devtoolset-8 devtoolset-8-libasan-devel libasan5 devtoolset-8-libubsan-devel libubsan1
            $DOCKER_EXEC bash -c "echo 'source scl_source enable devtoolset-8' >> /root/.bashrc"
            # Note to my future frustrated self: docker exec runs the given command
            # as sh -c 'command' - which means both .bash_profile and .bashrc will
            # be ignored. That's because .bash_profile is sourced for LOGIN shells (i.e.
            # sh -l), whereas .bashrc is sourced for NON-LOGIN INTERACTIVE shells
            # (i.e. sh -i).
            # As the default docker exec command lacks either of those options,
            # we need to use a wrapper command which runs the wanted command
            # under an explicit bash -i, so the SCL source above works properly.
            docker exec -it $CONT_NAME bash -ic 'gcc --version'

            if [[ "$phase" = "RUN_CLANG_ASAN" ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                MESON_ARGS="-Db_lundef=false" # See https://github.com/mesonbuild/meson/issues/764
            fi
            docker exec $ENV_VARS -it $CONT_NAME bash -ic "meson build --werror -Dtests=unsafe -Db_sanitize=address,undefined $MESON_ARGS ${CONFIGURE_OPTS[@]}"
            docker exec -it $CONT_NAME bash -ic 'ninja -v -C build'

            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            travis_wait docker exec --interactive=false \
                -e UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1 \
                -e ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1 \
                -e "TRAVIS=$TRAVIS" \
                -t $CONT_NAME \
                bash -ic 'meson test --timeout-multiplier=3 -C ./build/ --print-errorlogs'
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
