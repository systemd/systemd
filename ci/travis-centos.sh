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
ADDITIONAL_DEPS=(yum-utils iputils hostname libasan libubsan clang llvm)

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
            # Install necessary build/test requirements
            $DOCKER_EXEC yum -y --exclude selinux-policy\* upgrade
            $DOCKER_EXEC yum -y install "${ADDITIONAL_DEPS[@]}"
            $DOCKER_EXEC yum-builddep -y systemd
            ;;
        RUN)
            info "Run phase"
            # Build systemd
            $DOCKER_EXEC ./autogen.sh
            $DOCKER_EXEC ./configure --disable-timesyncd --disable-kdbus --disable-terminal \
                                     --enable-gtk-doc --enable-compat-libs --disable-sysusers \
                                     --disable-ldconfig --enable-lz4 --with-sysvinit-path=/etc/rc.d/init.d
            $DOCKER_EXEC make
            if ! $DOCKER_EXEC make check; then
                $DOCKER_EXEC cat test-suite.log
                exit 1
            fi
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
