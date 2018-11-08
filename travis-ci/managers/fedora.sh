#!/bin/bash

# Run this script from the root of the systemd's git repository
# or set REPO_ROOT to a correct path.
#
# Example execution on Fedora:
# dnf install docker
# systemctl start docker
# export CONT_NAME="my-fancy-container"
# travis-ci/managers/fedora.sh SETUP RUN CLEANUP

PHASES=(${@:-SETUP RUN RUN_ASAN CLEANUP})
FEDORA_RELEASE="${FEDORA_RELEASE:-rawhide}"
CONT_NAME="${CONT_NAME:-fedora-$FEDORA_RELEASE-$RANDOM}"
DOCKER_EXEC="${DOCKER_EXEC:-docker exec -it $CONT_NAME}"
DOCKER_RUN="${DOCKER_RUN:-docker run}"
REPO_ROOT="${REPO_ROOT:-$PWD}"
ADDITIONAL_DEPS=(dnf-plugins-core python2 iputils hostname libasan python3-pyparsing python3-evdev libubsan)

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

set -e

for phase in "${PHASES[@]}"; do
    case $phase in
        SETUP)
            info "Setup phase"
            info "Using Fedora $FEDORA_RELEASE"
            # Pull a Docker image and start a new container
            docker pull fedora:$FEDORA_RELEASE
            info "Starting container $CONT_NAME"
            $DOCKER_RUN -v $REPO_ROOT:/build:rw \
                        -w /build --privileged=true --name $CONT_NAME \
                        -dit --net=host fedora:$FEDORA_RELEASE /sbin/init
            # Beautiful workaround for Fedora's version of Docker
            sleep 1
            $DOCKER_EXEC dnf makecache
            # Install necessary build/test requirements
            $DOCKER_EXEC dnf -y --exclude selinux-policy\* upgrade
            $DOCKER_EXEC dnf -y install "${ADDITIONAL_DEPS[@]}"
            $DOCKER_EXEC dnf -y builddep systemd
            ;;
        RUN)
            info "Run phase"
            # Build systemd
            $DOCKER_EXEC meson -Dslow-tests=true build
            $DOCKER_EXEC ninja -v -C build
            $DOCKER_EXEC ninja -C build test
            ;;
        RUN_ASAN)
            $DOCKER_EXEC git clean -dxff
            $DOCKER_EXEC meson -Db_sanitize=address,undefined build
            $DOCKER_EXEC ninja -v -C build
            $DOCKER_EXEC sh -c "printf '#!/bin/sh\necho The test is failing under ASan, skipping; exit 77' >/build/build/test-capability"

            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            $DOCKER_EXEC sh -c "UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1 ninja -C build test"
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
