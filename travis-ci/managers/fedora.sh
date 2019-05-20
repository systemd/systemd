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
ADDITIONAL_DEPS=(dnf-plugins-core
                 python2 iputils
                 hostname libasan
                 python3-pyparsing
                 python3-evdev
                 libubsan
                 clang
                 llvm
                 perl)

function info() {
    echo -e "\033[33;1m$1\033[0m"
}

set -e

source "$(dirname $0)/travis_wait.bash"

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
            $DOCKER_EXEC meson --werror -Dtests=unsafe -Dslow-tests=true build
            $DOCKER_EXEC ninja -v -C build
            $DOCKER_EXEC ninja -C build test
            ;;
        RUN_CLANG)
            docker exec -e CC=clang -e CXX=clang++ -it $CONT_NAME meson --werror -Dtests=unsafe -Dslow-tests=true -Dman=true build
            $DOCKER_EXEC ninja -v -C build
            $DOCKER_EXEC ninja -C build test
            ;;
        RUN_ASAN|RUN_CLANG_ASAN)
            if [[ "$phase" = "RUN_CLANG_ASAN" ]]; then
                ENV_VARS="-e CC=clang -e CXX=clang++"
                MESON_ARGS="-Db_lundef=false" # See https://github.com/mesonbuild/meson/issues/764
            fi
            docker exec $ENV_VARS -it $CONT_NAME meson --werror -Dtests=unsafe -Db_sanitize=address,undefined $MESON_ARGS build
            $DOCKER_EXEC ninja -v -C build

            # Never remove halt_on_error from UBSAN_OPTIONS. See https://github.com/systemd/systemd/commit/2614d83aa06592aedb.
            travis_wait docker exec --interactive=false \
                -e UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1 \
                -e ASAN_OPTIONS=strict_string_checks=1:detect_stack_use_after_return=1:check_initialization_order=1:strict_init_order=1 \
                -e "TRAVIS=$TRAVIS" \
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
