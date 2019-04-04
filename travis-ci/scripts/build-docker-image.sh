#!/bin/bash

# Check environment
[ -z "$TRAVIS_COMMIT" ] && echo "ERROR: TRAVIS_COMMIT must be set" && exit 1

# Build docker image
echo -e "\n\033[33;1mBuilding docker image: coverity-$TRAVIS_COMMIT.\033[0m"

docker build \
       --build-arg DOCKER_USER=$USER \
       --build-arg DOCKER_USER_UID=`id -u` \
       --build-arg DOCKER_USER_GID=`id -g` \
       --force-rm -t coverity-${TRAVIS_COMMIT} --pull=true .
