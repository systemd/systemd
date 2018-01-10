#!/bin/bash

# Check environment
[ -z "$DOCKER_REPOSITORY" ] && echo "ERROR: DOCKER_REPOSITORY must be set" && exit 1
[ -z "$TRAVIS_COMMIT" ] && echo "ERROR: TRAVIS_COMMIT must be set" && exit 1

# Build docker image
echo -e "\n\033[33;1mBuilding docker image: $DOCKER_REPOSITORY:$TRAVIS_COMMIT.\033[0m"

docker build \
--build-arg DOCKER_USER=$USER \
--build-arg DOCKER_USER_UID=`id -u` \
--build-arg DOCKER_USER_GID=`id -g` \
--force-rm -t ${DOCKER_REPOSITORY}:${TRAVIS_COMMIT} --pull=true .
