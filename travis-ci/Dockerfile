## Create Dockerfile that builds container suitable for systemd build
## This container runs as non-root user by default

FROM fedora:27

# Demand the specification of non-root username
ARG DOCKER_USER
ARG DOCKER_USER_UID
ARG DOCKER_USER_GID

# Copy the requirements into the container at /tmp
COPY requirements.txt /tmp/

# Install the requirements
# RUN dnf -y update FIXME
RUN dnf -y install $(cat '/tmp/requirements.txt')
# clean step to prevent cache and metadata corruption
RUN dnf clean all
RUN dnf -y builddep systemd

# Add non-root user and chown the project dir
RUN groupadd -g $DOCKER_USER_GID $DOCKER_USER
RUN useradd --create-home --shell /bin/bash -u $DOCKER_USER_UID -g $DOCKER_USER_GID -G wheel $DOCKER_USER
ENV HOME /home/$DOCKER_USER
ENV PROJECTDIR $HOME/systemd

# Copy content to the project directory
COPY . $PROJECTDIR

# Greant user all permissions to the project dir
RUN chown -R $DOCKER_USER $PROJECTDIR

# Switch to noroot user by default
USER $DOCKER_USER

# Update workdir to user home dir
WORKDIR $PROJECTDIR
