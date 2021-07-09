# Dockerfile for systemd-builder.
#
# This container runs as root initially, but then creates a "builder" user
# which is then used in subsequent build steps.
#
# This is necessary in order to create a user with the proper UID/GID that
# are compatible with the UID/GID of the user outside the container mounting
# the source and output directories into it.

FROM fedora:29

# Update the image and install the requirements.
RUN dnf -y update && \
    dnf -y install dnf-plugins-core python3 && \
    dnf -y builddep systemd

COPY systemd-builder.py /usr/local/bin/systemd-builder
RUN chmod 755 /usr/local/bin/systemd-builder && \
    /usr/local/bin/systemd-builder setup

ENTRYPOINT ["/usr/local/bin/systemd-builder"]
