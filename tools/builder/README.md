# systemd-builder

Build systemd from a source tree inside a docker/podman container.

Start by fetching the container with:

```
$ docker pull filbranden/systemd-builder
```

(You can also build your own using `docker build -t systemd-builder tools/builder`.)

Then, at the top of the systemd tree, create a target directory for the build
and run the build command:

```
$ mkdir container-build
$ docker run --rm \
      --mount type=bind,src="${PWD}",dst=/systemd,readonly \
      --mount type=bind,src="${PWD}/container-build",dst=/build \
      filbranden/systemd-builder build
```

The mount commands will mount the source tree under `/systemd` in the
container, and mount the target directory under `/build`. The source tree can
be mounted read-only.

Even if you don't care about the build artifacts (e.g.  just running tests on
CI), you still need an external mount for it, so use a scratch directory for
that case. You can use an unnamed volume mount for that:

```
$ docker run --rm \
      --mount type=bind,src="${PWD}",dst=/systemd,readonly \
      --mount type=volume,dst=/build \
      filbranden/systemd-builder build
```
