---
title: Hacking on systemd
category: Contributing
layout: default
---

# Hacking on systemd

We welcome all contributions to systemd. If you notice a bug or a missing
feature, please feel invited to fix it, and submit your work as a GitHub Pull
Request (PR) at https://github.com/systemd/systemd/pull/new.

Please make sure to follow our [Coding Style](CODING_STYLE.md) when submitting patches.
Also have a look at our [Contribution Guidelines](CONTRIBUTING.md).

When adding new functionality, tests should be added. For shared functionality
(in `src/basic/` and `src/shared/`) unit tests should be sufficient. The general
policy is to keep tests in matching files underneath `src/test/`,
e.g. `src/test/test-path-util.c` contains tests for any functions in
`src/basic/path-util.c`. If adding a new source file, consider adding a matching
test executable. For features at a higher level, tests in `src/test/` are very
strongly recommended. If that is not possible, integration tests in `test/` are
encouraged.

Please also have a look at our list of [code quality tools](CODE_QUALITY.md) we have setup for systemd,
to ensure our codebase stays in good shape.

Please always test your work before submitting a PR. For many of the components
of systemd testing is straight-forward as you can simply compile systemd and
run the relevant tool from the build directory.

For some components (most importantly, systemd/PID1 itself) this is not
possible, however. In order to simplify testing for cases like this we provide
a set of `mkosi` build files directly in the source tree. `mkosi` is a tool for
building clean OS images from an upstream distribution in combination with a
fresh build of the project in the local working directory. To make use of this,
please acquire `mkosi` from https://github.com/systemd/mkosi first, unless your
distribution has packaged it already and you can get it from there. After the
tool is installed, symlink the settings file for your distribution of choice from
.mkosi/ to mkosi.default in the project root directory (note that the package
manager for this distro needs to be installed on your host system). After doing
that, it is sufficient to type `mkosi` in the systemd project directory to
generate a disk image `image.raw` you can boot either in `systemd-nspawn` or in
an UEFI-capable VM:

```
# mkosi boot
```

or:

```
# mkosi qemu
```

Every time you rerun the `mkosi` command a fresh image is built, incorporating
all current changes you made to the project tree. To save time when rebuilding,
you can use mkosi's incremental mode (`-i`). This instructs mkosi to build a set
of cache images that make future builds a lot faster. Note that the `-i` flag
both instructs mkosi to build cached images if they don't exist yet and to use
cached images if they already exist so make sure to always specify `-i` if you
want mkosi to use the cached images.

If you're going to build mkosi images that use the same distribution and release
that you're currently using, you can speed up the initial mkosi run by having it
reuse the host's package cache. To do this, create a mkosi override file in
mkosi.default.d/ (e.g 20-local.conf) and add the following contents:

```
[Packages]
Cache=<full-path-to-package-manager-cache> # (e.g. /var/cache/dnf)
```

If you want to do a local build without mkosi, most distributions also provide
very simple and convenient ways to install all development packages necessary
to build systemd. For example, on Fedora the following command line should be
sufficient to install all of systemd's build dependencies:

```
# dnf builddep systemd
```

Putting this all together, here's a series of commands for preparing a patch
for systemd (this example is for Fedora):

```sh
$ sudo dnf builddep systemd               # install build dependencies
$ sudo dnf install mkosi                  # install tool to quickly build images
$ git clone https://github.com/systemd/systemd.git
$ cd systemd
$ vim src/core/main.c                     # or wherever you'd like to make your changes
$ meson build                             # configure the build
$ meson compile -C build                  # build it locally, see if everything compiles fine
$ meson test -C build                     # run some simple regression tests
$ ln -s .mkosi/mkosi.fedora mkosi.default # Configure mkosi to build a fedora image
$ sudo mkosi                              # build a test image
$ sudo mkosi boot                         # boot up the test image
$ git add -p                              # interactively put together your patch
$ git commit                              # commit it
$ git push REMOTE HEAD:refs/heads/BRANCH
                                          # where REMOTE is your "fork" on GitHub
                                          # and BRANCH is a branch name.
```

And after that, head over to your repo on GitHub and click "Compare & pull request"

Happy hacking!


## Developer and release modes

In the default meson configuration (`-Dmode=developer`), certain checks are
enabled that are suitable when hacking on systemd (such as internal
documentation consistency checks). Those are not useful when compiling for code
for distribution and can be disabled by setting `-Dmode=release`.

## Fuzzers

systemd includes fuzzers in `src/fuzz/` that use libFuzzer and are automatically
run by [OSS-Fuzz](https://github.com/google/oss-fuzz) with sanitizers.
To add a fuzz target, create a new `src/fuzz/fuzz-foo.c` file with a `LLVMFuzzerTestOneInput`
function and add it to the list in `src/fuzz/meson.build`.

Whenever possible, a seed corpus and a dictionary should also be added with new
fuzz targets. The dictionary should be named `src/fuzz/fuzz-foo.dict` and the seed
corpus should be built and exported as `$OUT/fuzz-foo_seed_corpus.zip` in
`tools/oss-fuzz.sh`.

The fuzzers can be built locally if you have libFuzzer installed by running
`tools/oss-fuzz.sh`. You should also confirm that the fuzzer runs in the
OSS-Fuzz environment by checking out the OSS-Fuzz repo, and then running
commands like this:

```
python infra/helper.py build_image systemd
python infra/helper.py build_fuzzers --sanitizer memory systemd ../systemd
python infra/helper.py run_fuzzer systemd fuzz-foo
```

If you find a bug that impacts the security of systemd, please follow the
guidance in [CONTRIBUTING.md](CONTRIBUTING.md) on how to report a security vulnerability.

For more details on building fuzzers and integrating with OSS-Fuzz, visit:

- [Setting up a new project - OSS-Fuzz](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Tutorials - OSS-Fuzz](https://google.github.io/oss-fuzz/reference/useful-links/#tutorials)
