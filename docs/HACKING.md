---
title: Hacking on systemd
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
tool is installed it is sufficient to type `mkosi` in the systemd project
directory to generate a disk image `image.raw` you can boot either in
`systemd-nspawn` or in an UEFI-capable VM:

```
# systemd-nspawn -bi image.raw
```

or:

```
# qemu-system-x86_64 -enable-kvm -m 512 -smp 2 -bios /usr/share/edk2/ovmf/OVMF_CODE.fd -hda image.raw
```

Every time you rerun the `mkosi` command a fresh image is built, incorporating
all current changes you made to the project tree.

Alternatively, you may install the systemd version from your git check-out
directly on top of your host system's directory tree. This mostly works fine,
but of course you should know what you are doing as you might make your system
unbootable in case of a bug in your changes. Also, you might step into your
package manager's territory with this. Be careful!

And never forget: most distributions provide very simple and convenient ways to
install all development packages necessary to build systemd. For example, on
Fedora the following command line should be sufficient to install all of
systemd's build dependencies:

```
# dnf builddep systemd
```

Putting this all together, here's a series of commands for preparing a patch
for systemd (this example is for Fedora):

```sh
$ sudo dnf builddep systemd            # install build dependencies
$ sudo dnf install mkosi               # install tool to quickly build images
$ git clone https://github.com/systemd/systemd.git
$ cd systemd
$ vim src/core/main.c                  # or wherever you'd like to make your changes
$ meson build                          # configure the build
$ ninja -C build                       # build it locally, see if everything compiles fine
$ ninja -C build test                  # run some simple regression tests
$ (umask 077; echo 123 > mkosi.rootpw) # set root password used by mkosi
$ sudo mkosi                           # build a test image
$ sudo systemd-nspawn -bi image.raw    # boot up the test image
$ git add -p                           # interactively put together your patch
$ git commit                           # commit it
$ git push REMOTE HEAD:refs/heads/BRANCH
                                       # where REMOTE is your "fork" on GitHub
                                       # and BRANCH is a branch name.
```

And after that, head over to your repo on GitHub and click "Compare & pull request"

Happy hacking!


## Fuzzers

systemd includes fuzzers in `src/fuzz/` that use libFuzzer and are automatically
run by [OSS-Fuzz](https://github.com/google/oss-fuzz) and [Fuzzit](https://fuzzit.dev) with sanitizers.
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

When you add a new target you should also add the target on [Fuzzit](https://app.fuzzit.dev/admin/RxqRpGNXquIvqrmp4iJS/dashboard)
 (Please ask someone with permissions). One the target is configured on Fuzzit you need to add it to
 `travis-ci/managers/fuzzit.sh` so the new target will run sanity tests on every pull-request and periodic fuzzing jobs.

If you find a bug that impacts the security of systemd, please follow the
guidance in [CONTRIBUTING.md](CONTRIBUTING.md) on how to report a security vulnerability.

For more details on building fuzzers and integrating with OSS-Fuzz, visit:

- https://github.com/google/oss-fuzz/blob/master/docs/new_project_guide.md
- https://llvm.org/docs/LibFuzzer.html
- https://github.com/google/fuzzer-test-suite/blob/master/tutorial/libFuzzerTutorial.md
- https://chromium.googlesource.com/chromium/src/testing/libfuzzer/+/HEAD/efficient_fuzzer.md
