# Integration tests

## Running the integration tests with meson + mkosi

To run the integration tests with meson + mkosi, make sure you're running the
latest version of mkosi. See
[`docs/HACKING.md`](https://github.com/systemd/systemd/blob/main/docs/HACKING.md)
for more specific details. Make sure `mkosi` is available in `$PATH` when
reconfiguring meson to make sure it is picked up properly.

We also need to make sure the required meson options are enabled:

```shell
$ mkosi -f sandbox meson setup --reconfigure build -Dremote=enabled
```

To make sure `mkosi` doesn't try to build systemd from source during the image build
process, you can add the following to `mkosi.local.conf`:

```
[Build]
Environment=NO_BUILD=1
```

You might also want to use the `PackageDirectories=` or `Repositories=` option to provide
mkosi with a directory or repository containing the systemd packages that should be installed
instead. If the repository containing the systemd packages is not a builtin repository known
by mkosi, you can use the `SandboxTrees=` option to write an extra repository definition
to /etc which is used when building the image instead.

Next, we can build the integration test image with meson:

```shell
$ mkosi -f sandbox meson compile -C build mkosi
```

By default, the `mkosi` meson target which builds the integration test image depends on
other meson targets to build various systemd tools that are used to build the image to make
sure they are up-to-date. If you instead want the already installed systemd tools on the
host to be used, you can run `mkosi` manually to build the image. To build the integration test
image without meson, run the following:

```shell
$ mkosi -f
```

Note that by default we assume that `build/` is used as the meson build directory that will be used to run
the integration tests. If you want to use another directory as the meson build directory, you will have to
configure the mkosi build directory (`BuildDirectory=`), cache directory (`CacheDirectory=`) and output
directory (`OutputDirectory=`) to point to the other directory using `mkosi.local.conf`.

After the image has been built, the integration tests can be run with:

```shell
$ env SYSTEMD_INTEGRATION_TESTS=1 mkosi -f sandbox meson test -C build --no-rebuild --suite integration-tests --num-processes "$(($(nproc) / 4))"
```

As usual, specific tests can be run in meson by appending the name of the test
which is usually the name of the directory e.g.

```shell
$ env SYSTEMD_INTEGRATION_TESTS=1 mkosi -f sandbox meson test -C build --no-rebuild -v TEST-01-BASIC
```

See `mkosi -f sandbox meson introspect build --tests` for a list of tests.

To interactively debug a failing integration test, the `--interactive` option
(`-i`) for `meson test` can be used. Note that this requires meson v1.5.0 or
newer:

```shell
$ env SYSTEMD_INTEGRATION_TESTS=1 mkosi -f sandbox meson test -C build --no-rebuild -i TEST-01-BASIC
```

Due to limitations in meson, the integration tests do not yet depend on the
mkosi target, which means the mkosi target has to be manually rebuilt before
running the integration tests. To rebuild the image and rerun a test, the
following command can be used:

```shell
$ mkosi -f sandbox meson compile -C build mkosi && env SYSTEMD_INTEGRATION_TESTS=1 mkosi -f sandbox meson test -C build --no-rebuild -v TEST-01-BASIC
```

The integration tests use the same mkosi configuration that's used when you run
mkosi in the systemd reposistory, so any local modifications to the mkosi
configuration (e.g. in `mkosi.local.conf`) are automatically picked up and used
by the integration tests as well.

## Iterating on an integration test

To iterate on an integration test, let's first get a shell in the integration test environment by running
the following:

```shell
$ mkosi -f sandbox meson compile -C build mkosi && env SYSTEMD_INTEGRATION_TESTS=1 TEST_SHELL=1 mkosi -f sandbox meson test -C build --no-rebuild -i TEST-01-BASIC
```

This will get us a shell in the integration test environment after booting the machine without running the
integration test itself. After booting, we can verify the integration test passes by running it manually,
for example with `systemctl start TEST-01-BASIC`.

Now you can extend the test in whatever way you like to add more coverage of existing features or to add
coverage for a new feature. Once you've finished writing the logic and want to rerun the test, run the
the following on the host:

```shell
$ mkosi -t none
```

This will rebuild the distribution packages without rebuilding the entire integration test image. Next, run
the following in the integration test machine:

```shell
$ systemctl soft-reboot
$ systemctl start TEST-01-BASIC
```

A soft-reboot is required to make sure all the leftover state from the previous run of the test is cleaned
up by soft-rebooting into the btrfs snapshot we made before running the test. After the soft-reboot,
re-running the test will first install the new packages we just built, make a new snapshot and finally run
the test again. You can keep running the loop of `mkosi -t none`, `systemctl soft-reboot` and
`systemctl start ...` until the changes to the integration test are working.

If you're debugging a failing integration test (running `meson test --interactive` without `TEST_SHELL`),
there's no need to run `systemctl start ...`, running `systemctl soft-reboot` on its own is sufficient to
rerun the test.

### Configuration variables

`TEST_NO_QEMU=1`: Don't run tests under qemu.

`TEST_PREFER_QEMU=1`:  Run all tests under qemu.

`TEST_NO_KVM=1`: Disable qemu KVM auto-detection (may be necessary when you're
trying to run the *vanilla* qemu and have both qemu and qemu-kvm installed)

`TEST_SHELL=1`: Configure the machine to be more *user-friendly* for
interactive debugging (e.g. by setting a usable default terminal, suppressing
the shutdown after the test, etc.).

`TEST_MATCH_SUBTEST=subtest`:  If the test makes use of `run_subtests` use this
variable to provide a POSIX extended regex to run only subtests matching the
expression.

`TEST_MATCH_TESTCASE=testcase`: Same as $TEST_MATCH_SUBTEST but for subtests
that make use of `run_testcases`.

`TEST_SKIP`: takes a space separated list of tests to skip.

`TEST_SKIP_SUBTEST=subtest`: takes a space separated list of subtests to skip.

`TEST_SKIP_TESTCASE=testcase`: takes a space separated list of testcases to skip.

`TEST_JOURNAL_USE_TMP=1`: Write test journal to `/tmp` while the test is in
progress and only move the journal to its final location in the build directory
(`$BUILD_DIR/test/journal`) when the test is finished.

### SELinux AVCs

To have `TEST-06-SELINUX` check for SELinux denials, write the following to
mkosi.local.conf:

```conf
[Runtime]
KernelCommandLineExtra=systemd.setenv=TEST_SELINUX_CHECK_AVCS=1
```

## Ubuntu CI

New PRs submitted to the project are run through regression tests, and one set
of those is the 'autopkgtest' runs for several different architectures, called
'Ubuntu CI'.  Part of that testing is to run all these tests.

Known issues affecting the infrastructure/testbed can be seen on this Ubuntu page:

https://discourse.ubuntu.com/t/autopkgtest-service/34490

In case a test fails, the full set of artifacts, including the journal of the
failed run, can be downloaded from the artifacts.tar.gz archive which will be
reachable in the same URL parent directory as the logs.gz that gets linked on
the Github CI status.

The log URL can be derived following a simple algorithm, however the test
completion timestamp is needed and it's not easy to find without access to the
log itself. For example, a noble s390x job started on 2024-03-23 at 02:09:11
will be stored at the following URL:

https://autopkgtest.ubuntu.com/results/autopkgtest-noble-upstream-systemd-ci-systemd-ci/noble/s390x/s/systemd-upstream/20240323_020911_e8e88@/log.gz

Fortunately a list of URLs listing file paths for recently completed test runs
is available at:

https://autopkgtest.ubuntu.com/results/autopkgtest-noble-upstream-systemd-ci-systemd-ci/

paths listed at this URL can be appended to the URL to download them. Unfortunately
there are too many results and the web server cannot list them all at once. Fortunately
there is a workaround: copy the last line on the page, and append it to the URL, with
a '?marker=' prefix, and the web server will show the next page of results. For example:

https://autopkgtest.ubuntu.com/results/autopkgtest-noble-upstream-systemd-ci-systemd-ci/?marker=noble/amd64/s/systemd-upstream/20240616_211635_5993a@/result.tar

The 5 characters at the end of the last directory are not random, but the first
5 characters of a SHA1 hash generated based on the set of parameters given to
the build plus the completion timestamp, such as:

```shell
$ echo -n 'systemd-upstream {"build-git": "https://salsa.debian.org/systemd-team/systemd.git#debian/master", "env": ["UPSTREAM_REPO=https://github.com/systemd/systemd.git", "CFLAGS=-O0", "DEB_BUILD_PROFILES=pkg.systemd.upstream noudeb", "TEST_UPSTREAM=1", "CONFFLAGS_UPSTREAM=--werror -Dslow-tests=true", "UPSTREAM_PULL_REQUEST=31444", "GITHUB_STATUSES_URL=https://api.github.com/repos/systemd/systemd/statuses/c27f600a1c47f10b22964eaedfb5e9f0d4279cd9"], "ppas": ["upstream-systemd-ci/systemd-ci"], "submit-time": "2024-02-27 17:06:27", "uuid": "02cd262f-af22-4f82-ac91-53fa5a9e7811"}' | sha1sum | cut -c1-5
```

To add new dependencies or new binaries to the packages used during the tests,
a merge request can be sent to: https://salsa.debian.org/systemd-team/systemd
targeting the 'upstream-ci' branch.

The cloud-side infrastructure, that is hooked into the Github interface, is
located at:

https://git.launchpad.net/autopkgtest-cloud/

A generic description of the testing infrastructure can be found at:

https://wiki.ubuntu.com/ProposedMigration/AutopkgtestInfrastructure

In case of infrastructure issues with this CI, things might go wrong in two
places:

- starting a job: this is done via a Github webhook, so check if the HTTP POST
  are failing on https://github.com/systemd/systemd/settings/hooks
- running a job: all currently running jobs are listed at
  https://autopkgtest.ubuntu.com/running#pkg-systemd-upstream in case the PR
  does not show the status for some reason
- reporting the job result: this is done on Canonical's cloud infrastructure, if
  jobs are started and running but no status is visible on the PR, then it is
  likely that reporting back is not working

The CI job needs a PPA in order to be accepted, and the
upstream-systemd-ci/systemd-ci PPA is used. Note that this is necessary even
when there are no packages to backport, but by default a PPA won't have a
repository for a release if there are no packages built for it. To work around
this problem, when a new empty release is needed the mark-suite-dirty tool from
the https://git.launchpad.net/ubuntu-archive-tools can be used to force the PPA
to publish an empty repository, for example:

```shell
$ ./mark-suite-dirty -A ppa:upstream-systemd-ci/ubuntu/systemd-ci -s noble
```

will create an empty 'noble' repository that can be used for 'noble' CI jobs.

For infrastructure help, reaching out to 'qa-help' via the #ubuntu-quality
channel on libera.chat is an effective way to receive support in general.

Given access to the shared secret, tests can be re-run using the generic
retry-github-test tool:

https://git.launchpad.net/autopkgtest-cloud/tree/charms/focal/autopkgtest-cloud-worker/autopkgtest-cloud/tools/retry-github-test

A wrapper script that makes it easier to use is also available:

https://piware.de/gitweb/?p=bin.git;a=blob;f=retry-gh-systemd-Test

## Manually running a part of the Ubuntu CI test suite

In some situations one may want/need to run one of the tests run by Ubuntu CI
locally for debugging purposes. For this, you need a machine (or a VM) with
the same Ubuntu release as is used by Ubuntu CI (Jammy ATTOW).

First of all, clone the Debian systemd repository and sync it with the code of
the PR (set by the `$UPSTREAM_PULL_REQUEST` env variable) you'd like to debug:

```shell
$ git clone https://salsa.debian.org/systemd-team/systemd.git
$ cd systemd
$ git checkout ci/v<XYZ>-stable
$ TEST_UPSTREAM=1 UPSTREAM_PULL_REQUEST=12345 ./debian/extra/checkout-upstream
```

Now install necessary build & test dependencies:

```shell
# PPA with some newer Ubuntu packages required by upstream systemd
$ add-apt-repository -y --enable-source ppa:upstream-systemd-ci/systemd-ci
$ apt build-dep -y systemd
$ apt install -y autopkgtest fakemachine qemu-system-x86
```

Build systemd deb packages with debug info:

```shell
$ TEST_UPSTREAM=1 DEB_BUILD_OPTIONS="nocheck nostrip noopt pkg.systemd.upstream" dpkg-buildpackage -us -uc -b
$ cd ..
```

Prepare a testbed image for autopkgtest (tweak the release as necessary):

```shell
$ autopkgtest-buildvm-ubuntu-cloud --ram-size 1024 -v -a amd64 -r noble
```

And finally run the autopkgtest itself:

```shell
$ autopkgtest -o logs *.deb systemd/ \
              --env=TEST_UPSTREAM=1 \
              --timeout-factor=3 \
              --test-name=boot-and-services \
              --shell-fail \
              -- autopkgtest-virt-qemu --cpus 4 --ram-size 2048 autopkgtest-noble-amd64.img
```

where `--test-name=` is the name of the test you want to run/debug. The
`--shell-fail` option will pause the execution in case the test fails and shows
you the information how to connect to the testbed for further debugging.

## Manually running CodeQL analysis

This is mostly useful for debugging various CodeQL quirks.

Download the CodeQL Bundle from https://github.com/github/codeql-action/releases
and unpack it somewhere. From now the 'tutorial' assumes you have the `codeql`
binary from the unpacked archive in $PATH for brevity.

Switch to the systemd repository if not already:

```shell
$ cd <systemd-repo>
```

Create an initial CodeQL database:

```shell
$ CCACHE_DISABLE=1 codeql database create codeqldb --language=cpp -vvv
```

Disabling ccache is important, otherwise you might see CodeQL complaining:

No source code was seen and extracted to
/home/mrc0mmand/repos/@ci-incubator/systemd/codeqldb. This can occur if the
specified build commands failed to compile or process any code.
 - Confirm that there is some source code for the specified language in the
   project.
 - For codebases written in Go, JavaScript, TypeScript, and Python, do not
   specify an explicit --command.
 - For other languages, the --command must specify a "clean" build which
   compiles all the source code files without reusing existing build artefacts.

If you want to run all queries systemd uses in CodeQL, run:

```shell
$ codeql database analyze codeqldb/ --format csv --output results.csv .github/codeql-custom.qls .github/codeql-queries/*.ql -vvv
```

Note: this will take a while.

If you're interested in a specific check, the easiest way (without hunting down
the specific CodeQL query file) is to create a custom query suite. For example:

```shell
$ cat >test.qls <<EOF
- queries: .
  from: codeql/cpp-queries
- include:
    id:
        - cpp/missing-return
EOF
```

And then execute it in the same way as above:

```shell
$ codeql database analyze codeqldb/ --format csv --output results.csv test.qls -vvv
```

More about query suites here: https://codeql.github.com/docs/codeql-cli/creating-codeql-query-suites/

The results are then located in the `results.csv` file as a comma separated
values list (obviously), which is the most human-friendly output format the
CodeQL utility provides (so far).

## Running Coverity locally

Note: this requires a Coverity license, as the public tool
[tarball](https://scan.coverity.com/download) doesn't contain cov-analyze and
friends, so the usefulness of this guide is somewhat limited.

Debugging certain pesky Coverity defects can be painful, especially since the
OSS Coverity instance has a very strict limit on how many builds we can send it
per day/week, so if you have an access to a non-OSS Coverity license, knowing
how to debug defects locally might come in handy.

After installing the necessary tooling we need to populate the emit DB first:

```shell
$ rm -rf build cov
$ meson setup build -Dman=false
$ cov-build --dir=./cov ninja -C build
```

From there it depends if you're interested in a specific defect or all of them.
For the latter run:

```shell
$ cov-analyze --dir=./cov --wait-for-license
```

If you want to debug a specific defect, telling that to cov-analyze speeds
things up a bit:

```shell
$ cov-analyze --dir=./cov --wait-for-license --disable-default --enable ASSERT_SIDE_EFFECT
```

The final step is getting the actual report which can be generated in multiple
formats, for example:

```shell
$ cov-format-errors --dir ./cov --text-output-style multiline
$ cov-format-errors --dir=./cov --emacs-style
$ cov-format-errors --dir=./cov --html-output html-out
```

Which generate a text report, an emacs-compatible text report, and an HTML
report respectively.

Other useful options for cov-format-error include `--file <file>` to filter out
defects for a specific file, `--checker-regex DEFECT_TYPE` to filter our only a
specific defect (if this wasn't done already by cov-analyze), and many others,
see `--help` for an exhaustive list.

## Code coverage

We have a daily cron job in Github Actions which runs all unit and integration
tests, collects coverage using gcov/lcov, and uploads the report to
[Coveralls](https://coveralls.io/github/systemd/systemd). In order to collect
the most accurate coverage information, some measures have to be taken regarding
sandboxing, namely:

 - ProtectSystem= and ProtectHome= need to be turned off
 - the coverage files (*.gcda) files need to be present in the image and need
   to be writable by all processes

The first point is relatively easy to handle and is handled automagically by
mkosi by creating the necessary dropins when `COVERAGE=1` is passed via the
`Environment=` setting.

Making the coverage files accessible and writable to _everything_ is achieved by
pre-creating all the files and making them world readable and writable. However,
this is not enough in some cases, like for services that use DynamicUser=yes,
since that implies ProtectSystem=strict that can't be turned off. A solution to
this is to use `ReadWritePaths=/coverage`, which works for the majority of
cases, but can't be turned on globally, since ReadWritePaths= creates its own
mount namespace which might break some services. Hence, the
`ReadWritePaths=/coverage` is enabled for all services with the `test-` prefix
(i.e. test-foo.service or test-foo-bar.service), both in the system and the user
managers.

So, if you're considering writing an integration test that makes use of
`DynamicUser=yes`, or other sandboxing stuff that implies it, please prefix the
test unit (be it a static one or a transient one created via systemd-run), with
`test-`, unless the test unit needs to be able to install mount points in the
main mount namespace - in that case use `IGNORE_MISSING_COVERAGE=yes` in the
test definition (i.e. `TEST-*-NAME/test.sh`), which will skip the post-test
check for missing coverage for the respective test.

## Fuzzers

systemd includes fuzzers in `src/fuzz/` that use libFuzzer and are automatically
run by [OSS-Fuzz](https://github.com/google/oss-fuzz) with sanitizers. To add a
fuzz target, create a new `src/fuzz/fuzz-foo.c` file with a
`LLVMFuzzerTestOneInput` function and add it to the list in
`src/fuzz/meson.build`.

Whenever possible, a seed corpus and a dictionary should also be added with new
fuzz targets. The dictionary should be named `src/fuzz/fuzz-foo.dict` and the
seed corpus should be built and exported as `$OUT/fuzz-foo_seed_corpus.zip` in
`tools/oss-fuzz.sh`.

The fuzzers can be built locally if you have libFuzzer installed by running
`tools/oss-fuzz.sh`, or by running:

```sh
CC=clang CXX=clang++ \
meson setup build-libfuzz -Dllvm-fuzz=true -Db_sanitize=address,undefined -Db_lundef=false \
-Dc_args='-fno-omit-frame-pointer -DFUZZING_BUILD_MODE_UNSAFE_FOR_PRODUCTION'
ninja -C build-libfuzz fuzzers
```

Each fuzzer then can be then run manually together with a directory containing
the initial corpus:

```
export UBSAN_OPTIONS=print_stacktrace=1:print_summary=1:halt_on_error=1
build-libfuzz/fuzz-varlink-idl test/fuzz/fuzz-varlink-idl/
```

Note: the `halt_on_error=1` UBSan option is especially important, otherwise the
fuzzer won't crash when undefined behavior is triggered.

You should also confirm that the fuzzers can be built and run using
[the OSS-Fuzz toolchain](https://google.github.io/oss-fuzz/advanced-topics/reproducing/#building-using-docker):

```sh
path_to_systemd=...

git clone --depth=1 https://github.com/google/oss-fuzz
cd oss-fuzz

for sanitizer in address undefined memory; do
for engine in libfuzzer afl honggfuzz; do
./infra/helper.py build_fuzzers --sanitizer "$sanitizer" --engine "$engine" \
--clean systemd "$path_to_systemd"

./infra/helper.py check_build --sanitizer "$sanitizer" --engine "$engine" \
-e ALLOWED_BROKEN_TARGETS_PERCENTAGE=0 systemd
done
done

./infra/helper.py build_fuzzers --clean --architecture i386 systemd "$path_to_systemd"
./infra/helper.py check_build --architecture i386 -e ALLOWED_BROKEN_TARGETS_PERCENTAGE=0 systemd

./infra/helper.py build_fuzzers --clean --sanitizer coverage systemd "$path_to_systemd"
./infra/helper.py coverage --no-corpus-download systemd
```

If you find a bug that impacts the security of systemd, please follow the
guidance in [CONTRIBUTING.md](/CONTRIBUTING) on how to report a security
vulnerability.

For more details on building fuzzers and integrating with OSS-Fuzz, visit:

- [Setting up a new project - OSS-Fuzz](https://google.github.io/oss-fuzz/getting-started/new-project-guide/)
- [Tutorials - OSS-Fuzz](https://google.github.io/oss-fuzz/reference/useful-links/#tutorials)
