---
title: Hacking on systemd
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Hacking on systemd

We welcome all contributions to systemd. If you notice a bug or a missing
feature, please feel invited to fix it, and submit your work as a
[GitHub Pull Request (PR)](https://github.com/systemd/systemd/pull/new).

Please make sure to follow our [Coding Style](CODING_STYLE.md) when submitting
patches. Also have a look at our [Contribution Guidelines](CONTRIBUTING.md).

When adding new functionality, tests should be added. For shared functionality
(in `src/basic/` and `src/shared/`) unit tests should be sufficient. The general
policy is to keep tests in matching files underneath `src/test/`,
e.g. `src/test/test-path-util.c` contains tests for any functions in
`src/basic/path-util.c`. If adding a new source file, consider adding a matching
test executable. For features at a higher level, tests in `src/test/` are very
strongly recommended. If that is not possible, integration tests in `test/` are
encouraged.

Please also have a look at our list of [code quality tools](CODE_QUALITY.md) we
have setup for systemd, to ensure our codebase stays in good shape.

Please always test your work before submitting a PR. For many of the components
of systemd testing is straight-forward as you can simply compile systemd and
run the relevant tool from the build directory.

For some components (most importantly, systemd/PID1 itself) this is not
possible, however. In order to simplify testing for cases like this we provide
a set of `mkosi` build files directly in the source tree.
[mkosi](https://github.com/systemd/mkosi) is a tool for building clean OS images
from an upstream distribution in combination with a fresh build of the project
in the local working directory. To make use of this, please install the
`mkosi` package (if not packaged for your distro, it can be downloaded from
the [GitHub repository](https://github.com/systemd/mkosi). `mkosi` will build an
image for the host distro by default. It is sufficient to type `mkosi` in the
systemd project directory to generate a disk image `image.raw` you can boot either
in `systemd-nspawn` or in an UEFI-capable VM:

```sh
$ mkosi boot
```

or:

```sh
$ mkosi qemu
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
to build systemd:

```sh
# Fedora
$ sudo dnf builddep systemd
# Debian/Ubuntu
$ sudo apt-get build-dep systemd
# Arch
$ sudo pacman install asp
$ asp checkout systemd
$ cd systemd/trunk
$ makepkg -seoc
```

Putting this all together, here's a series of commands for preparing a patch
for systemd:

```sh
# Install build dependencies (see above)
# Install a recent version of mkosi (either via your distro's package manager if
# available there or from the github repository otherwise)
$ git clone https://github.com/systemd/systemd.git
$ cd systemd
$ git checkout -b <BRANCH>                # where BRANCH is the name of the branch
$ vim src/core/main.c                     # or wherever you'd like to make your changes
$ meson build                             # configure the build
$ meson compile -C build                  # build it locally, see if everything compiles fine
$ meson test -C build                     # run some simple regression tests
$ sudo mkosi                              # build a test image
$ sudo mkosi boot                         # boot up the test image
$ git add -p                              # interactively put together your patch
$ git commit                              # commit it
$ git push -u <REMOTE>                    # where REMOTE is your "fork" on GitHub
```

And after that, head over to your repo on GitHub and click "Compare & pull request"

Happy hacking!

## Templating engines in .in files

Some source files are generated during build. We use two templating engines:
* meson's `configure_file()` directive uses syntax with `@VARIABLE@`.

  See the
  [Meson docs for `configure_file()`](https://mesonbuild.com/Reference-manual.html#configure_file)
  for details.

{% raw %}
* most files are rendered using jinja2, with `{{VARIABLE}}` and `{% if … %}`,
  `{% elif … %}`, `{% else … %}`, `{% endif … %}` blocks. `{# … #}` is a
  jinja2 comment, i.e. that block will not be visible in the rendered
  output. `{% raw %} … `{% endraw %}`{{ '{' }}{{ '% endraw %' }}}` creates a block
  where jinja2 syntax is not interpreted.

  See the
  [Jinja Template Designer Documentation](https://jinja2docs.readthedocs.io/en/stable/templates.html#synopsis)
  for details.

Please note that files for both template engines use the `.in` extension.

## Developer and release modes

In the default meson configuration (`-Dmode=developer`), certain checks are
enabled that are suitable when hacking on systemd (such as internal
documentation consistency checks). Those are not useful when compiling for
distribution and can be disabled by setting `-Dmode=release`.

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

## mkosi + clangd

[clangd](https://clangd.llvm.org/) is a language server that provides code completion, diagnostics and more
right in your editor of choice (with the right plugin installed). When using mkosi, we can run clangd in the
mkosi build container to avoid needing to build systemd on the host machine just to make clangd work. To
achieve this, create a script with the following contents in systemd's project directory on the host:

```sh
#!/usr/bin/env sh
tee mkosi-clangd.build > /dev/null << EOF
#!/usr/bin/env sh
exec clangd \\
        --compile-commands-dir=/root/build \\
        --path-mappings=\\
"\\
$(pwd)=/root/src,\\
$(pwd)/mkosi.builddir=/root/build,\\
$(pwd)/mkosi.includedir=/usr/include,\\
$(pwd)/mkosi.installdir=/root/dest\\
" \\
        --header-insertion=never
EOF
chmod +x mkosi-clangd.build
exec sudo mkosi --source-file-transfer=mount --incremental --skip-final-phase --build-script mkosi-clangd.build build
```

Next, mark the script as executable and point your editor plugin to use this script to start clangd. For
vscode's clangd extension, this is done via setting the `clangd.path` option to the path of the
mkosi-clangd.sh script.

To be able to navigate to include files of systemd's dependencies, we need to make the /usr/include folder of
the build image available on the host. mkosi supports this by setting the `IncludeDirectory` option in
mkosi's config. The easiest way to set the option is to create a file 20-local.conf in mkosi.default.d/ and
add the following contents:

```
[Packages]
IncludeDirectory=mkosi.includedir
```

This will make the contents of /usr/include available in mkosi.includedir in the systemd project directory.
We already configured clangd to map any paths in /usr/include in the build image to mkosi.includedir/ on the
host in the mkosi-clangd.sh script.

We also need to make sure clangd is installed in the build image. To have mkosi install clangd in the build
image, edit the 20-local.conf file we created earlier and add the following contents under the `[Packages]`
section:

```
BuildPackages=<clangd-package>
```

Note that the exact package containing clangd will differ depending on the distribution used. Some
distributions have a separate clangd package, others put the clangd binary in a clang-tools-extra package and
some bundle clangd in the clang package.

Because mkosi needs to run as root, we also need to make sure we can enter the root password when the editor
plugin tries to run the mkosi-clangd.sh script. To be able to enter the root password in non-interactive
scripts, we use an askpass provider. This is a program that sudo will launch if it detects it's being
executed from a non-interactive shell so that the root password can still be entered. There are multiple
implementations such as gnome askpass and KDE askpass. Install one of the askpass packages your distro
provides and set the `SUDO_ASKPASS` environment variable to the path of the askpass binary you want to use.
If configured correctly, a window will appear when your editor plugin tries to run the mkosi-clangd.sh script
allowing you to enter the root password.

Due to a bug in btrfs, it's currently impossible to mount two mkosi btrfs images at the same time. Because of
this, trying to do a regular build while the clangd image is running will fail. To circumvent this, use ext4
instead of btrfs for the images by adding the following contents to 20-local.conf:

```
[Output]
Format=gpt_ext4
```

Finally, to ensure clangd starts up quickly in the editor, run an incremental build with mkosi to make sure
the cached images are initialized (`mkosi -i`).

Now, your editor will start clangd in the mkosi build image and all of clangd's features will work as
expected.

## Debugging systemd with mkosi + vscode

To simplify debugging systemd when testing changes using mkosi, we're going to show how to attach
[VSCode](https://code.visualstudio.com/)'s debugger to an instance of systemd running in a mkosi image
(either using QEMU or systemd-nspawn).

To allow VSCode's debugger to attach to systemd running in a mkosi image, we have to make sure it can access
the container/virtual machine spawned by mkosi where systemd is running. mkosi makes this possible via a
handy SSH option that makes the generated image accessible via SSH when booted. The easiest way to set the
option is to create a file 20-local.conf in mkosi.default.d/ and add the following contents:

```
[Host]
Ssh=yes
```

Next, make sure systemd-networkd is running on the host system so that it can configure the network interface
connecting the host system to the container/VM spawned by mkosi. Once systemd-networkd is running, you should
be able to connect to a running mkosi image by executing `mkosi ssh` in the systemd repo directory.

Now we need to configure VSCode. First, make sure the C/C++ extension is installed. If you're already using
a different extension for code completion and other IDE features for C in VSCode, make sure to disable the
corresponding parts of the C/C++ extension in your VSCode user settings by adding the following entries:

```json
"C_Cpp.formatting": "Disabled",
"C_Cpp.intelliSenseEngine": "Disabled",
"C_Cpp.enhancedColorization": "Disabled",
"C_Cpp.suggestSnippets": false,
```

With the extension set up, we can create the launch.json file in the .vscode/ directory to tell the VSCode
debugger how to attach to the systemd instance running in our mkosi container/VM. Create the file and add the
following contents:

```json
{
    "version": "0.2.0",
    "configurations": [
        {
            "type": "cppdbg",
            "program": "/usr/lib/systemd/systemd",
            "processId": "${command:pickRemoteProcess}",
            "request": "attach",
            "name": "systemd",
            "pipeTransport": {
                "pipeProgram": "mkosi",
                "pipeArgs": [
                    "-C",
                    "/path/to/systemd/repo/directory/on/host/system/",
                    "ssh"
                ],
                "debuggerPath": "/usr/bin/gdb"
            },
            "MIMode": "gdb",
            "sourceFileMap": {
                "/root/build/../src": {
                    "editorPath": "${workspaceFolder}",
                    "useForBreakpoints": false
                },
                "/root/build/*": {
                    "editorPath": "${workspaceFolder}/mkosi.builddir",
                    "useForBreakpoints": false
                }
            }
        }
    ]
}
```

Now that the debugger knows how to connect to our process in the container/VM and we've set up the necessary
source mappings, go to the "Run and Debug" window and run the "systemd" debug configuration. If everything
goes well, the debugger should now be attached to the systemd instance running in the container/VM. You can
attach breakpoints from the editor and enjoy all the other features of VSCode's debugger.

To debug systemd components other than PID 1, set "program" to the full path of the component you want to
debug and set "processId" to "${command:pickProcess}". Now, when starting the debugger, VSCode will ask you
the PID of the process you want to debug. Run `systemctl show --property MainPID --value <component>` in the
container to figure out the PID and enter it when asked and VSCode will attach to that process instead.
