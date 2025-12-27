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

Please make sure to follow our [Coding Style](/CODING_STYLE) when submitting
patches. Also have a look at our [Contribution Guidelines](/CONTRIBUTING).

When adding new functionality, tests should be added. For shared functionality
(in `src/basic/` and `src/shared/`) unit tests should be sufficient. The general
policy is to keep tests in matching files underneath `src/test/`, e.g.
`src/test/test-path-util.c` contains tests for any functions in
`src/basic/path-util.c`. If adding a new source file, consider adding a matching
test executable. For features at a higher level, tests in `src/test/` are very
strongly recommended. If that is not possible, integration tests in `test/` are
encouraged. Please always test your work before submitting a PR.

## Hacking on systemd with mkosi

[mkosi](https://mkosi.systemd.io/) is our swiss army knife for hacking on
systemd. It makes sure all necessary dependencies are available to build systemd
and allows building and booting an OS image with the latest systemd installed
for testing purposes.

First, install `mkosi` from the
[GitHub repository](https://github.com/systemd/mkosi#running-mkosi-from-the-repository)
or via your distribution's package manager. Note that systemd regularly adopts
newer mkosi features that are not in an official release yet so there's a good
chance that your distribution's packaged version of mkosi will be too old.

Make sure to read the "Unprivileged User Namespaces" section in the mkosi documentation
(run `mkosi documentation` to view the mkosi docs) and apply any necessary instructions
to make sure unprivileged user namespaces work on your system.

Then, you can build, run and test systemd executables as follows:

```sh
$ mkosi -f genkey                                            # Generate signing keys once.
$ mkosi -f box -- meson setup -Dbpf-framework=disabled build # bpftool detection inside mkosi box is broken on Ubuntu Noble and older
$ mkosi -f box -- meson compile -C build
$ mkosi -f box -- build/systemctl --version
$ mkosi -f box -- meson test -C build --print-errorlogs      # Run the unit tests
```

To build and boot an OS image with the latest systemd installed:

```sh
$ mkosi -f box -- meson compile -C build mkosi # (re-)build the OS image
$ mkosi boot                                       # Boot the image with systemd-nspawn.
$ mkosi vm                                         # Boot the image with qemu.
```

Putting this all together, here's a series of commands for preparing a patch for
systemd:

```sh
$ git clone https://github.com/systemd/mkosi.git
$ ln -s $PWD/mkosi/bin/mkosi ~/.local/bin/mkosi # Make sure ~/.local/bin is in $PATH.
$ git clone https://github.com/systemd/systemd.git
$ cd systemd
$ git checkout -b <BRANCH>                         # where BRANCH is the name of the branch
$ $EDITOR src/core/main.c                          # or wherever you'd like to make your changes
$ mkosi -f genkey                                  # Generate signing keys once.
$ mkosi -f box -- meson setup build            # Set up meson
$ mkosi -f box -- meson compile -C build mkosi # (re-)build the test image
$ mkosi vm                                         # Boot the image in qemu
$ git add -p                                       # interactively put together your patch
$ git commit                                       # commit it
$ git push -u <REMOTE>                             # where REMOTE is your "fork" on GitHub
```

And after that, head over to your repo on GitHub and click "Compare & pull
request"

Happy hacking!

The following sections contain advanced topics on how to speed up development or
streamline debugging. Feel free to read them if you're interested but they're
not required to write basic patches.

## Building the OS image without a tools tree

By default, `mkosi` will first build a tools tree and use it build the image and
provide the environment for `mkosi box`. To disable the tools tree and use
binaries from your host instead, write the following to `mkosi/mkosi.local.conf`:

```conf
[Build]
ToolsTree=
```

## Rebuilding systemd without rebuilding the OS image

Every time the `mkosi` target is built, a fresh image is built. To build the
latest changes and re-install systemd without rebuilding the image, run one of
the following commands in another terminal on your host after booting the image
(choose the right one depending on the distribution of the container or virtual
machine):

```sh
mkosi -R && mkosi ssh -- dnf upgrade --disablerepo="*" --assumeyes "/work/build/*.rpm"             # CentOS/Fedora
mkosi -R && mkosi ssh -- apt-get install "/work/build/*.deb"                                       # Debian/Ubuntu
mkosi -R && mkosi ssh -- pacman --upgrade --needed --noconfirm "/work/build/*.pkg.tar"             # Arch Linux
mkosi -R && mkosi ssh -- zypper --non-interactive install --allow-unsigned-rpm "/work/build/*.rpm" # OpenSUSE
```

and optionally restart the daemon(s) you're working on using
`systemctl restart <units>` or `systemctl daemon-reexec` if you're working on
pid1 or `systemctl soft-reboot` to restart everything.

## Building distribution packages with mkosi

To build distribution packages for a specific distribution and release without
building an actual image, the following command can be used:

```sh
mkosi -d <distribution> -r <release> -t none -f
```

Afterwards the distribution packages will be located in
`build/mkosi.builddir/<distribution>~<release>~<architecture>/`. To also build
debuginfo packages, the following command can be used:

```sh
mkosi -d <distribution> -r <release> -E WITH_DEBUG=1 -t none -f
```

To upgrade the systemd packages on the host system to the newer versions built
by mkosi, run the following:

```sh
run0 dnf upgrade build/mkosi.builddir/<distribution>~<release>~<architecture>/*.rpm                                           # Fedora/CentOS
run0 apt-get install build/mkosi.builddir/<distribution>~<release>~<architecture>/*.deb                                       # Debian/Ubuntu
run0 pacman --upgrade --needed --noconfirm build/mkosi.builddir/<distribution>~<release>~<architecture>/*.pkg.tar             # Arch Linux
run0 zypper --non-interactive install --allow-unsigned-rpm build/mkosi.builddir/<distribution>~<release>~<architecture>/*.rpm # OpenSUSE
```

To downgrade back to the old version shipped by the distribution, run the
following:

```sh
run0 dnf downgrade "systemd*" # Fedora/CentOS
# TODO: Other distributions
```

## Installing packages built from the main branch

Packages for main distributions are built on the SUSE Open Build Service and
repositories are published, so that they can be installed and upgraded easily.

Instructions on how to add the repository for each supported distribution can
[be found on OBS.](https://software.opensuse.org//download.html?project=system%3Asystemd&package=systemd)
The `systemd-boot` file is signed for Secure Boot, the self-signed certificate
can be downloaded for enrollment. For example, when using MOK Manager:

```sh
$ wget https://build.opensuse.org/projects/system:systemd/signing_keys/download?kind=ssl -O- | openssl x509 -inform pem -outform der -out obs.der
$ run0 mokutil --import obs.der
```

## Templating engines in .in files

Some source files are generated during build. We use two templating engines:
* meson's `configure_file()` directive uses syntax with `@VARIABLE@`.

See the [Meson docs for `configure_file()`](https://mesonbuild.com/Reference-manual.html#configure_file) for details.

{% raw %}
* most files are rendered using jinja2, with `{{VARIABLE}}` and `{% if … %}`,
`{% elif … %}`, `{% else … %}`, `{% endif … %}` blocks. `{# … #}` is a jinja2 comment,
i.e. that block will not be visible in the rendered output.
`{% raw %} … `{% endraw %}`{{ '{' }}{{ '% endraw %' }}}` creates a block where jinja2 syntax is not interpreted.

See the [Jinja Template Designer Documentation](https://jinja.palletsprojects.com/en/3.1.x/templates/#synopsis) for details.

Please note that files for both template engines use the `.in` extension.

## Developer and release modes

In the default meson configuration (`-Dmode=developer`),
certain checks are enabled that are suitable when hacking on systemd (such as internal documentation consistency checks).
Those are not useful when compiling for distribution and can be disabled by setting `-Dmode=release`.

## Sanitizers in mkosi

See [Testing systemd using sanitizers](/TESTING_WITH_SANITIZERS) for more information on how to build with sanitizers enabled in mkosi.

## Debugging binaries that need to run as root in vscode

When trying to debug binaries that need to run as root,
we need to do some custom configuration in vscode to have it try to run the applications as root and to ask the user for the root password when trying to start the binary.
To achieve this, we'll use a custom debugger path which points to a script that starts `gdb` as root using `pkexec`.
pkexec will prompt the user for their root password via a graphical interface.
This guide assumes the C/C++ extension is used for debugging.

First, create a file `sgdb` in the root of the systemd repository with the following contents and make it executable:

```sh
#!/bin/sh
exec pkexec gdb "$@"
```

Then, open launch.json in vscode, and set `miDebuggerPath` to `${workspaceFolder}/sgdb` for the corresponding debug configuration.
Now, whenever you try to debug the application, vscode will try to start gdb as root via pkexec which will prompt you for your password via a graphical interface.
After entering your password, vscode should be able to start debugging the application.

For more information on how to set up a debug configuration for C binaries,
please refer to the official vscode documentation [here](https://code.visualstudio.com/docs/cpp/launch-json-reference)

## Debugging systemd with mkosi + vscode

To simplify debugging systemd when testing changes using mkosi, we're going to show how to attach [VSCode](https://code.visualstudio.com/)'s debugger to an instance of systemd running in a mkosi image using QEMU.

To allow VSCode's debugger to attach to systemd running in a mkosi image,
we have to make sure it can access the virtual machine spawned by mkosi where systemd is running.
After booting the image with `mkosi vm`,
you should now be able to connect to it by running `mkosi ssh` from the same directory in another terminal window.

Now we need to configure VSCode.
First, make sure the C/C++ extension is installed.
If you're already using a different extension for code completion and other IDE features for C in VSCode,
make sure to disable the corresponding parts of the C/C++ extension in your VSCode user settings by adding the following entries:

```json
"C_Cpp.formatting": "Disabled",
"C_Cpp.intelliSenseEngine": "Disabled",
"C_Cpp.enhancedColorization": "Disabled",
"C_Cpp.suggestSnippets": false,
```

With the extension set up,
we can create the launch.json file in the .vscode/ directory to tell the VSCode debugger how to attach to the systemd instance running in our mkosi container/VM.
Create the file, and possibly the directory, and add the following contents:

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
                "pipeArgs": ["-C", "${workspaceFolder}", "ssh"],
                "debuggerPath": "/usr/bin/gdb"
            },
            "MIMode": "gdb",
            "sourceFileMap": {
                "/work/src": {
                    "editorPath": "${workspaceFolder}",
                    "useForBreakpoints": false
                },
            }
        }
    ]
}
```

Now that the debugger knows how to connect to our process in the container/VM and we've set up the necessary source mappings,
go to the "Run and Debug" window and run the "systemd" debug configuration.
If everything goes well, the debugger should now be attached to the systemd instance running in the container/VM.
You can attach breakpoints from the editor and enjoy all the other features of VSCode's debugger.

To debug systemd components other than PID 1,
set "program" to the full path of the component you want to debug and set "processId" to "${command:pickProcess}".
Now, when starting the debugger, VSCode will ask you the PID of the process you want to debug.
Run `systemctl show --property MainPID --value <component>`
in the container to figure out the PID and enter it when asked and VSCode will attach to that process instead.

## Debugging systemd-boot

During boot, systemd-boot and the stub loader will output messages like `systemd-boot@0x0A` and `systemd-stub@0x0B`,
providing the base of the loaded code.
This location can then be used to attach to a QEMU session (provided it was run with `-s`).
See `debug-sd-boot.sh` script in the tools folder which automates this processes.

If the debugger is too slow to attach to examine an early boot code passage,
the call to `DEFINE_EFI_MAIN_FUNCTION()` can be modified to enable waiting.
As soon as the debugger has control, we can then run `set variable wait = 0` or `return` to continue.
Once the debugger has attached, setting breakpoints will work like usual.

To debug systemd-boot in an IDE such as VSCode we can use a launch configuration like this:
```json
{
    "name": "systemd-boot",
    "type": "cppdbg",
    "request": "launch",
    "program": "${workspaceFolder}/build/src/boot/efi/systemd-bootx64.efi",
    "cwd": "${workspaceFolder}",
    "MIMode": "gdb",
    "miDebuggerServerAddress": ":1234",
    "setupCommands": [
        { "text": "shell mkfifo /tmp/sdboot.{in,out}" },
        { "text": "shell qemu-system-x86_64 [...] -s -serial pipe:/tmp/sdboot" },
        { "text": "shell ${workspaceFolder}/tools/debug-sd-boot.sh ${workspaceFolder}/build/src/boot/efi/systemd-bootx64.efi /tmp/sdboot.out systemd-boot.gdb" },
        { "text": "source /tmp/systemd-boot.gdb" },
    ]
}
```

## mkosi + clangd

[clangd](https://clangd.llvm.org/) is a language server that provides code completion, diagnostics and more
right in your editor of choice (with the right plugin installed). When using mkosi, we can run clangd in the
mkosi tools tree to avoid needing to install clangd on the host machine.

All that is required is to run `mkosi -f box true` once to make sure the tools tree is available and to modify
the path of the clangd binary used by your editor to the `mkosi.clangd` script included in the systemd repository.
For example, for VScode, you'd have to add the following to the VSCode workspace settings of the systemd repository:

```json
{
    "clangd.path": "<path-to-systemd-repository>/mkosi/mkosi.clangd",
}
```

The script passes any arguments it receives directly to clangd which you can use
for example to tell clangd where the compilation database can be found using the
`--compile-commands-dir=` option.

When using clangd, it's recommended to setup the build directory containing the
compilation database used by clangd to use clang as the compiler as well:

```sh
$ mkosi box -- env CC=clang CXX=clang++ meson setup build
```

Additionally, the `gensources` target can be used to make sure all generated
sources are generated to avoid clangd complaining that these source files don't
exist.

```sh
$ mkosi box -- ninja -C build gensources
```
