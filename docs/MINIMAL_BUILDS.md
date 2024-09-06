---
title: Minimal Builds
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Minimal Builds

systemd includes a variety of components.
The core components are always built (which includes systemd itself, as well as udevd and journald).
Many of the other components can be disabled at compile time with configure switches.

For some uses the configure switches do not provide sufficient modularity.
For example, they cannot be used to build only the man pages, or to build only the tmpfiles tool, only detect-virt or only udevd.

If such modularity is required that goes beyond what we support in the configure script we can suggest you two options:

1. Build systemd as usual, but pick only the built files you need from the result of "make install DESTDIR=<directory>", by using the file listing functionality of your packaging software.
For example: if all you want is the tmpfiles tool, then build systemd normally, and list only /usr/bin/systemd-tmpfiles in the .spec file for your RPM package.
This is simple to do, allows you to pick exactly what you need, but requires a larger number of build dependencies (but not runtime dependencies).

2. If you want to reduce the build time dependencies (though only dbus and libcap are needed as build time deps) and you know the specific component you are interested in doesn't need it, then create a dummy .pc file for that dependency (i.e. basically empty), and configure systemd with PKG_CONFIG_PATH set to the path of these dummy .pc files. Then, build only the few bits you need with "make foobar", where foobar is the file you need.

We are open to merging patches for the build system that make more "fringe" components of systemd optional. However, please be aware that in order to keep the complexity of our build system small and its readability high, and to make our lives easier, we will not accept patches that make the minimal core components optional, i.e. systemd itself, journald and udevd.

Note that the .pc file trick mentioned above currently doesn't work for libcap, since libcap doesn't provide a .pc file. We invite you to go ahead and post a patch to libcap upstream to get this corrected. We'll happily change our build system to look for that .pc file then. (a .pc file has been sent to upstream by Bryan Kadzban).
