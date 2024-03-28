---
title: Presets
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Presets

## Why?

Different **distributions** have different policies on which services shall be enabled by default when the package they are shipped in is installed.
On Fedora all services stay off by default, so that installing a package will not cause a service to be enabled (with some exceptions).
On Debian all services are immediately enabled by default, so that installing a package will cause its service(s) to be enabled right-away.

Different **spins** (flavours, remixes, whatever you might want to call them) of a distribution also have different policies on what services to enable, and what services to leave off.
For example, the Fedora default will enable gdm as display manager by default, while the Fedora KDE spin will enable kdm instead.

Different **sites** might also have different policies what to turn on by default and what to turn off.
For example, one administrator would prefer to enforce the policy of "ssh should be always on, but everything else off", while another one might say "snmp always on, and for everything else use the distribution policy defaults".

## The Logic

Traditionally, policy about what services shall be enabled and what services shall not have been decided globally by the distributions, and were enforced in each package individually.
This made it cumbersome to implement different policies per spin or per site, or to create software packages that do the right thing on more than one distribution.
The enablement _mechanism_ was also encoding the enablement _policy_.

systemd 32 and newer support package "preset" policies.
These encode which units shall be enabled by default when they are installed, and which units shall not be enabled.

Preset files may be written for specific distributions, for specific spins or for specific sites, in order to enforce different policies as needed.
Preset policies are stored in .preset files in /usr/lib/systemd/system-preset/.
If no policy exists the default implied policy of "enable everything" is enforced, i.e. in Debian style.

The policy encoded in preset files is applied to a unit by invoking "systemctl preset ".
It is recommended to use this command in all package post installation scriptlets.
"systemctl preset " is identical to "systemctl enable " resp. "systemctl disable " depending on the policy.

Preset files allow clean separation of enablement mechanism (inside the package scriptlets, by invoking "systemctl preset"), and enablement policy (centralized in the preset files).

## Documentation

Documentation for the preset policy file format is available here: [http://www.freedesktop.org/software/systemd/man/systemd.preset.html](http://www.freedesktop.org/software/systemd/man/systemd.preset.html)

Documentation for "systemctl preset" you find here: [http://www.freedesktop.org/software/systemd/man/systemctl.html](http://www.freedesktop.org/software/systemd/man/systemctl.html)

Documentation for the recommended package scriptlets you find here: [http://www.freedesktop.org/software/systemd/man/daemon.html](http://www.freedesktop.org/software/systemd/man/daemon.html)

## How To

For the preset logic to be useful, distributions need to implement a couple of steps:

- The default distribution policy needs to be encoded in a preset file /usr/lib/systemd/system-preset/99-default.preset or suchlike, unless the implied policy of "enable everything" is the right choice.
For a Fedora-like policy of "enable nothing" it is sufficient to include the single line "disable" into that file.
The default preset file should be installed as part of one the core packages of the distribution.

- All packages need to be updated to use "systemctl preset" in the post install scriptlets.

- (Optionally) spins/remixes/flavours should define their own preset file, either overriding or extending the default distribution preset policy. Also see the fedora feature page: [https://fedoraproject.org/wiki/Features/PackagePresets](https://fedoraproject.org/wiki/Features/PackagePresets)
