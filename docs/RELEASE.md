---
title: Steps to a Successful Release
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Steps to a Successful Release

1. Add all items to NEWS
1. Update the contributors list in NEWS (`ninja -C build git-contrib`)
1. Update the time and place in NEWS
1. Update hwdb (`ninja -C build update-hwdb`, `ninja -C build update-hwdb-autosuspend`, commit separately).
1. Update syscall numbers (`ninja -C build update-syscall-tables update-syscall-header`).
1. [RC1] Update version and library numbers in `meson.build`
1. Check dbus docs with `ninja -C build update-dbus-docs`
1. Update translation strings (`cd build`, `meson compile systemd-pot`, `meson compile systemd-update-po`) - drop the header comments from `systemd.pot` + re-add SPDX before committing. If the only change in a file is the 'POT-Creation-Date' field, then ignore that file.
1. Tag the release: `version=vXXX~rcY && git tag -s "${version}" -m "systemd ${version}"`. Note that this uses a tilde (\~) instead of a hyphen (-) because tildes sort lower in version comparisons according to the [version format specification](https://uapi-group.org/specifications/specs/version_format_specification/), and we want `v255~rc1` to sort lower than `v255`.
1. Do `ninja -C build`
1. Make sure that the version string and package string match: `build/systemctl --version`
1. [FINAL] Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
1. "Draft" a new release on github (https://github.com/systemd/systemd/releases/new), mark "This is a pre-release" if appropriate.
1. Check that announcement to systemd-devel, with a copy&paste from NEWS, was sent. This should happen automatically.
1. Update IRC topic (`/msg chanserv TOPIC #systemd Version NNN released | Online resources https://systemd.io/`)
1. [FINAL] Push commits to stable, create an empty -stable branch: `git push systemd-stable --atomic origin/main:main origin/main:refs/heads/${version}-stable`.
1. [FINAL] Build and upload the documentation (on the -stable branch): `ninja -C build doc-sync`
1. [FINAL] Change the default branch to latest release (https://github.com/systemd/systemd-stable/settings/branches).
1. [FINAL] Change the Github Pages branch in the stable repository to the newly created branch (https://github.com/systemd/systemd-stable/settings/pages) and set the 'Custom domain' to 'systemd.io'
