---
title: Steps to a Successful Release
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Steps to a Successful Release

1. Add all items to NEWS
2. Update the contributors list in NEWS (`ninja -C build git-contrib`)
3. Update the time and place in NEWS
4. Update hwdb (`ninja -C build update-hwdb`, `ninja -C build update-hwdb-autosuspend`, commit separately).
5. Update syscall numbers (`ninja -C build update-syscall-tables update-syscall-header`).
6. [RC1] Update library numbers in `meson.build`
7. Update version number in `meson.version` (e.g. from `256~devel` to `256~rc1` or from `256~rc3` to `256`). Note that this uses a tilde (\~) instead of a hyphen (-) because tildes sort lower in version comparisons according to the [version format specification](https://uapi-group.org/specifications/specs/version_format_specification/), and we want `255~rc1` to sort lower than `255`.
8. Check dbus docs with `ninja -C build update-dbus-docs`
9. Update translation strings (`ninja -C build systemd-pot`, `ninja -C build systemd-update-po`) - drop the header comments from `systemd.pot` + re-add SPDX before committing. If the only change in a file is the 'POT-Creation-Date' field, then ignore that file.
10. Tag the release: `version="v$(sed 's/~/-/g' meson.version)" && git tag -s "${version}" -m "systemd ${version}"` (tildes are replaced with hyphens, because git doesn't accept the former).
11. Do `ninja -C build`
12. Make sure that the version string and package string match: `build/systemctl --version`
13. [FINAL] Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
14. "Draft" a new release on github (https://github.com/systemd/systemd/releases/new), mark "This is a pre-release" if appropriate.
15. Check that announcement to systemd-devel, with a copy&paste from NEWS, was sent. This should happen automatically.
16. Update IRC topic (`/msg chanserv TOPIC #systemd Version NNN released | Online resources https://systemd.io/`)
17. [FINAL] Create an empty -stable branch: `git push systemd origin/main:refs/heads/v${version}-stable`.
18. [FINAL] Build and upload the documentation (on the -stable branch): `ninja -C build doc-sync`
20. [FINAL] Change the Github Pages branch to the newly created branch (https://github.com/systemd/systemd/settings/pages) and set the 'Custom domain' to 'systemd.io'
21. [FINAL] Update version number in `meson.version` to the devel version of the next release (e.g. from `v256` to `v257~devel`)
