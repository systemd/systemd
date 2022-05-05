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
6. [RC1] Update version and library numbers in `meson.build`
7. Check dbus docs with `ninja -C build update-dbus-docs`
8. Tag the release: `version=vXXX-rcY && git tag -s "${version}" -m "systemd ${version}"`
9. Do `ninja -C build`
10. Make sure that the version string and package string match: `build/systemctl --version`
11. Upload the documentation: `ninja -C build doc-sync`
12. [FINAL] Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
13. "Draft" a new release on github (https://github.com/systemd/systemd/releases/new), mark "This is a pre-release" if appropriate.
14. Check that announcement to systemd-devel, with a copy&paste from NEWS, was sent. This should happen automatically.
15. Update IRC topic (`/msg chanserv TOPIC #systemd Version NNN released`)
16. [FINAL] Push commits to stable, create an empty -stable branch: `git push systemd-stable --atomic origin/main:main origin/main:refs/heads/${version}-stable`, and change the default branch to latest release (https://github.com/systemd/systemd-stable/settings/branches).
