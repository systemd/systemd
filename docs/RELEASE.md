---
title: Steps to a Successful Release
category: Contributing
layout: default
---

# Steps to a Successful Release

1. Add all items to NEWS
2. Update the contributors list in NEWS (`meson compile -C build git-contrib`)
3. Update the time and place in NEWS
4. Update hwb (`meson compile -C build update-hwdb update-hwdb-autosuspend`)
5. [RC1] Update version and library numbers in `meson.build`
6. Check dbus docs with `meson compile -C build update-dbus-docs`
7. Tag the release: `version=vXXX-rcY && git tag -s "${version}" -m "systemd ${version}"`
8. Do `meson compile -C build`
9. Make sure that the version string and package string match: `build/systemctl --version`
10. Upload the documentation: `meson compile -C build doc-sync`
11. [FINAL] Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
12. "Draft" a new release on github (https://github.com/systemd/systemd/releases/new), mark "This is a pre-release" if appropriate.
13. Check that announcement to systemd-devel, with a copy&paste from NEWS, was sent. This should happen automatically.
14. Update IRC topic (`/msg chanserv TOPIC #systemd Version NNN released`)
15. [FINAL] Push commits to stable, create an empty -stable branch: `git push systemd-stable origin/master:master origin/master:refs/heads/${version}-stable`, and change the default branch to latest release (https://github.com/systemd/systemd-stable/settings/branches).
