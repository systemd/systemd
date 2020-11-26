---
title: Steps to a Successful Release
category: Contributing
layout: default
---

# Steps to a Successful Release

1. Add all items to NEWS
2. Update the contributors list in NEWS (`ninja -C build git-contrib`)
3. Update the time and place in NEWS
4. [RC1] Update version and library numbers in `meson.build`
5. Check dbus docs with `ninja -C build man/update-dbus-docs`
6. Tag the release: `version=vXXX-rcY && git tag -s "${version}" -m "systemd ${version}"`
7. Do `ninja -C build`
8. Make sure that the version string and package string match: `build/systemctl --version`
9. Upload the documentation: `ninja -C build doc-sync`
10. [FINAL] Close the github milestone and open a new one (https://github.com/systemd/systemd/milestones)
11. "Draft" a new release on github (https://github.com/systemd/systemd/releases/new), mark "This is a pre-release" if appropriate.
12. Check that announcement to systemd-devel, with a copy&paste from NEWS, was sent. This should happen automatically.
13. Update IRC topic (`/msg chanserv TOPIC #systemd Version NNN released`)
14. [FINAL] Push commits to stable, create an empty -stable branch: `git push systemd-stable origin/master:master origin/master:refs/heads/${version}-stable`, and change the default branch to latest release (https://github.com/systemd/systemd-stable/settings/branches).
