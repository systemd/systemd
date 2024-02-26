---
title: Backports
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Backports

The upstream systemd git repo at [https://github.com/systemd/systemd](https://github.com/systemd/systemd) only contains the main systemd branch that progresses at a quick pace, continuously bringing both bugfixes and new features.

Distributions usually prefer basing their releases on stabilized versions branched off from this, that receive the bugfixes but not the features.

## Stable Branch Repository

Stable branches are available from [https://github.com/systemd/systemd-stable](https://github.com/systemd/systemd-stable).

Stable branches are started for certain releases of systemd and named after them, e.g. v208-stable.
Stable branches are typically managed by distribution maintainers on an as needed basis.

For example v208 has been chosen for stable as several distributions are shipping this version and the official/upstream cycle of v208-v209 was a long one due to kdbus work.

If you are using a particular version and find yourself backporting several patches, you may consider pushing a stable branch here for that version so others can benefit.

Please contact us if you are interested.

The following types of commits are cherry-picked onto those branches:

* bugfixes
* documentation updates, when relevant to this version
* hardware database additions, especially the keymap updates
* small non-conflicting features deemed safe to add in a stable release

Please try to ensure that anything backported to the stable repository is done with the `git cherry-pick -x` option such that text stating the original SHA1 is added into the commit message.
This makes it easier to check where the code came from (as sometimes it is necessary to add small fixes as new code due to the upstream refactors) that are deemed too invasive to backport as a stable patch.
