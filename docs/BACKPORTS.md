---
title: Backports
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Backports

The upstream systemd git repo at https://github.com/systemd/systemd
contains the `main` branch that progresses at a quick pace,
continuously bringing both bugfixes and new features.
New releases are tagged as `vNNN` on this branch.

In addition to the `main` branch,
the repo contains a number of branches for stable point updates for a given release,
called `vNNN-stable`.
Stable releases are tagged as `vNNN.X` on those branches.
See [list of branches](https://github.com/systemd/systemd/branches/all?query=-stable)
and [pull requests for stable branches](https://github.com/systemd/systemd/pulls?q=is%3Apr+is%3Aopen+label%3Astable-branch).

Distributions usually prefer basing their releases on those stable branches.
Stable branches are typically managed by distribution maintainers on an as-needed basis.

## Stable Branch Repository for older releases

Stable branches for releases up to 255 are available from
[https://github.com/systemd/systemd-stable](https://github.com/systemd/systemd-stable).

## Policy for backports into stable branches

If you are using a particular version and find yourself backporting several patches,
consider pushing a stable branch here for that version so others can benefit.

Please contact us if you are interested.

The following types of commits are cherry-picked onto those branches:

* bugfixes
* documentation updates, when relevant to this version
* hardware database additions, especially the keymap updates
* small non-conflicting features deemed safe to add in a stable release

Please try to ensure that anything backported to the stable repository is done
with the `git cherry-pick -x` option such that text stating the original SHA1 is added into the commit message.
This makes it easier to check where the code came from
(as sometimes it is necessary to add small fixes as new code due to the upstream refactors)
that are deemed too invasive to backport as a stable patch.

Pull requests for the stable branches should be tagged with `stable-branch`.

Pull requests that shall be backported to stable releases,
should be tagged with `needs-stable-backport`.
See [pull requests marked for backporting](https://github.com/systemd/systemd/pulls?q=is%3Apr+label%3Aneeds-stable-backport).
If only some commits should be backported, this should be mentioned in the pull request.
If the backport is not obvious, additional justification can also be provided in the pull request.
