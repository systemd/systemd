---
title: GitHub Labels
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# GitHub Labels

This document describes the meaning of the labels used on
[GitHub](https://github.com/systemd/systemd) issues and pull requests.
Only members of the `systemd` organization can set labels.

## `good-to-merge/trust-me-bro`

The pull request contains purely mechanical changes that are unlikely to be controversial.
Examples are simple refactoring, introducing internal helper functions in `string-util.h`,
adding tests, making non-major changes to newly introduced and unused daemons/libraries.

A maintainer may apply this label to such a pull request and merge it once CI passes, claude-review
is happy, and at least a working day has passed. The `please-review` label should be kept on the
PR so it still pops up in maintainer review queues. Do not use this label for changes that alter 
behavior, add features, or touch interfaces.

## `obs-build-images`

If a maintainer sets this label on a PR, the CI workflow will enable image building and publishing
on the Open Build Service, at a URL based on the PR number.
For example, for PR number 12345, system extension images for the respective distributions will be published
at the following URLs:

[Fedora 44](https://download.opensuse.org/repositories/system:/systemd:/ci:/systemd:/systemd:/PR-12345/fedora_44_images/)
[openSUSE Tumbleweed](https://download.opensuse.org/repositories/system:/systemd:/ci:/systemd:/systemd:/PR-12345/openSUSE_Tumbleweed_images/)
[Ubuntu 26.04](https://download.opensuse.org/repositories/system:/systemd:/ci:/systemd:/systemd:/PR-12345/ubuntu_26.04_images/)
[Arch Linux](https://download.opensuse.org/repositories/system:/systemd:/ci:/systemd:/systemd:/PR-12345/arch_images/)

The images available are signed with the [system:systemd:ci subproject key](https://build.opensuse.org/projects/system:systemd:ci/signing_keys)
which can be downloaded and added to the various trust stores.

`systemd-sysupdate`-compatible `SHA256SUMS` and `SHA256SUMS.gpg` are also published, so `systemd-sysupdate`
can be pointed at the URL(s) to automatically fetch the images.

The sysexts contain the systemd packages built from the PR branch, and nothing else, so they are compatible
with their respective distributions.

For the latest Fedora release, a full [ParticleOS](https://github.com/systemd/particleos) and a standalone
UKI are also built and published.

These images correspond to the ones built on each push to the main branch on (the top-level systemd project)[https://build.opensuse.org/project/show/system:systemd]
in OBS.
