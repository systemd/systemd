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
