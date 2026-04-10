---
title: Reporting of Security Vulnerabilities
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Reporting of Security Vulnerabilities

If you discover a security vulnerability, we'd appreciate a non-public disclosure.
systemd developers can be contacted privately by creating a new **[Security Advisory on GitHub](https://github.com/systemd/systemd/security/advisories/new)**
or via the **[systemd-security@redhat.com](mailto:systemd-security@redhat.com) mailing list**.
The disclosure will be coordinated with distributions.

(The [issue tracker](https://github.com/systemd/systemd/issues) and [systemd-devel mailing list](https://lists.freedesktop.org/mailman/listinfo/systemd-devel) are fully public.)

Subscription to the Security Advisories and/or systemd-security mailing list is open to **regular systemd contributors and people working in the security teams of various distributions**.
Those conditions should be backed by publicly accessible information (ideally, a track of posts and commits from the mail address in question).
If you fall into one of those categories and wish to be subscribed,
contact the maintainers or submit a **[subscription request](https://www.redhat.com/mailman/listinfo/systemd-security)**.

# Requirements for a Valid Report

- Issue must be reproducible on main
- Fully working, end-to-end reproducer must be provided
- Reproducer must be real-world and not simulated or abstracted
- Reproducer must demonstrably violate a security boundary
- Reporter must not impose any conditions on the project maintainers
- Reporter must not disclose a report elsewhere until the project maintainers have either accepted and disclosed it, or rejected it
- Project maintainers' time is largely volunteered and severely constrained, so violating these rules may result in access being removed from reporters
