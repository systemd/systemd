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

- Please ensure the issue is reproducible on main.
- Please ensure a fully working, end-to-end reproducer is provided.
- Please ensure the reproducer is real-world and not simulated or abstracted.
- Please ensure the reproducer demonstrably violates a security boundary.
- Please understand that most of our maintainers are volunteers and already have a heavy review burden. While we will try to triage and fix issues in a timely manner, we cannot guarantee any fixed timeline for issue resolution.
- While modern industry practices around coordinated disclosures encourage public disclosure to avoid vendors stonewalling researchers, we are an open source project that would gain little from needlessly stonewalling researchers. We thus kindly request that reporters do not publicly disclose issues they have reported to us before an agreed-to disclosure date.
