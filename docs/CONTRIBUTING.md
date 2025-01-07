---
title: Contributing
category: Contributing
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Contributing

We welcome contributions from everyone. However, please follow the following guidelines when posting a GitHub Pull Request or filing a GitHub Issue on the systemd project:

## Filing Issues

* We use [GitHub Issues](https://github.com/systemd/systemd/issues) **exclusively** for tracking **bugs** and **feature** **requests** (RFEs) of systemd.
  If you are looking for help, please try the forums of your distribution first, or [systemd-devel mailing list](https://lists.freedesktop.org/mailman/listinfo/systemd-devel) for general questions about systemd.
* We only track bugs in the **two** **most** **recently** **released** (non-rc) **versions** of systemd in the GitHub Issue tracker.
  If you are using an older version of systemd, please contact your distribution's bug tracker instead (see below).
  See [GitHub Release Page](https://github.com/systemd/systemd/releases) for the list of most recent releases.
* When filing a feature request issue (RFE), please always check first if the newest upstream version of systemd already implements the feature,
  and whether there's already an issue filed for your feature by someone else.
* When filing an issue, specify the **systemd** **version** you are experiencing the issue with. Also, indicate which **distribution** you are using.
* Please include an explanation how to reproduce the issue you are pointing out.

Following these guidelines makes it easier for us to process your issue, and ensures we won't close your issue right-away for being misfiled.

### Older downstream versions

For older versions that are still supported by your distribution please use respective downstream tracker:

* **Fedora** - [bugzilla](https://bugzilla.redhat.com/enter_bug.cgi?product=Fedora&component=systemd)
* **RHEL/CentOS stream** - [Jira](https://issues.redhat.com/secure/CreateIssueDetails!init.jspa?pid=12332745&issuetype=1&components=12380515&priority=10300) or [contribute to systemd-rhel @GitHub](https://github.com/redhat-plumbers#systemd)
* **Debian** - [bugs.debian.org](https://bugs.debian.org/cgi-bin/pkgreport.cgi?pkg=systemd)

## Security vulnerability reports

See [reporting of security vulnerabilities](https://systemd.io/SECURITY).

## Posting Pull Requests

* Make sure to post PRs only relative to a recent tip of the `main` branch.
* Follow our [Coding Style](https://systemd.io/CODING_STYLE) when contributing code. This is a requirement for all code we merge.
* Please make sure to test your change before submitting the PR. See the [Hacking guide](https://systemd.io/HACKING) for details on how to do this.
* Make sure to run the test suite locally, before posting your PR. We use a CI system, meaning we don't even look at a PR if the build fails or the unit tests don't pass.
* If you need to update the code in an existing PR, force-push into the same branch, overriding old commits with new versions.
* After you have pushed a new version, add a comment explaining the latest changes.
* If you are copying existing code from another source (eg: a compat header), please make sure the license is compatible with `LGPL-2.1-or-later`.
  If the license is not `LGPL-2.1-or-later`, please add a note to [`LICENSES/README.md`](https://github.com/systemd/systemd/blob/main/LICENSES/README.md).
* If the pull request stalls without review, post a ping in a comment after some time has passed.
  We are always short on reviewer time, and pull requests which haven't seen any recent activity can be easily forgotten.
* Github will automatically add the `please-review` label when a pull request is opened or updated.
  If you need more information after a review, you can comment `/please-review` on the pull request to have Github add the `please-review` label to the pull request.

## Reviewing Pull Requests

* See [filtered list of pull requests](https://github.com/systemd/systemd/pulls?q=is%3Aopen+is%3Apr+-label%3A%22reviewed%2Fneeds-rework+%F0%9F%94%A8%22+-label%3Aneeds-rebase+-label%3Agood-to-merge%2Fwith-minor-suggestions+-label%3A%22good-to-merge%2Fwaiting-for-ci+%F0%9F%91%8D%22+-label%3Apostponed+-label%3A%22needs-reporter-feedback+%E2%9D%93%22+-label%3A%22dont-merge+%F0%9F%92%A3%22+-label%3A%22ci-fails%2Fneeds-rework+%F0%9F%94%A5%22+sort%3Aupdated-desc) for requests that are ready for review.
* After performing a review, set

  * `reviewed/needs-rework` if the pull request needs significant changes
  * `ci-fails/needs-rework` if the automatic tests fail and the failure is relevant to the pull request
  * `ci-failure-appears-unrelated` if the test failures seem irrelevant
  * `needs-rebase` if the pull request needs a rebase because of conflicts
  * `good-to-merge/waiting-for-ci` if the pull request should be merged without further review
  * `good-to-merge/with-minor-suggestions` if the pull request should be merged after an update without going through another round of reviews

Unfortunately only members of the `systemd` organization on github can change labels.
If your pull request is mislabeled, make a comment in the pull request and somebody will fix it.
Reviews from non-members are still welcome.

## Final Words

We'd like to apologize in advance if we are not able to process and reply to your issue or PR right-away. We have a lot of work to do, but we are trying our best!

Thank you very much for your contributions!

# Backward Compatibility And External Dependencies

We strive to keep backward compatibility where possible and reasonable.
The following are general guidelines, not hard rules, and case-by-case exceptions might be applied at the discretion of the maintainers.
The current set of build-time and runtime dependencies are documented in the [README](https://github.com/systemd/systemd/blob/main/README).

## New features

It is fine for new features/functionality/tools/daemons to require bleeding edge external dependencies, provided there
are runtime and build-time graceful fallbacks (e.g.: a daemon will not be built, runtime functionality will be skipped with a clear log message).
In case a new feature is added to both `systemd` and one of its dependencies, we expect the corresponding feature code to
be merged upstream in the dependency before accepting our side of the implementation.
Making use of new kernel syscalls can be achieved through compat wrappers in our tree (see: `src/basic/missing_syscall_def.h`),
and does not need to wait for glibc support.

## External Build/Runtime Dependencies

It is often tempting to bump external dependencies' minimum versions to cut cruft, and in general it's an essential part
of the maintenance process. But as a general rule, existing dependencies should not be bumped without strong
reasons. When possible, we try to keep compatibility with the most recent LTS releases of each mainstream distribution
for optional components, and with all currently maintained (i.e.: not EOL) LTS releases for core components. When in
doubt, ask before committing time to work on contributions if it's not clear that cutting support would be obviously
acceptable.

## Kernel Requirements

Same principles as with other dependencies should be applied. It is fine to require newer kernel versions for additional
functionality or optional features, but very strong reasons should be required for breaking compatibility for existing
functionality, especially for core components. It is not uncommon, for example, for embedded systems to be stuck on older
kernel versions due to hardware requirements, so do not assume everybody is running with latest and greatest at all times.
In general, [currently maintained LTS branches](https://www.kernel.org/category/releases.html) should keep being supported
for existing functionality.

## `libsystemd.so`

`libsystemd.so` is a shared public library, so breaking ABI/API compatibility would create lot of work for everyone, and is not allowed.
Instead, always add a new interface instead of modifying the signature of an existing function.
It is fine to mark an interface as deprecated to gently nudge users toward a newer one, but support for the old one must be maintained.
Symbol versioning and the compiler's deprecated attribute should be used when managing the lifetime of a public interface.

## `libudev.so`

`libudev.so` is a shared public library, and is still maintained, but should not gain new symbols at this point.
