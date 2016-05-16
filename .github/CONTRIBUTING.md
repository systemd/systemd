# Contributing

We welcome contributions from everyone. However, please follow the following guidelines when posting a GitHub Pull
Request or filing a GitHub Issue on the systemd project:

## Filing Issues

* We use GitHub Issues **exclusively** for tracking **bugs** and **feature** **requests** of systemd. If you are
  looking for help, please contact our [mailing list](http://lists.freedesktop.org/mailman/listinfo/systemd-devel)
  instead.
* We only track bugs in the **two** **most** **recently** **released** **versions** of systemd in the GitHub Issue
  tracker. If you are using an older version of systemd, please contact your distribution's bug tracker instead.
* When filing an issue, specify the **systemd** **version** you are experiencing the issue with. Also, indicate which
  **distribution** you are using.
* Please include an explanation how to reproduce the issue you are pointing out.

Following these guidelines makes it easier for us to process your issue, and ensures we won't close your issue
right-away for being misfiled.

## Posting Pull Requests

* Make sure to post PRs only relative to a very recent git master.
* Follow our [Coding Style](https://raw.githubusercontent.com/systemd/systemd/master/CODING_STYLE) when contributing
  code. This is a requirement for all code we merge.
* Make sure to run "make check" locally, before posting your PR. We use a CI system, meaning we don't even look at your
  PR, if the build and tests don't pass.
* If you need to update the code in an existing PR, force-push into the same branch, overriding old commits with new versions.

## Final Words

We'd like to apologize in advance if we are not able to process and reply to your issue or PR right-away. We have a lot
of work to do, but we are trying our best!

Thank you very much for your contributions!
