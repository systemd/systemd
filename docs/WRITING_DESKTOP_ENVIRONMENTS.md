---
title: Writing Desktop Environments
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing Desktop Environments

_Or: how to hook up your favorite desktop environment with logind_

systemd's logind service obsoletes ConsoleKit which was previously widely used on Linux distributions.
This provides a number of new features, but also requires updating of the Desktop Environment running on it, in a few ways.

This document should be read together with [Writing Display Managers](/WRITING_DISPLAY_MANAGERS) which focuses on the porting work necessary for display managers.

If required it is possible to implement ConsoleKit and systemd-logind support in the same desktop environment code, detecting at runtime which interface is needed.
The [sd_booted()](http://www.freedesktop.org/software/systemd/man/sd_booted.html) call may be used to determine at runtime whether systemd is used.

To a certain level ConsoleKit and systemd-logind may be used side-by-side, but a number of features are not available if ConsoleKit is used.

Please have a look at the [Bus API of logind](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html) and the C API as documented in [sd-login(7)](http://www.freedesktop.org/software/systemd/man/sd-login.html). (Also see below)

Here are the suggested changes:

- Your session manager should listen to "Lock" and "Unlock" messages that are emitted from the session object logind exposes for your DE session, on the system bus.
  If "Lock" is received the screen lock should be activated, if "Unlock" is received it should be deactivated.
  This can easily be tested with "loginctl lock-sessions".
  See the [Bus API of logind](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html) for further details.
- Whenever the session gets idle the DE should invoke the SetIdleHint(True) call on the respective session object on the session bus.
  This is necessary for the system to implement auto-suspend when all sessions are idle.
  If the session gets used again it should call SetIdleHint(False).
  A session should be considered idle if it didn't receive user input (mouse movements, keyboard) in a while.
  See the [Bus API of logind](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html) for further details.
- To reboot/power-off/suspend/hibernate the machine from the DE use logind's bus calls Reboot(), PowerOff(), Suspend(), Hibernate(), HybridSleep().
  For further details see [Bus API of logind](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html).
- If your session manager handles the special power, suspend, hibernate hardware keys or the laptop lid switch on its own it is welcome to do so,
  but needs to disable logind's built-in handling of these events.
  Take one or more of the _handle-power-key_, _handle-suspend-key_, _handle-hibernate-key_, _handle-lid-switch_ inhibitor locks for that.
  See [Inhibitor Locks](/INHIBITOR_LOCKS) for further details on this.
- Before rebooting/powering-off/suspending/hibernating and when the operation is triggered by the user by clicking on some UI elements
  (or suchlike) it is recommended to show the list of currently active inhibitors for the operation, and ask the user to acknowledge the operation.
  Note that PK often allows the user to execute the operation ignoring the inhibitors.
  Use logind's ListInhibitors() call to get a list of these inhibitors. See [Inhibitor Locks](/INHIBITOR_LOCKS) for further details on this.
- If your DE contains a process viewer of some kind ("system monitor") it's a good idea to show session, service and seat information for each process.
  Use sd_pid_get_session(), sd_pid_get_unit(), sd_session_get_seat() to determine these.
  For details see [sd-login(7)](http://www.freedesktop.org/software/systemd/man/sd-login.html).

And that's all! Thank you!
