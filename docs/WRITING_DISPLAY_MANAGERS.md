---
title: Writing Display Managers
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Writing Display Managers

_Or: How to hook up your favorite X11 display manager with systemd_

systemd's logind service obsoletes ConsoleKit which was previously widely used on Linux distributions.
For X11 display managers the switch to logind requires a minimal amount of porting, however brings a couple of new features:
true automatic multi-seat support, proper tracking of session processes, (optional) automatic killing of user processes on logout, a synchronous low-level C API and much simplification.

This document should be read together with [Writing Desktop Environments](/WRITING_DESKTOP_ENVIRONMENTS) which focuses on the porting work necessary for desktop environments.

If required it is possible to implement ConsoleKit and systemd-logind support in the same display manager, detecting at runtime which interface is needed.
The [sd_booted()](http://www.freedesktop.org/software/systemd/man/sd_booted.html) call may be used to determine at runtime whether systemd is used.

To a certain level ConsoleKit and systemd-logind may be used side-by-side, but a number of features are not available if ConsoleKit is used, for example automatic multi-seat support.

Please have a look at the [Bus API of logind](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html) and the C API as documented in [sd-login(7)](http://www.freedesktop.org/software/systemd/man/sd-login.html).
(Also see below)

Minimal porting (without multi-seat) requires the following:

1. Remove/disable all code responsible for registering your service with ConsoleKit.
2. Make sure to register your greeter session via the PAM session stack, and make sure the PAM session modules include pam_systemd.
   Also, make sure to set the session class to "greeter." This may be done by setting the environment variable XDG_SESSION_CLASS to "greeter" with pam_misc_setenv() or setting the "class=greeter" option in the pam_systemd module, in order to allow applications to filter out greeter sessions from normal login sessions.
3. Make sure to register your logged in session via the PAM session stack as well, also including pam_systemd in it.
4. Optionally, use pam_misc_setenv() to set the environment variables XDG_SEAT and XDG_VTNR.
   The former should contain "seat0", the latter the VT number your session runs on. pam_systemd can determine these values automatically but it's nice to pass these variables anyway.
In summary: porting a display manager from ConsoleKit to systemd primarily means removing code, not necessarily adding any new code. Here, a cheers to simplicity!

1. Subscribe to seats showing up and going away, via the systemd-logind D-Bus interface's SeatAdded and SeatRemoved signals.
   Take possession of each seat by spawning your greeter on it.
   However, do so exclusively for seats where the boolean CanGraphical property is true.
   Note that there are seats that cannot do graphical, and there are seats that are text-only first, and gain graphical support later on.
   Most prominently this is actually seat0 which comes up in text mode, and where the graphics driver is then loaded and probed during boot.
   This means display managers must watch PropertyChanged events on all seats, to see if they gain (or lose) the CanGraphical field.
2. Use ListSeats() on the D-Bus interface to acquire a list of already available seats and also take possession of them.
3. For each seat you spawn a greeter/user session on use the XDG_SEAT and XDG_VTNR PAM environment variables to inform pam_systemd about the seat name, resp.
   VT number you start them on. Note that only the special seat "seat0" actually knows kernel VTs, so you shouldn't pass the VT number on any but the main seat, since it doesn't make any sense there.
4. Pass the seat name to the X server you start via the -seat parameter.
5. At this time X interprets the -seat parameter natively only for input devices, not for graphics devices.
   To work around this limitation we provide a tiny wrapper /lib/systemd/systemd-multi-seat-x which emulates the enumeration for graphics devices too.
   This wrapper will eventually go away, as soon as X learns udev-based graphics device enumeration natively, instead of the current PCI based one.
   Hence it is a good idea to fall back to the real X when this wrapper is not found.
   You may use this wrapper exactly like the real X server, and internally it will just exec() it after putting together a minimal multi-seat configuration.
   And that's already it.

While most information about seats, sessions and users is available on systemd-logind's D-Bus interface, this is not the only API.
The synchronous [sd-login(7)](http://www.freedesktop.org/software/systemd/man/sd-login.html) C interface is often easier to use and much faster too.
In fact it is possible to implement the scheme above entirely without D-Bus relying only on this API.
Note however, that this C API is purely passive, and if you want to execute an actually state changing operation you need to use the bus interface (for example, to switch sessions, or to kill sessions and suchlike).
Also have a look at the [logind Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html).
