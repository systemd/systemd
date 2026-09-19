---
title: Desktop Environment Integration
category: Concepts
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Desktop Environments

NOTE: This document is a work-in-progress.

## Single Graphical Session

systemd only supports running one graphical session per user at a time.
While this might not have always been the case historically, having multiple
sessions for one user running at the same time is problematic.
The DBus session bus is shared between all the logins, and services that are
started must be implicitly assigned to the user's current graphical session.

In principle it is possible to run a single graphical session across multiple
logind seats, and this could be a way to use more than one display per user.
When a user logs in to a second seat, the seat resources could be assigned
to the existing session, allowing the graphical environment to present it
is a single seat.
Currently nothing like this is supported or even planned.

## Pre-defined systemd units

[`systemd.special(7)`](https://www.freedesktop.org/software/systemd/man/latest/systemd.special.html)
defines the `graphical-session.target` and `graphical-session-pre.target` to
allow cross-desktop integration. Furthermore, systemd defines the three base
slices `background`, `app` and `session`.
All units should be placed into one of these slices depending on their purposes:

 * `session.slice`: Contains only processes essential to run the user's graphical session
 * `app.slice`: Contains all normal applications that the user is running
 * `background.slice`: Useful for low-priority background tasks

The purpose of this grouping is to assign different priorities to the
applications.
This could e.g. mean reserving memory to session processes,
preferentially killing background tasks in out-of-memory situations
or assigning different memory/CPU/IO priorities to ensure that the session
runs smoothly under load.

## XDG Unit Naming Convention for Apps

To ensure cross-desktop compatibility and encourage sharing of good practices,
desktop environments should adhere to the following conventions:

 * Apps should be placed in systemd units that adhere to the following naming
   convention: `app-<AppID>[@<RANDOM>].service` or `app-<AppID>-<RANDOM>.scope`.
   For example:
    - `app-org.kde.amarok.service`
    - `app-im.riot.Riot@12345.service`
    - `app-org.gnome.Evince-12345.scope`

 * For backwards-compatibility reasons, an alternative naming convention is also
   allowed: `app-<launcher>-<AppID>[@<RANDOM>].service` or
   `app-<launcher>-<AppID>-<RANDOM>.scope`. New code should not set a `<launcher>`
   when creating units for apps, but new parsers should be able to parse and
   ignore it. When this convention was first designed, the intent was for
   `<launcher>` to reflect the user's desktop environment, so that different
   desktops could have different drop-in overrides for apps. However, in practice
   `<launcher>` only ever represented the library responsible for putting the
   app into a systemd unit, which didn't necessarily correspond to the running desktop.
   Examples:
    - `app-gnome-org.gnome.Evince@12345.service`
    - `app-flatpak-org.telegram.desktop@12345.service`
    - `app-KDE-org.kde.okular@12345.service`
    - `app-gnome-org.gnome.Evince-12345.scope`

 * It is preferable to use `.service` units instead of `.scope` units. Static
   configuration files are preferable to transient units. In other words, systemd
   should be allowed to start and monitor the process on behalf of the caller
   where possible.

 * `<RANDOM>` should be a string of unique characters to ensure that multiple instances
   of the application can be launched. This can be omitted for non-transient
   single-instance service files, since we know that there will never be multiple
   instances of such apps. For scope files, a `<RANDOM>` is mandatory because the
   format would be ambiguous otherwise. A useful source of `<RANDOM>` could be
   the pidfdid of the app's initial process.

 * If no application ID is available, the launcher should generate a reasonable
   name when possible (e.g. using the basename of the `.desktop` file, or ultimately
   falling back to `basename(argv[0])`). This name must not contain a `-` character.

 * Note that it is valid to adhere to this naming scheme within a unit alias, so
   a parser should check the entire name array of the unit rather than just the
   unit ID.

This has the advantage of making it possible to reliably identify the app.

## XDG autostart integration

To allow XDG autostart integration, systemd ships a cross-desktop generator
to create appropriate units for the autostart directory
(`systemd-xdg-autostart-generator`).
Desktop Environments can opt-in to using this by starting `xdg-desktop-autostart.target`.
The systemd generator correctly handles `OnlyShowIn=` and `NotShowIn=`.
It also handles the KDE and GNOME specific `X-KDE-autostart-condition=` and `AutostartCondition=` by using desktop-environment-provided binaries in an `ExecCondition=` line.

However, this generator is somewhat limited in what it supports.
For example, all generated units will have `After=graphical-session.target` set on them,
and therefore may not be useful to start session services.

Desktop files can be marked to be explicitly excluded from the generator using the line
`X-systemd-skip=true`.
This should be set if an application provides its own systemd service file for startup.

## Startup and shutdown best practices

Question here are:

 * Are there strong opinions on how the session-leader process should watch the user's session units?
 * Should systemd/logind/… provide an integrated way to define a session in terms of a running *user* unit?
 * Is having `gnome-session-shutdown.target` that is run with `replace-irreversibly` considered a good practice?
