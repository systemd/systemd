---
title: Desktop Environment Integration
category: Concepts
layout: default
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

[`systemd.special(7)`](https://www.freedesktop.org/software/systemd/man/systemd.special.html)
defines the `graphical-session.target` and `graphical-session-pre.target` to
allow cross-desktop integration. Furthermore, systemd defines the three base
slices `background`, `apps` and `session`.
All units should be placed into one of these slices depending on their purposes:

 * `session.slice`: Contains only processes essential to run the user's graphical session
 * `apps.slice`: Contains all normal applications that the user is running
 * `background.slice`: Useful for low-priority background tasks

The purpose of this grouping is to assign different priorities to the
applications.
This could e.g. mean reserving memory to session processes,
preferentially killing background tasks in out-of-memory situations
or assinging different memory/CPU/IO priorities to ensure that the session
runs smoothly under load.

TODO: Will there be a default to place units into e.g. `apps.slice` by default
rather than the root slice?

## XDG standardization for applications

To ensure cross-desktop compatibility and encourage sharing of good practices,
desktop environments should adhere to the following conventions:

 * Application units should follow the scheme `apps-<launcher>-<ApplicationID>-<RANDOM>.service`,
   e.g. `apps-gnome-org.gnome.Evince-12345.service`,
   `apps-flatpak-org.telegram.desktop-12345.service` or `apps-KDE-org.kde.okular-12345.service`.
 * Using `.service` units instead of `.scope` units, i.e. allowing systemd to
   start the process on behalf of the caller,
   instead of the caller starting the process and letting systemd know about it,
   is encouraged.
 * If no application ID is available, the launcher should generate a reasonable
   name when possible (e.g. using `basename(argv[0])`). This name must not
   contain a `-` character.

This has the following advantages:
 * Using the `apps-<launcher>-` prefix means that the unit defaults can be
   adjusted using desktop environment specific drop-in files.
 * The application ID can be retrieved by stripping the prefix and postfix.
   This in turn should map to the corresponding `.desktop` file when available

TODO: Define the name of slices that should be used.
This could be `apps-<launcher>-<ApplicationID>-<RANDOM>.slice`.

TODO: Does it really make sense to insert the `<launcher>`? In GNOME I am
currently using a drop-in to configure `BindTo=graphical-session.target`,
`CollectMode=inactive-or-failed` and `TimeoutSec=5s`. I feel that such a
policy makes sense, but it may make much more sense to just define a
global default for all (graphical) applications.

 * Should application lifetime be bound to the session?
 * May the user have applications that do not belong to the graphical session (e.g. launched from SSH)?
 * Could we maybe add a default `apps-.service.d` drop-in configuration?

## XDG autostart integration

To allow XDG autostart integration, systemd will ship a cross-desktop generator
to create appropriate units for the autostart directory.
Desktop Environments will be able to make use of this simply by starting the
appropriate XDG related targets (representing e.g. content of the
`$XDG_CURRENT_DESKTOP` environment variable to handle `OnlyShowIn/NotShowIn`).
The names and ordering rules for these targets are to be defined.

This generator will likely never support certain desktop specific extensions.
One such example is the GNOME specific feature to bind a service to a settings
variable.

## Startup and shutdown best practices

Question here are:

 * Are there strong opinions on how the session-leader process should watch the user's session units?
 * Should systemd/logind/… provide an integrated way to define a session in terms of a running *user* unit?
 * Is having `gnome-session-shutdown.target` that is run with `replace-irreversibly` considered a good practice?
