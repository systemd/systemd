---
title: Inhibitor Locks
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Inhibitor Locks

systemd 183 and newer include a logic to inhibit system shutdowns and sleep states. This is implemented as part of [systemd-logind.daemon(8)](http://www.freedesktop.org/software/systemd/man/systemd-logind.service.html) There are a couple of different use cases for this:

- A CD burning application wants to ensure that the system is not turned off or suspended while the burn process is in progress.

- A package manager wants to ensure that the system is not turned off while a package upgrade is in progress.

- An office suite wants to be notified before system suspend in order to save all data to disk, and delay the suspend logic until all data is written.

- A web browser wants to be notified before system hibernation in order to free its cache to minimize the amount of memory that needs to be virtualized.

- A screen lock tool wants to bring up the screen lock right before suspend, and delay the suspend until that's complete.

Applications which want to make use of the inhibition logic shall take an inhibitor lock via the [logind D-Bus API](https://www.freedesktop.org/software/systemd/man/latest/org.freedesktop.login1.html).

Seven distinct inhibitor lock types may be taken, or a combination of them:

1. _sleep_ inhibits system suspend and hibernation requested by (unprivileged) **users**
2. _shutdown_ inhibits high-level system power-off and reboot requested by (unprivileged) **users**
3. _idle_ inhibits that the system goes into idle mode, possibly resulting in **automatic** system suspend or shutdown depending on configuration.

- _handle-power-key_ inhibits the low-level (i.e. logind-internal) handling of the system power **hardware** key, allowing (possibly unprivileged) external code to handle the event instead.

4. Similar, _handle-suspend-key_ inhibits the low-level handling of the system **hardware** suspend key.
5. Similar, _handle-hibernate-key_ inhibits the low-level handling of the system **hardware** hibernate key.
6. Similar, _handle-lid-switch_ inhibits the low-level handling of the systemd **hardware** lid switch.

Two different modes of locks are supported:

1. _block_ inhibits operations entirely until the lock is released.
If such a lock is taken the operation will fail (but still may be overridden if the user possesses the necessary privileges).

2. _delay_ inhibits operations only temporarily, either until the lock is released or up to a certain amount of time.
The InhibitDelayMaxSec= setting in [logind.conf(5)](http://www.freedesktop.org/software/systemd/man/logind.conf.html) controls the timeout for this. This is intended to be used by applications which need a synchronous way to execute actions before system suspend but shall not be allowed to block suspend indefinitely.
This mode is only available for _sleep_ and _shutdown_ locks.

3. _block-weak_ that works as its non-weak counterpart, but that in addition may be ignored
automatically and silently under certain circumstances, unlike the former which is always respected.

Inhibitor locks are taken via the Inhibit() D-Bus call on the logind Manager object:

```
$ gdbus introspect --system --dest org.freedesktop.login1 --object-path /org/freedesktop/login1
node /org/freedesktop/login1 {
  interface org.freedesktop.login1.Manager {
    methods:
      Inhibit(in  s what,
              in  s who,
              in  s why,
              in  s mode,
              out h fd);
      ListInhibitors(out a(ssssuu) inhibitors);
      ...
    signals:
      PrepareForShutdown(b active);
      PrepareForSleep(b active);
      ...
    properties:
      readonly s BlockInhibited = '';
      readonly s DelayInhibited = '';
      readonly t InhibitDelayMaxUSec = 5000000;
      readonly b PreparingForShutdown = false;
      readonly b PreparingForSleep = false;
      ...
  };
  ...
};
```

**Inhibit()** is the only API necessary to take a lock. It takes four arguments:

- _What_ is a colon-separated list of lock types, i.e. `shutdown`, `sleep`, `idle`, `handle-power-key`, `handle-suspend-key`, `handle-hibernate-key`, `handle-lid-switch`. Example: "shutdown:idle"
- _Who_ is a human-readable, descriptive string of who is taking the lock. Example: "Package Updater"
- _Why_ is a human-readable, descriptive string of why the lock is taken. Example: "Package Update in Progress"
- _Mode_ is one of `block` or `delay`, see above. Example: "block"

Inhibit() returns a single value, a file descriptor that encapsulates the lock.
As soon as the file descriptor is closed (and all its duplicates) the lock is automatically released.
If the client dies while the lock is taken the kernel automatically closes the file descriptor so that the lock is automatically released.

A delay lock taken this way should be released ASAP on reception of PrepareForShutdown(true) (see below), but of course only after execution of the actions the application wanted to delay the operation for in the first place.

**ListInhibitors()** lists all currently active inhibitor locks. It returns an array of structs, each consisting of What, Who, Why, Mode as above, plus the PID and UID of the process that requested the lock.

The **PrepareForShutdown()** and **PrepareForSleep()** signals are emitted when a system suspend or shutdown has been requested and is about to be executed, as well as after the suspend/shutdown was completed (or failed).

The signals carry a boolean argument.
If _True_ the shutdown/sleep has been requested, and the preparation phase for it begins, if _False_ the operation has finished completion (or failed).

If _True_, this should be used as indication for applications to quickly execute the operations they wanted to execute before suspend/shutdown and then release any delay lock taken.
If _False_ the suspend/shutdown operation is over, either successfully or unsuccessfully (of course, this signal will never be sent if a shutdown request was successful).

The signal with _False_ is generally delivered only after the system comes back from suspend, the signal with _True_ possibly as well, for example when no delay lock was taken in the first place, and the system suspend hence executed without any delay.

The signal with _False_ is usually the signal on which applications request a new delay lock in order to be synchronously notified about the next suspend/shutdown cycle.

Note that watching PrepareForShutdown(true)/PrepareForSleep(true) without taking a delay lock is racy and should not be done, as any code that an application might want to execute on this signal might not actually finish before the suspend/shutdown cycle is executed.

_Again_: if you watch PrepareForShutdown(true)/PrepareForSleep(true), then you really should have taken a delay lock first. PrepareForSleep(false) may be subscribed to by applications which want to be notified about system resume events.

Note that this will only be sent out for suspend/resume cycles done via logind, i.e. generally only for high-level user-induced suspend cycles, and not automatic, low-level kernel induced ones which might exist on certain devices with more aggressive power management.

The **BlockInhibited** and **DelayInhibited** properties encode what types of locks are currently taken. These fields are a colon separated list of `shutdown`, `sleep`, `idle`, `handle-power-key`, `handle-suspend-key`, `handle-hibernate-key`, `handle-lid-switch`. The list is basically the union of the What fields of all currently active locks of the specific mode.

**InhibitDelayMaxUSec** contains the delay timeout value as configured in [logind.conf(5)](http://www.freedesktop.org/software/systemd/man/logind.conf.html).

The **PreparingForShutdown** and **PreparingForSleep** boolean properties are true between the two PrepareForShutdown() resp PrepareForSleep() signals that are sent out.
Note that these properties do not trigger PropertyChanged signals.

## Taking Blocking Locks

Here's the basic scheme for applications which need blocking locks such as a package manager or CD burning application:

1. Take the lock
2. Do your work you don't want to see interrupted by system sleep or shutdown
3. Release the lock

Example pseudo code:

```
fd = Inhibit("shutdown:idle", "Package Manager", "Upgrade in progress...", "block");
/* ...
      do your work
                 ... */
close(fd);
```

## Taking Delay Locks

Here's the basic scheme for applications which need delay locks such as a web browser or office suite:

1. As you open a document, take the delay lock
2. As soon as you see PrepareForSleep(true), save your data, then release the lock
3. As soon as you see PrepareForSleep(false), take the delay lock again, continue as before.

Example pseudo code:

```
int fd = -1;

takeLock() {
        if (fd >= 0)
                return;

        fd = Inhibit("sleep", "Word Processor", "Save any unsaved data in time...", "delay");
}

onDocumentOpen(void) {
        takeLock();
}

onPrepareForSleep(bool b) {
        if (b) {
                saveData();
                if (fd >= 0) {
                        close(fd);
                        fd = -1;
                }
         } else
                takeLock();

}

```

## Taking Key Handling Locks

By default logind will handle the power and sleep keys of the machine, as well as the lid switch in all states.

This ensures that this basic system behavior is guaranteed to work in all circumstances, on text consoles as well as on all graphical environments.

However, some DE might want to do their own handling of these keys, for example in order to show a pretty dialog box before executing the relevant operation, or to simply disable the action under certain conditions.
For these cases the handle-power-key, handle-suspend-key, handle-hibernate-key and handle-lid-switch type inhibitor locks are available.

When taken, these locks simply disable the low-level handling of the keys, they have no effect on system suspend/hibernate/poweroff executed with other mechanisms than the hardware keys (such as the user typing "systemctl suspend" in a shell).

A DE intending to do its own handling of these keys should simply take the locks at login time, and release them on logout; alternatively it might make sense to take this lock only temporarily under certain circumstances
(e.g. take the lid switch lock only when a second monitor is plugged in, in order to support the common setup where people close their laptops when they have the big screen connected).

These locks need to be taken in the "block" mode, "delay" is not supported for them.

If a DE wants to ensure the lock screen for the eventual resume is on the screen before the system enters suspend state, it should do this via a suspend delay inhibitor block (see above).

## Miscellanea

Taking inhibitor locks is a privileged operation. Depending on the action _org.freedesktop.login1.inhibit-block-shutdown_, _org.freedesktop.login1.inhibit-delay-shutdown_, _org.freedesktop.login1.inhibit-block-sleep_, _org.freedesktop.login1.inhibit-delay-sleep_, _org.freedesktop.login1.inhibit-block-idle_, _org.freedesktop.login1.inhibit-handle-power-key_, _org.freedesktop.login1.inhibit-handle-suspend-key_, _org.freedesktop.login1.inhibit-handle-hibernate-key_,_org.freedesktop.login1.inhibit-handle-lid-switch_.

In general it should be assumed that delay locks are easier to obtain than blocking locks, simply because their impact is much more minimal.
Note that the policy checks for Inhibit() are never interactive.

Inhibitor locks should not be misused.
For example taking idle blocking locks without a very good reason might cause mobile devices to never auto-suspend.
This can be quite detrimental for the battery.

If an application finds a lock denied it should not consider this much of an error and just continue its operation without the protecting lock.

The tool [systemd-inhibit(1)](http://www.freedesktop.org/software/systemd/man/systemd-inhibit.html) may be used to take locks or list active locks from the command line.

Note that gnome-session also provides an [inhibitor API](http://people.gnome.org/~mccann/gnome-session/docs/gnome-session.html#org.gnome.SessionManager.Inhibit), which is very similar to the one of systemd.
Internally, locks taken on gnome-session's interface will be forwarded to logind, hence both APIs are supported.

While both offer similar functionality they do differ in some regards.
For obvious reasons gnome-session can offer logout locks and screensaver avoidance locks which logind lacks.

logind's API OTOH supports delay locks in addition to block locks like GNOME.
Also, logind is available to system components, and centralizes locks from all users, not just those of a specific one.

In general: if in doubt it is probably advisable to stick to the GNOME locks, unless there is a good reason to use the logind APIs directly.
When locks are to be enumerated it is better to use the logind APIs however, since they also include locks taken by system services and other users.
