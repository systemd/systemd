---
title: Automatic Boot Assessment
---

# Automatic Boot Assessment

systemd provides support for automatically reverting back to the previous
version of the OS or kernel in case the system consistently fails to boot. This
support is built into various of its components. When used together these
components provide a complete solution on UEFI systems, built as add-on to the
[Boot Loader
Specification](https://systemd.io/BOOT_LOADER_SPECIFICATION). However, the
different components may also be used independently, and in combination with
other software, to implement similar schemes, for example with other boot
loaders or for non-UEFI systems. Here's a brief overview of the complete set of
components:

* The
  [`systemd-boot(7)`](https://www.freedesktop.org/software/systemd/man/systemd-boot.html)
  boot loader optionally maintains a per-boot-loader-entry counter that is
  decreased by one on each attempt to boot the entry, prioritizing entries that
  have non-zero counters over those which already reached a counter of zero
  when choosing the entry to boot.

* The
  [`systemd-bless-boot.service(8)`](https://www.freedesktop.org/software/systemd/man/systemd-bless-boot.service.html)
  service automatically marks a boot loader entry, for which boot counting as
  mentioned above is enabled, as "good" when a boot has been determined to be
  successful, thus turning off boot counting for it.

* The
  [`systemd-bless-boot-generator(8)`](https://www.freedesktop.org/software/systemd/man/systemd-bless-boot-generator.html)
  generator automatically pulls in `systemd-bless-boot.service` when use of
  `systemd-boot` with boot counting enabled is detected.

* The
  [`systemd-boot-check-no-failures.service(8)`](https://www.freedesktop.org/software/systemd/man/systemd-boot-check-no-failures.service.html)
  service is a simple health check tool that determines whether the boot
  completed successfully. When enabled it becomes an indirect dependency of
  `systemd-bless-boot.service` (by means of `boot-complete.target`, see
  below), ensuring that the boot will not be considered successful if there are
  any failed services.

* The `boot-complete.target` target unit (see
  [`systemd.special(7)`](https://www.freedesktop.org/software/systemd/man/systemd.special.html))
  serves as a generic extension point both for units that shall be considered
  necessary to consider a boot successful on one side (example:
  `systemd-boot-check-no-failures.service` as described above), and units that
  want to act only if the boot is successful on the other (example:
  `systemd-bless-boot.service` as described above).

* The
  [`kernel-install(8)`](https://www.freedesktop.org/software/systemd/man/kernel-install.html)
  script can optionally create boot loader entries that carry an initial boot
  counter (the initial counter is configurable in `/etc/kernel/tries`).

# Details

The boot counting data `systemd-boot` and `systemd-bless-boot.service`
manage is stored in the name of the boot loader entries. If a boot loader entry
file name contains `+` followed by one or two numbers (if two numbers, then
those need to be separated by `-`) right before the `.conf` suffix, then boot
counting is enabled for it. The first number is the "tries left" counter
encoding how many attempts to boot this entry shall still be made. The second
number is the "tries done" counter, encoding how many failed attempts to boot
it have already been made. Each time a boot loader entry marked this way is
booted the first counter is decreased by one, and the second one increased by
one. (If the second counter is missing, then it is assumed to be equivalent to
zero.) If the "tries left" counter is above zero the entry is still considered
for booting (the entry's state is considered to be "indeterminate"), as soon as
it reached zero the entry is not tried anymore (entry state "bad"). If the boot
attempt completed successfully the entry's counters are removed from the name
(entry state "good"), thus turning off boot counting for the future.

## Walkthrough

Here's an example walkthrough of how this all fits together.

1. The user runs `echo 3 > /etc/kernel/tries` to enable boot counting.

2. A new kernel is installed. `kernel-install` is used to generate a new boot
   loader entry file for it. Let's say the version string for the new kernel is
   `4.14.11-300.fc27.x86_64`, a new boot loader entry
   `/boot/loader/entries/4.14.11-300.fc27.x86_64+3.conf` is hence created.

3. The system is booted for the first time after the new kernel is
   installed. The boot loader now sees the `+3` counter in the entry file
   name. It hence renames the file to `4.14.11-300.fc27.x86_64+2-1.conf`
   indicating that at this point one attempt has started and thus only one less
   is left. After the rename completed the entry is booted as usual.

4. Let's say this attempt to boot fails. On the following boot the boot loader
   will hence see the `+2-1` tag in the name, and hence rename the entry file to
   `4.14.11-300.fc27.x86_64+1-2.conf`, and boot it.

5. Let's say the boot fails again. On the subsequent boot the loader hence will
   see the `+1-2` tag, and rename the file to
   `4.14.11-300.fc27.x86_64+0-3.conf` and boot it.

6. If this boot also fails, on the next boot the boot loader will see the
   tag `+0-3`, i.e. the counter reached zero. At this point the entry will be
   considered "bad", and ordered to the end of the list of entries. The next
   newest boot entry is now tried, i.e. the system automatically reverted back
   to an earlier version.

The above describes the walkthrough when the selected boot entry continuously
fails. Let's have a look at an alternative ending to this walkthrough. In this
scenario the first 4 steps are the same as above:

1. *as above*

2. *as above*

3. *as above*

4. *as above*

5. Let's say the second boot succeeds. The kernel initializes properly, systemd
   is started and invokes all generators.

6. One of the generators started is `systemd-bless-boot-generator` which
   detects that boot counting is used. It hence pulls
   `systemd-bless-boot.service` into the initial transaction.

7. `systemd-bless-boot.service` is ordered after and `Requires=` the generic
   `boot-complete.target` unit. This unit is hence also pulled into the initial
   transaction.

8. The `boot-complete.target` unit is ordered after and pulls in various units
   that are required to succeed for the boot process to be considered
   successful. One such unit is `systemd-boot-check-no-failures.service`.

9. `systemd-boot-check-no-failures.service` is run after all its own
   dependencies completed, and assesses that the boot completed
   successfully. It hence exits cleanly.

10. This allows `boot-complete.target` to be reached. This signifies to the
    system that this boot attempt shall be considered successful.

11. Which in turn permits `systemd-bless-boot.service` to run. It now
    determines which boot loader entry file was used to boot the system, and
    renames it dropping the counter tag. Thus
    `4.14.11-300.fc27.x86_64+1-2.conf` is renamed to
    `4.14.11-300.fc27.x86_64.conf`. From this moment boot counting is turned
    off.

12. On the following boot (and all subsequent boots after that) the entry is
    now seen with boot counting turned off, no further renaming takes place.

# How to adapt this scheme to other setups

Of the stack described above many components may be replaced or augmented. Here
are a couple of recommendations.

1. To support alternative boot loaders in place of `systemd-boot` two scenarios
   are recommended:

    a. Boot loaders already implementing the Boot Loader Specification can simply
       implement an equivalent file rename based logic, and thus integrate fully
       with the rest of the stack.

    b. Boot loaders that want to implement boot counting and store the counters
       elsewhere can provide their own replacements for
       `systemd-bless-boot.service` and `systemd-bless-boot-generator`, but should
       continue to use `boot-complete.target` and thus support any services
       ordered before that.

2. To support additional components that shall succeed before the boot is
   considered successful, simply place them in units (if they aren't already)
   and order them before the generic `boot-complete.target` target unit,
   combined with `Requires=` dependencies from the target, so that the target
   cannot be reached when any of the units fail. You may add any number of
   units like this, and only if they all succeed the boot entry is marked as
   good. Note that the target unit shall pull in these boot checking units, not
   the other way around.

3. To support additional components that shall only run on boot success, simply
   wrap them in a unit and order them after `boot-complete.target`, pulling it
   in.

# FAQ

1. *Why do you use file renames to store the counter? Why not a regular file?*
   — Mainly two reasons: it's relatively likely that renames can be implemented
   atomically even in simpler file systems, while writing to file contents has
   a much bigger chance to be result in incomplete or corrupt data, as renaming
   generally avoids allocating or releasing data blocks. Moreover it has the
   benefit that the boot count metadata is directly attached to the boot loader
   entry file, and thus the lifecycle of the metadata and the entry itself are
   bound together. This means no additional clean-up needs to take place to
   drop the boot loader counting information for an entry when it is removed.

2. *Why not use EFI variables for storing the boot counter?* — The memory chips
   used to back the persistent EFI variables are generally not of the highest
   quality, hence shouldn't be written to more than necessary. This means we
   can't really use it for changes made regularly during boot, but can use it
   only for seldom made configuration changes.

3. *I have a service which — when it fails — should immediately cause a
   reboot. How does that fit in with the above?* — Well, that's orthogonal to
   the above, please use `FailureAction=` in the unit file for this.

4. *Under some condition I want to mark the current boot loader entry as bad
   right-away, so that it never is tried again, how do I do that?* — You may
   invoke `/usr/lib/systemd/systemd-bless-boot bad` at any time to mark the
   current boot loader entry as "bad" right-away so that it isn't tried again
   on later boots.
