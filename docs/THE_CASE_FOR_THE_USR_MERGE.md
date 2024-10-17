---
title: The Case for the /usr Merge
category: Documentation for Developers
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# The Case for the /usr Merge

**Why the /usr Merge Makes Sense for Compatibility Reasons**

_This is based on the [Fedora feature](https://fedoraproject.org/wiki/Features/UsrMove) for the same topic, put together by Harald Hoyer and Kay Sievers. This feature has been implemented successfully in Fedora 17._

Note that this page discusses a topic that is actually independent of systemd. systemd supports both systems with split and with merged /usr, and the /usr merge also makes sense for systemd-less systems. That said we want to encourage distributions adopting systemd to also adopt the /usr merge.

### What's Being Discussed Here?

Fedora (and other distributions) have finished work on getting rid of the separation of /bin and /usr/bin, as well as /sbin and /usr/sbin, /lib and /usr/lib, and /lib64 and /usr/lib64. All files from the directories in / will be merged into their respective counterparts in /usr, and symlinks for the old directories will be created instead:

```
/bin → /usr/bin
/sbin → /usr/sbin
/lib → /usr/lib
/lib64 → /usr/lib64
```

You are wondering why merging /bin, /sbin, /lib, /lib64 into their respective counterparts in /usr makes sense, and why distributions are pushing for it? You are wondering whether your own distribution should adopt the same change? Here are a few answers to these questions, with an emphasis on a compatibility point of view:

### Compatibility: The Gist of It

- Improved compatibility with other Unixes/Linuxes in _behavior_: After the /usr merge all binaries become available in both /bin and /usr/bin, resp. both /sbin and /usr/sbin (simply because /bin becomes a symlink to /usr/bin, resp. /sbin to /usr/sbin). That means scripts/programs written for other Unixes or other Linuxes and ported to your distribution will no longer need fixing for the file system paths of the binaries called, which is otherwise a major source of frustration. /usr/bin and /bin (resp. /usr/sbin and /sbin) become entirely equivalent.
- Improved compatibility with other Unixes (in particular Solaris) in _appearance_: The primary commercial Unix implementation is nowadays Oracle Solaris. Solaris has already completed the same /usr merge in Solaris 11. By making the same change in Linux we minimize the difference towards the primary Unix implementation, thus easing portability from Solaris.
- Improved compatibility with GNU build systems: The biggest part of Linux software is built with GNU autoconf/automake (i.e. GNU autotools), which are unaware of the Linux-specific /usr split. Maintaining the /usr split requires non-trivial project-specific handling in the upstream build system, and in your distribution's packages. With the /usr merge, this work becomes unnecessary and porting packages to Linux becomes simpler.
- Improved compatibility with current upstream development: In order to minimize the delta from your Linux distribution to upstream development the /usr merge is key.

### Compatibility: The Longer Version

A unified filesystem layout (as it results from the /usr merge) is more compatible with UNIX than Linux’ traditional split of /bin vs. /usr/bin. Unixes differ in where individual tools are installed, their locations in many cases are not defined at all and differ in the various Linux distributions. The /usr merge removes this difference in its entirety, and provides full compatibility with the locations of tools of any Unix via the symlink from /bin to /usr/bin.

#### Example

- /usr/bin/foo may be called by other tools either via /usr/bin/foo or /bin/foo, both paths become fully equivalent through the /usr merge. The operating system ends up executing exactly the same file, simply because the symlink /bin just redirects the invocation to /usr/bin.

The historical justification for a /bin, /sbin and /lib separate from /usr no longer applies today. ([More on the historical justification for the split](http://lists.busybox.net/pipermail/busybox/2010-December/074114.html), by Rob Landley) They were split off to have selected tools on a faster hard disk (which was small, because it was more expensive) and to contain all the tools necessary to mount the slower /usr partition. Today, a separate /usr partition already must be mounted by the initramfs during early boot, thus making the justification for a split-off moot. In addition a lot of tools in /bin and /sbin in the status quo already lost the ability to run without a pre-mounted /usr. There is no valid reason anymore to have the operating system spread over multiple hierarchies, it lost its purpose.

Solaris implemented the core part of the /usr merge 15 years ago already, and completed it with the introduction of Solaris 11. Solaris has /bin and /sbin only as symlinks in the root file system, the same way as you will have after the /usr merge: [Transitioning From Oracle Solaris 10 to Oracle Solaris 11 - User Environment Feature Changes](http://docs.oracle.com/cd/E23824_01/html/E24456/userenv-1.html).

Not implementing the /usr merge in your distribution will isolate it from upstream development. It will make porting of packages needlessly difficult, because packagers need to split up installed files into multiple directories and hard code different locations for tools; both will cause unnecessary incompatibilities. Several Linux distributions are agreeing with the benefits of the /usr merge and are already in the process to implement the /usr merge. This means that upstream projects will adapt quickly to the change, those making portability to your distribution harder.

### Beyond Compatibility

One major benefit of the /usr merge is the reduction of complexity of our system: the new file system hierarchy becomes much simpler, and the separation between (read-only, potentially even immutable) vendor-supplied OS resources and users resources becomes much cleaner. As a result of the reduced complexity of the hierarchy, packaging becomes much simpler too, since the problems of handling the split in the .spec files go away.

The merged directory /usr, containing almost the entire vendor-supplied operating system resources, offers us a number of new features regarding OS snapshotting and options for enterprise environments for network sharing or running multiple guests on one host. Static vendor-supplied OS resources are monopolized at a single location, that can be made read-only easily, either for the whole system or individually for each service. Most of this is much harder to accomplish, or even impossible, with the current arbitrary split of tools across multiple directories.

_With all vendor-supplied OS resources in a single directory /usr they may be shared atomically, snapshots of them become atomic, and the file system may be made read-only as a single unit._

#### Example: /usr Network Share

- With the merged /usr directory we can offer a read-only export of the vendor supplied OS to the network, which will contain almost the entire operating system resources. The client hosts will then only need a minimal host-specific root filesystem with symlinks pointing into the shared /usr filesystem. From a maintenance perspective this is the first time where sharing the operating system over the network starts to make sense. Without the merged /usr directory (like in traditional Linux) we can only share parts of the OS at a time, but not the core components of it that are located in the root file system. The host-specific root filesystem hence traditionally needs to be much larger, cannot be shared among client hosts and needs to be updated individually and often. Vendor-supplied OS resources traditionally ended up "leaking" into the host-specific root file system.

#### Example: Multiple Guest Operating Systems on the Same Host

- With the merged /usr directory, we can offer to share /usr read-only with multiple guest operating systems, which will shrink down the guest file system to a couple of MB. The ratio of the per-guest host-only part vs. the shared operating system becomes nearly optimal.
  In the long run the maintenance burden resulting of the split-up tools in your distribution, and hard-coded deviating installation locations to distribute binaries and other packaged files into multiple hierarchies will very likely cause more trouble than the /usr merge itself will cause.

## Myths and Facts

**Myth #1**: Fedora is the first OS to implement the /usr merge

**Fact**: Oracle Solaris has implemented the /usr merge in parts 15 years ago, and completed it in Solaris 11. Fedora is following suit here, it is not the pioneer.

**Myth #2**: Fedora is the only Linux distribution to implement the /usr merge

**Fact**: Multiple other Linux distributions have been working in a similar direction.

**Myth #3**: The /usr merge decreases compatibility with other Unixes/Linuxes

**Fact**: By providing all binary tools in /usr/bin as well as in /bin (resp. /usr/sbin + /sbin) compatibility with hard coded binary paths in scripts is increased. When a distro A installs a tool “foo” in /usr/bin, and distro B installs it in /bin, then we’ll provide it in both, thus creating compatibility with both A and B.

**Myth #4**: The /usr merge’s only purpose is to look pretty, and has no other benefits

**Fact**: The /usr merge makes sharing the vendor-supplied OS resources between a host and networked clients as well as a host and local lightweight containers easier and atomic. Snapshotting the OS becomes a viable option. The /usr merge also allows making the entire vendor-supplied OS resources read-only for increased security and robustness.

**Myth #5**: Adopting the /usr merge in your distribution means additional work for your distribution's package maintainers

**Fact**: When the merge is implemented in other distributions and upstream, not adopting the /usr merge in your distribution means more work, adopting it is cheap.

**Myth #6**: A split /usr is Unix “standard”, and a merged /usr would be Linux-specific

**Fact**: On SysV Unix /bin traditionally has been a symlink to /usr/bin. A non-symlinked version of that directory is specific to non-SysV Unix and Linux.

**Myth #7**: After the /usr merge one can no longer mount /usr read-only, as it is common usage in many areas.

**Fact**: Au contraire! One of the reasons we are actually doing this is to make a read-only /usr more thorough: the entire vendor-supplied OS resources can be made read-only, i.e. all of what traditionally was stored in /bin, /sbin, /lib on top of what is already in /usr.

**Myth #8**: The /usr merge will break my old installation which has /usr on a separate partition.

**Fact**: This is perfectly well supported, and one of the reasons we are actually doing this is to make placing /usr of a separate partition more thorough. What changes is simply that you need to boot with an initrd that mounts /usr before jumping into the root file system. Most distributions rely on initrds anyway, so effectively little changes.

**Myth #9**: The /usr split is useful to have a minimal rescue system on the root file system, and the rest of the OS on /usr.

**Fact**: On Fedora the root directory contains ~450MB already. This hasn't been minimal since a long time, and due to today's complex storage and networking technologies it's unrealistic to ever reduce this again. In fact, since the introduction of initrds to Linux the initrd took over the role as minimal rescue system that requires only a working boot loader to be started, but not a full file system.

**Myth #10**: The status quo of a split /usr with mounting it without initrd is perfectly well supported right now and works.

**Fact**: A split /usr without involvement of an initrd mounting it before jumping into the root file system [hasn't worked correctly since a long time](/SEPARATE_USR_IS_BROKEN).

**Myth #11**: Instead of merging / into /usr it would make a lot more sense to merge /usr into /.

**Fact**: This would make the separation between vendor-supplied OS resources and machine-specific even worse, thus making OS snapshots and network/container sharing of it much harder and non-atomic, and clutter the root file system with a multitude of new directories.

---

If this page didn't answer your questions you may continue reading [on the Fedora feature page](https://fedoraproject.org/wiki/Features/UsrMove) and this [mail from Lennart](http://thread.gmane.org/gmane.linux.redhat.fedora.devel/155511/focus=155792).
