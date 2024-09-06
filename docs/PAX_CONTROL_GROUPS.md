---
title: Pax Controla Groupiana
category: Users, Groups and Home Directories
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Pax Controla Groupiana

_aka "How to behave nicely in the cgroupfs trees"_

**Important Update: Please consult this document only as a historical reference.
It was written under the assumption that the cgroups tree was a shared resource.
However, after much discussion this concept has been deemed outdated.
The cgroups tree can no longer be considered a shared resource.
Instead, a management daemon of some kind needs to arbitrate access to it, and it needs to actively propagate changes between the entities it manages.
More specifically, on systemd systems this management daemon is systemd itself, accessible via a number of bus APIs.
This means instead of dealing directly with the low-level interfaces of the cgroup file system, please use systemd's high-level APIs as a replacement, see the
[New Control Group Interfaces](/CONTROL_GROUP_INTERFACE)
for details. They offer similar functionality.**

Are you writing an application interfacing with the cgroups tree?
The cgroups trees are a shared resource, other applications will use them too.
Here are a few recommendations how to write your application in a way that minimizes conflicts with other applications.
If you follow these guidelines applications should not step on any other application's toes and users will be happy.

Before you read these recommendations please make sure you understand cgroups thoroughly,
and specifically are aware what a controller is, what a named hierarchy is and so on.

## Intended Audience

You should consider these recommendations if you are you working on one of the following:

- You write a system or session manager based on cgroups (like systemd)
- You write a VM manager based on cgroups (like libvirt)
- You write a terminal application and want to place every shell in a separate cgroup (like gnome-terminal)
- You write a web browser and want to place every renderer in a separate cgroup (like Firefox or Chrome)
- You create a container for some purpose (such as systemd-nspawn)
- Or you use cgroups for any other purpose and want things to work nicely with other applications.

## General Recommendations

- If you use one of the kernel controllers, do _not_ assume you are the only one who uses them.
  Other programs may manipulate the tree, add cgroups and change group attributes at any time, and they will not inform you about it.
  The kernel provided controller hierarchies are a shared resource, so be nice.
- If you use a generic named hierarchy with no controller attached, then you may assume it's yours and only yours, and that no other programs interfere with it.
- If you use a generic named hierarchy with no controller attached, then make sure to name it after your project in order to minimize namespacing conflicts.
  A hierarchy named "name=web" is a bit generic.
  A hierarchy named "name=apache" a much better choice, if you are an Apache developer and need an entire hierarchy all for yourself.
- Do _not_ assume everybody uses the same library to manipulate the cgroups tree as you are.
  In fact most likely most applications and the user himself will manipulate the tree without any further indirection (i.e. will use naked system calls/shell commands)
- Never create cgroups at the top of the tree (i.e. with an absolute path).
  If possible find the cgroup your own process was started in and create subgroups only below that group (read /proc/self/cgroup to find it).
  If that's not applicable, then at least place yourself below the cgroup path of PID 1 (read /proc/1/cgroup to find it).
  This is important to ensure that containers work properly (the cgroupfs tree is currently not virtualized for containers!), and solves permission problems, and makes the whole system nicely stackable.
- A corollary of this: If you spawn subprocesses expect that they will create subcgroups.
  That means when terminating there might be subcgroups below the ones you created and you hence need to recursively remove them too.
  In fact, many of your operations must probably be executed in a recursive fashion.
- Do not play permission games: if you are an unprivileged user application then it's _not_ your business to ensure you have the right permissions
  (i.e. do not include any setuid code in your app to create groups).
  Instead your system manager (such as systemd),
  should provide you with the right set of permissions on the cgroup you are running in to create subgroups.
  Normally that should mean that depending on administrator configuration, you will or will not get access to create subgroups under the cgroup you are running in and the ability to add PIDs to it.
  If you don't get access to these hierarchies then this might be a decision by the administrator and you should do your best to go on, and fail gracefully.
- If you create a cgroup, then you are in charge of removing it too after using it.
  Do not remove other program's cgroups.
  Special exception: in some cases it is OK to pre-set attributes on certain cgroups that are primarily managed by another program.
  (Example: in systemd we are fine if you externally pre-create or manipulate service cgroups, for example to make changes to some attributes you cannot control with systemd natively, see below).
  In that case: create the cgroup and set the sticky bit (+t) on the tasks file in it.
  This will then be used as an indication to the primary manager of the group not to remove the cgroup at the end, in order to avoid that your settings are lost.
  This is of course a bit of a misuse of the sticky bit, but given that it serves no other purpose on Linux for normal files, it is an OK use, with a fitting meaning given the name of "sticky bit".
- If you find a process in a cgroup you are about to remove, and it is not yours, consider leaving the cgroup around.
  I.e. if rmdir returns EEMPTY, ignore this.
- The cgroup mount point for a specific hierarchy is /sys/fs/cgroup/$CONTROLLER/.
  (Example: /sys/fs/cgroup/cpu for the "cpu" controller).
  In your application you are welcome to rely on these standardized mount points,
  and it is not necessary to dynamically determine the current mount point via /proc/self/mountinfo (but if you do, that's of course fine, too).
  Note that /sys/fs/cgroup/$CONTROLLER/ might actually just be a symlink to some other mount point (see below).
- If multiple controllers are mounted into the same hierarchy, it is guaranteed that symlinks exist to make sure all jointly mounted controllers are still available under /sys/fs/cgroup/$CONTROLLER/.
  Example: if "cpu" and "cpuacct" are mounted together, then symlinks /sys/fs/cgroup/cpu and /sys/fs/cgroup/cpuacct will point to the joint mountpoint (which could be something like /sys/fs/cgroup/cpu+cpuacct).
- Your application should not mount the cgroup controller file systems (unless it is your own private named hierarchy).
  This is exclusively a job for the system manager or a system-wide init script such as cgconfig.
  If you work on a system manager or such an init script you must mount the cgroup controllers to /sys/fs/cgroup/$CONTROLLER/ or provide compatibility symlinks.
- It's a good idea not to fail if a cgroup already exists when you try to create it.
  Ignore EEXIST on mkdir.
- Avoid renaming cgroups or similar fancier file operations.
- Expect that other programs might readjust the attributes on your cgroups dynamically during runtime.
- When creating a cgroup pick a nice a descriptive name that is guessable and no surprise to the admin.
  The admin will thank you for this if he has to read the output of "ps -eo pid,args,cgroups"
- /sys/fs/cgroup is a tmpfs. If you create your own private named hierarchy then you are welcome to mount it into a subdirectory of this directory.
  This minimizes surprises for the user.
- /sys/fs/cgroup is a tmpfs, but it's only intended use is to act as place where control group hierarchies can be mounted or symlinked to.
  You should not place any other kind of file in this directory.
  The same way as /dev/shm is for POSIX shared memory segments only -- and nothing else -- this directory is for cgroup hierarchies only.
  Just because something is a tmpfs it doesn't mean you can actually use it for "temporary" files, thank you.
- Avoid creating orthogonal hierarchies in the various kernel controller hierarchies.
  Please make sure that the controllers contain the same hierarchy or subsets of each other.

## Cooperation with systemd

systemd adheres to the recommendations above and guarantees additional behavior which might be useful for writing applications that cooperate with systemd on cgroup management:

- If a service cgroup already exists, systemd will make use of it and not recreate it.
  (If +t is set on the tasks file it will not remove it when stopping a service, otherwise it will, see above).
  It is hence OK to pre-create cgroups and then let systemd use it, without having systemd remove it afterwards.
- If a service cgroup already exists, systemd will not override the attributes of the cgroup with the exception of those explicitly configured in the systemd unit files.
  It is hence OK to pre-create cgroups for use in systemd, and pre-apply attributes to it.
- To avoid that systemd places all services in automatic cgroups in the "cpu" hierarchy change the DefaultControllers= in /etc/systemd/system.conf and set it to the empty string.
- By default systemd will place services only in automatic cgroups in the "cpu" hierarchy and in its own private tree "name=systemd".
  If you want it to duplicate these trees in other hierarchies add them to DefaultControllers= in /etc/systemd/system.conf
- To opt-out or opt-in specific services from the automatic tree generation in the kernel controller hierarchies use ControlGroup= in the unit file.
  Use "ControlGroup=cpu:/" to opt-out of cgroup assignment for a service or "ControlGroup=cpu:/foo/bar" to manipulate the cgroup path.
- Stay away from the name=systemd named hierarchy.
  It's private property of systemd.
  You are welcome to explore it, but it is uncool to modify it from outside systemd.
Thanks.
