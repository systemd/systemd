---
layout: default
---

systemd is a suite of basic building blocks for a Linux system. It provides a system and service manager that runs as PID 1 and starts the rest of the system.
  
systemd provides aggressive parallelization capabilities, uses socket and D-Bus activation for starting services, offers on-demand starting of daemons, keeps track of processes using Linux control groups, maintains mount and automount points, and implements an elaborate transactional dependency-based service control logic. systemd supports SysV and LSB init scripts and works as a replacement for sysvinit. 

Other parts include a logging daemon, utilities to control basic system configuration like the hostname, date, locale, maintain a list of logged-in users and running containers and virtual machines, system accounts, runtime directories and settings, and daemons to manage simple network configuration, network time synchronization, log forwarding, and name resolution.

---

{% assign by_category = site.pages | group_by:"category" %}
{% assign extra_pages = site.data.extra_pages | group_by:"category" %}
{% assign merged = by_category | concat: extra_pages | sort:"name" %}

{% for pair in merged %}
  {% if pair.name != "" %}
## {{ pair.name }}
{% assign sorted = pair.items | sort:"title" %}{% for page in sorted %}
* [{{ page.title }}]({{ page.url | relative_url }}){% endfor %}
  {% endif %}
{% endfor %}

## See also

* [Introductory blog story](http://0pointer.de/blog/projects/systemd.html)
* [Three](http://0pointer.de/blog/projects/systemd-update.html) [status](http://0pointer.de/blog/projects/systemd-update-2.html) [updates](http://0pointer.de/blog/projects/systemd-update-3.html)
* The [Wikipedia article](https://en.wikipedia.org/wiki/systemd)

---

<pre style="color:white; background-color:black; font-size:smaller; padding:6pt 8pt">
Welcome to <span style="color:blue">Fedora 20 (Heisenbug)</span>!

[  <span style="color:green">OK</span>  ] Reached target Remote File Systems.
[  <span style="color:green">OK</span>  ] Listening on Delayed Shutdown Socket.
[  <span style="color:green">OK</span>  ] Listening on /dev/initctl Compatibility Named Pipe.
[  <span style="color:green">OK</span>  ] Reached target Paths.
[  <span style="color:green">OK</span>  ] Reached target Encrypted Volumes.
[  <span style="color:green">OK</span>  ] Listening on Journal Socket.
         Mounting Huge Pages File System...
         Mounting POSIX Message Queue File System...
         Mounting Debug File System...
         Starting Journal Service...
[  <span style="color:green">OK</span>  ] Started Journal Service.
         Mounting Configuration File System...
         Mounting FUSE Control File System...
[  <span style="color:green">OK</span>  ] Created slice Root Slice.
[  <span style="color:green">OK</span>  ] Created slice User and Session Slice.
[  <span style="color:green">OK</span>  ] Created slice System Slice.
[  <span style="color:green">OK</span>  ] Reached target Slices.
[  <span style="color:green">OK</span>  ] Reached target Swap.
         Mounting Temporary Directory...
[  <span style="color:green">OK</span>  ] Reached target Local File Systems (Pre).
         Starting Load Random Seed...
         Starting Load/Save Random Seed...
[  <span style="color:green">OK</span>  ] Mounted Huge Pages File System.
[  <span style="color:green">OK</span>  ] Mounted POSIX Message Queue File System.
[  <span style="color:green">OK</span>  ] Mounted Debug File System.
[  <span style="color:green">OK</span>  ] Mounted Configuration File System.
[  <span style="color:green">OK</span>  ] Mounted FUSE Control File System.
[  <span style="color:green">OK</span>  ] Mounted Temporary Directory.
[  <span style="color:green">OK</span>  ] Started Load Random Seed.
[  <span style="color:green">OK</span>  ] Started Load/Save Random Seed.
[  <span style="color:green">OK</span>  ] Reached target Local File Systems.
         Starting Recreate Volatile Files and Directories...
         Starting Trigger Flushing of Journal to Persistent Storage...
[  <span style="color:green">OK</span>  ] Started Recreate Volatile Files and Directories.
         Starting Update UTMP about System Reboot/Shutdown...
[  <span style="color:green">OK</span>  ] Started Trigger Flushing of Journal to Persistent Storage.
[  <span style="color:green">OK</span>  ] Started Update UTMP about System Reboot/Shutdown.
[  <span style="color:green">OK</span>  ] Reached target System Initialization.
[  <span style="color:green">OK</span>  ] Reached target Timers.
[  <span style="color:green">OK</span>  ] Listening on D-Bus System Message Bus Socket.
[  <span style="color:green">OK</span>  ] Reached target Sockets.
[  <span style="color:green">OK</span>  ] Reached target Basic System.
         Starting Permit User Sessions...
         Starting D-Bus System Message Bus...
[  <span style="color:green">OK</span>  ] Started D-Bus System Message Bus.
         Starting Login Service...
         Starting Cleanup of Temporary Directories...
[  <span style="color:green">OK</span>  ] Started Permit User Sessions.
[  <span style="color:green">OK</span>  ] Started Cleanup of Temporary Directories.
         Starting Console Getty...
[  <span style="color:green">OK</span>  ] Started Console Getty.
[  <span style="color:green">OK</span>  ] Reached target Login Prompts.
[  <span style="color:green">OK</span>  ] Started Login Service.
[  <span style="color:green">OK</span>  ] Reached target Multi-User System.

Fedora release 20 (Heisenbug)
Kernel 3.9.2-200.fc18.x86_64 on an x86_64 (console)

fedora login:
</pre>
