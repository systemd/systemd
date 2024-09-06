---
title: Diagnosing Boot Problems
category: Manuals and Documentation for Users and Administrators
layout: default
SPDX-License-Identifier: LGPL-2.1-or-later
---

# Diagnosing Boot Problems

If your machine gets stuck during boot, first check if the hang happens before or after control passes to systemd.

Try to boot without `rhgb` and `quiet` on the kernel command line.
If you see some messages like these:

* Welcome to Fedora _VERSION_ (_codename_)!"
* Starting _name_...
* \[ OK \] Started _name_.

then systemd is running.
(See an actual [screenshot](../assets/f17boot.png).)

Debugging always gets easier if you can get a shell.
If you do not get a login prompt, try switching to a different virtual terminal using CTRL+ALT+F\_\_.
Problems with a display server startup may manifest themselves as a missing login on tty1, but other VTs working.

If the boot stops without presenting you with a login on any virtual console,
let it retry for _up to 5 minutes_ before declaring it definitely stuck.
There is a chance that a service that has trouble starting will be killed after this timeout and the boot will continue normally.
Another possibility is that a device for an important mountpoint will fail to appear and you will be presented with _emergency mode_.

## If You Get No Shell

If you get neither a normal login nor the emergency mode shell,
you will need to do additional steps to get debugging information out of the machine.

* Try CTRL+ALT+DEL to reboot.
  * If it does not reboot, mention it in your bugreport. Meanwhile force the reboot with
  [SysRq](http://fedoraproject.org/wiki/QA/Sysrq)
  or hard reset.
* When booting the next time, you will have to add some kernel command line arguments depending on which of the debugging strategies you choose from the following options.

### Debug Logging to a Serial Console

If you have a hardware serial console available or if you are debugging in a virtual machine
(e.g. using virt-manager you can switch your view to a serial console in the menu View -> Text Consoles or connect from the terminal using `virsh console MACHINE`),
you can ask systemd to log lots of useful debugging information to it by booting with:

```sh
systemd.log_level=debug systemd.log_target=console console=ttyS0,38400 console=tty1
```

The above is useful if pid 1 is failing, but if a later but critical boot service is broken (such as networking),
you can configure journald to forward to the console by using:

```sh
systemd.journald.forward_to_console=1 console=ttyS0,38400 console=tty1
```

console= can be specified multiple times, systemd will output to all of them.

### Booting into Rescue or Emergency Targets

To boot directly into rescue target add `systemd.unit=rescue.target` or just `1` to the kernel command line.
This target is useful if the problem occurs somewhere after the basic system is brought up, during the starting of "normal" services.
If this is the case, you should be able to disable the bad service from here.
If the rescue target will not boot either, the more minimal emergency target might.

To boot directly into emergency shell add `systemd.unit=emergency.target` or `emergency` to the kernel command line.
Note that in the emergency shell you will have to remount the root filesystem read-write by yourself before editing any files:

```sh
mount -o remount,rw /
```

Common issues that can be resolved in the emergency shell are bad lines in `/etc/fstab`.
After fixing **/etc/fstab**, run `systemctl daemon-reload` to let systemd refresh its view of it.

If not even the emergency target works, you can boot directly into a shell with `init=/bin/sh`.
This may be necessary in case systemd itself or some libraries it depends on are damaged by filesystem corruption.
You may need to reinstall working versions of the affected packages.

If `init=/bin/sh` does not work, you must boot from another medium.

### Early Debug Shell

You can enable shell access to be available very early in the startup process to fall back on and diagnose systemd related boot up issues with various systemctl commands.
Enable it using:

```sh
systemctl enable debug-shell.service
```

or by specifying

```sh
systemd.debug_shell=1
```

on the kernel command line.

**Tip**: If you find yourself in a situation where you cannot use systemctl to communicate with a running systemd
(e.g. when setting this up from a different booted system),
you can avoid communication with the manager by specifying `--root=`:

```sh
systemctl --root=/ enable debug-shell.service
```

Once enabled, the next time you boot you will be able to switch to tty9 using CTRL+ALT+F9 and have a root shell there available from an early point in the booting process.
You can use the shell for checking the status of services, reading logs, looking for stuck jobs with `systemctl list-jobs`, etc.

**Warning:** Use this shell only for debugging!
Do not forget to disable systemd-debug-shell.service after you've finished debugging your boot problems.
Leaving the root shell always available would be a security risk.

It is also possible to alias `kbrequest.target` to `debug-shell.service` to start the debug shell on demand.
This has the same security implications, but avoids running the shell always.

### verify prerequisites

A (at least partly) populated `/dev` is required.
Depending on your setup (e.g. on embedded systems),
check that the Linux kernel config options `CONFIG_DEVTMPFS` and `CONFIG_DEVTMPFS_MOUNT` are set.
Also support for cgroups and fanotify is recommended for a flawless operation, so check that the Linux kernel config options `CONFIG_CGROUPS` and `CONFIG_FANOTIFY` are set.
The message "Failed to get D-Bus connection: No connection to service manager."
during various `systemctl` operations is an indicator that these are missing.

## If You Can Get a Shell

When you have systemd running to the extent that it can provide you with a shell,
please use it to extract useful information for debugging.
Boot with these parameters on the kernel command line:

```sh
systemd.log_level=debug systemd.log_target=kmsg log_buf_len=1M printk.devkmsg=on
```

in order to increase the verbosity of systemd, to let systemd write its logs to the kernel log buffer,
to increase the size of the kernel log buffer, and to prevent the kernel from discarding messages.
After reaching the shell, look at the log:

```sh
journalctl -b
```

When reporting a bug, pipe that to a file and attach it to the bug report.

To check for possibly stuck jobs use:

```sh
systemctl list-jobs
```

The jobs that are listed as "running" are the ones that must complete before the "waiting" ones will be allowed to start executing.

# Diagnosing Shutdown Problems

Just like with boot problems, when you encounter a hang during shutting down,
make sure you wait _at least 5 minutes_ to distinguish a permanent hang from a broken service that's just timing out.
Then it's worth testing whether the system reacts to CTRL+ALT+DEL in any way.

If shutdown (whether it be to reboot or power-off) of your system gets stuck,
first test if the kernel itself is able to reboot or power-off the machine forcedly using one of these commands:

```sh
reboot -f
poweroff -f
```

If either one of the commands does not work, it's more likely to be a kernel, not systemd bug.

## Shutdown Completes Eventually

If normal reboot or poweroff work, but take a suspiciously long time, then

* boot with the debug options:

```sh
systemd.log_level=debug systemd.log_target=kmsg log_buf_len=1M printk.devkmsg=on enforcing=0
```

* save the following script as `/usr/lib/systemd/system-shutdown/debug.sh` and make it executable:

```sh
#!/bin/sh
mount -o remount,rw /
dmesg > /shutdown-log.txt
mount -o remount,ro /
```

* reboot

Look for timeouts logged in the resulting file `shutdown-log.txt` and/or attach it to a bugreport.

## Shutdown Never Finishes

If normal reboot or poweroff never finish even after waiting a few minutes,
the above method to create the shutdown log will not help and the log must be obtained using other methods.
Two options that are useful for debugging boot problems can be used also for shutdown problems:

* use a serial console
* use a debug shell - not only is it available from early boot, it also stays active until late shutdown.

# Status and Logs of Services

When the start of a service fails, systemctl will give you a generic error message:

```sh
# systemctl start foo.service
Job failed. See system journal and 'systemctl status' for details.
```

The service may have printed its own error message, but you do not see it,
because services run by systemd are not related to your login session and their outputs are not connected to your terminal.
That does not mean the output is lost though.
By default the stdout,
stderr of services are directed to the systemd _journal_ and the logs that services produce via `syslog(3)` go there too.
systemd also stores the exit code of failed services.
Let's check:

```sh
# systemctl status foo.service
foo.service - mmm service
Loaded: loaded (/etc/systemd/system/foo.service; static)
Active: failed (Result: exit-code) since Fri, 11 May 2012 20:26:23 +0200; 4s ago
Process: 1329 ExecStart=/usr/local/bin/foo (code=exited, status=1/FAILURE)
CGroup: name=systemd:/system/foo.service

May 11 20:26:23 scratch foo[1329]: Failed to parse config
```

In this example the service ran as a process with PID 1329 and exited with error code 1.
If you run systemctl status as root or as a user from the `adm` group,
you will get a few lines from the journal that the service wrote.
In the example the service produced just one error message.

To list the journal, use the `journalctl` command.

If you have a syslog service (such as rsyslog) running, the journal will also forward the messages to it,
so you'll find them in `/var/log/messages` (depending on rsyslog's configuration).

# Reporting systemd Bugs

Be prepared to include some information (logs) about your system as well.
These should be complete (no snippets please), not in an archive, uncompressed.

Please report bugs to your distribution's bug tracker first.
If you are sure that you are encountering an upstream bug, then first check
[for existing bug reports](https://github.com/systemd/systemd/issues/),
and if your issue is not listed
[file a new bug](https://github.com/systemd/systemd/issues/new).

## Information to Attach to a Bug Report

Whenever possible, the following should be mentioned and attached to your bug report:

* The exact kernel command-line used.
Typically from the bootloader configuration file (e.g. `/boot/grub2/grub.cfg`) or from `/proc/cmdline`
* The journal (the output of `journalctl -b > journal.txt`)
  * ideally after booting with `systemd.log_level=debug systemd.log_target=kmsg log_buf_len=1M printk.devkmsg=on`
* The output of a systemd dump: `systemd-analyze dump > systemd-dump.txt`
* The output of `/usr/lib/systemd/systemd --test --system --log-level=debug > systemd-test.txt 2>&1`
