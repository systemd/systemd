/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#define SPECIAL_DEFAULT_TARGET "default.target"

/* Shutdown targets */
#define SPECIAL_UMOUNT_TARGET "umount.target"
/* This is not really intended to be started by directly. This is
 * mostly so that other targets (reboot/halt/poweroff) can depend on
 * it to bring all services down that want to be brought down on
 * system shutdown. */
#define SPECIAL_SHUTDOWN_TARGET "shutdown.target"
#define SPECIAL_HALT_TARGET "halt.target"
#define SPECIAL_POWEROFF_TARGET "poweroff.target"
#define SPECIAL_REBOOT_TARGET "reboot.target"
#define SPECIAL_KEXEC_TARGET "kexec.target"
#define SPECIAL_EXIT_TARGET "exit.target"
#define SPECIAL_SUSPEND_TARGET "suspend.target"
#define SPECIAL_HIBERNATE_TARGET "hibernate.target"
#define SPECIAL_HYBRID_SLEEP_TARGET "hybrid-sleep.target"
#define SPECIAL_SUSPEND_THEN_HIBERNATE_TARGET "suspend-then-hibernate.target"

/* Special boot targets */
#define SPECIAL_RESCUE_TARGET "rescue.target"
#define SPECIAL_EMERGENCY_TARGET "emergency.target"
#define SPECIAL_MULTI_USER_TARGET "multi-user.target"
#define SPECIAL_GRAPHICAL_TARGET "graphical.target"

/* Early boot targets */
#define SPECIAL_SYSINIT_TARGET "sysinit.target"
#define SPECIAL_SOCKETS_TARGET "sockets.target"
#define SPECIAL_TIMERS_TARGET "timers.target"
#define SPECIAL_PATHS_TARGET "paths.target"
#define SPECIAL_LOCAL_FS_TARGET "local-fs.target"
#define SPECIAL_LOCAL_FS_PRE_TARGET "local-fs-pre.target"
#define SPECIAL_INITRD_FS_TARGET "initrd-fs.target"
#define SPECIAL_INITRD_ROOT_DEVICE_TARGET "initrd-root-device.target"
#define SPECIAL_INITRD_ROOT_FS_TARGET "initrd-root-fs.target"
#define SPECIAL_REMOTE_FS_TARGET "remote-fs.target"       /* LSB's $remote_fs */
#define SPECIAL_REMOTE_FS_PRE_TARGET "remote-fs-pre.target"
#define SPECIAL_SWAP_TARGET "swap.target"
#define SPECIAL_NETWORK_ONLINE_TARGET "network-online.target"
#define SPECIAL_TIME_SYNC_TARGET "time-sync.target"       /* LSB's $time */
#define SPECIAL_BASIC_TARGET "basic.target"

/* LSB compatibility */
#define SPECIAL_NETWORK_TARGET "network.target"           /* LSB's $network */
#define SPECIAL_NSS_LOOKUP_TARGET "nss-lookup.target"     /* LSB's $named */
#define SPECIAL_RPCBIND_TARGET "rpcbind.target"           /* LSB's $portmap */

/*
 * Rules regarding adding further high level targets like the above:
 *
 * - Be conservative, only add more of these when we really need
 *   them. We need strong usecases for further additions.
 *
 * - When there can be multiple implementations running side-by-side,
 *   it needs to be a .target unit which can pull in all
 *   implementations.
 *
 * - If something can be implemented with socket activation, and
 *   without, it needs to be a .target unit, so that it can pull in
 *   the appropriate unit.
 *
 * - Otherwise, it should be a .service unit.
 *
 * - In some cases it is OK to have both a .service and a .target
 *   unit, i.e. if there can be multiple parallel implementations, but
 *   only one is the "system" one. Example: syslog.
 *
 * Or to put this in other words: .service symlinks can be used to
 * arbitrate between multiple implementations if there can be only one
 * of a kind. .target units can be used to support multiple
 * implementations that can run side-by-side.
 */

/* Magic early boot services */
#define SPECIAL_FSCK_SERVICE "systemd-fsck@.service"
#define SPECIAL_QUOTACHECK_SERVICE "systemd-quotacheck.service"
#define SPECIAL_QUOTAON_SERVICE "quotaon.service"
#define SPECIAL_REMOUNT_FS_SERVICE "systemd-remount-fs.service"

/* Services systemd relies on */
#define SPECIAL_DBUS_SERVICE "dbus.service"
#define SPECIAL_DBUS_SOCKET "dbus.socket"
#define SPECIAL_JOURNALD_SOCKET "systemd-journald.socket"
#define SPECIAL_JOURNALD_SERVICE "systemd-journald.service"
#define SPECIAL_TMPFILES_SETUP_SERVICE "systemd-tmpfiles-setup.service"

/* Magic init signals */
#define SPECIAL_KBREQUEST_TARGET "kbrequest.target"
#define SPECIAL_SIGPWR_TARGET "sigpwr.target"
#define SPECIAL_CTRL_ALT_DEL_TARGET "ctrl-alt-del.target"

/* Where we add all our system units, users and machines by default */
#define SPECIAL_SYSTEM_SLICE "system.slice"
#define SPECIAL_USER_SLICE "user.slice"
#define SPECIAL_MACHINE_SLICE "machine.slice"
#define SPECIAL_ROOT_SLICE "-.slice"

/* The scope unit systemd itself lives in. */
#define SPECIAL_INIT_SCOPE "init.scope"

/* The root directory. */
#define SPECIAL_ROOT_MOUNT "-.mount"
