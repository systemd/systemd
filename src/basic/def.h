/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "util.h"

#define DEFAULT_TIMEOUT_USEC (90*USEC_PER_SEC)
#define DEFAULT_RESTART_USEC (100*USEC_PER_MSEC)
#define DEFAULT_CONFIRM_USEC (30*USEC_PER_SEC)

#define DEFAULT_START_LIMIT_INTERVAL (10*USEC_PER_SEC)
#define DEFAULT_START_LIMIT_BURST 5

/* The default time after which exit-on-idle services exit. This
 * should be kept lower than the watchdog timeout, because otherwise
 * the watchdog pings will keep the loop busy. */
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

#define SYSTEMD_CGROUP_CONTROLLER "name=systemd"

#define SIGNALS_CRASH_HANDLER SIGSEGV,SIGILL,SIGFPE,SIGBUS,SIGQUIT,SIGABRT
#define SIGNALS_IGNORE SIGPIPE

#define DIGITS            "0123456789"
#define LOWERCASE_LETTERS "abcdefghijklmnopqrstuvwxyz"
#define UPPERCASE_LETTERS "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
#define LETTERS LOWERCASE_LETTERS UPPERCASE_LETTERS
#define ALPHANUMERICAL LETTERS DIGITS

#define REBOOT_PARAM_FILE "/run/systemd/reboot-param"

#ifdef HAVE_SPLIT_USR
#define KBD_KEYMAP_DIRS                         \
        "/usr/share/keymaps/\0"                 \
        "/usr/share/kbd/keymaps/\0"             \
        "/usr/lib/kbd/keymaps/\0"               \
        "/lib/kbd/keymaps/\0"
#else
#define KBD_KEYMAP_DIRS                         \
        "/usr/share/keymaps/\0"                 \
        "/usr/share/kbd/keymaps/\0"             \
        "/usr/lib/kbd/keymaps/\0"
#endif

#define UNIX_SYSTEM_BUS_ADDRESS "unix:path=/var/run/dbus/system_bus_socket"
#define KERNEL_SYSTEM_BUS_ADDRESS "kernel:path=/sys/fs/kdbus/0-system/bus"
#define DEFAULT_SYSTEM_BUS_ADDRESS KERNEL_SYSTEM_BUS_ADDRESS ";" UNIX_SYSTEM_BUS_ADDRESS
#define UNIX_USER_BUS_ADDRESS_FMT "unix:path=%s/bus"
#define KERNEL_USER_BUS_ADDRESS_FMT "kernel:path=/sys/fs/kdbus/"UID_FMT"-user/bus"

#define PLYMOUTH_SOCKET {                                       \
                .un.sun_family = AF_UNIX,                       \
                .un.sun_path = "\0/org/freedesktop/plymouthd",  \
        }

#ifndef TTY_GID
#define TTY_GID 5
#endif

#define NOTIFY_FD_MAX 768
#define NOTIFY_BUFFER_MAX PIPE_BUF
