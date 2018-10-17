/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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

/* The default value for the net.unix.max_dgram_qlen sysctl */
#define DEFAULT_UNIX_MAX_DGRAM_QLEN 512UL

#define SIGNALS_CRASH_HANDLER SIGSEGV,SIGILL,SIGFPE,SIGBUS,SIGQUIT,SIGABRT
#define SIGNALS_IGNORE SIGPIPE

#if HAVE_SPLIT_USR
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

/* Note that we use the new /run prefix here (instead of /var/run) since we require them to be aliases and that way we
 * become independent of /var being mounted */
#define DEFAULT_SYSTEM_BUS_ADDRESS "unix:path=/run/dbus/system_bus_socket"
#define DEFAULT_USER_BUS_ADDRESS_FMT "unix:path=%s/bus"

#define PLYMOUTH_SOCKET {                                       \
                .un.sun_family = AF_UNIX,                       \
                .un.sun_path = "\0/org/freedesktop/plymouthd",  \
        }

#define NOTIFY_FD_MAX 768
#define NOTIFY_BUFFER_MAX PIPE_BUF

#if HAVE_SPLIT_USR
#  define _CONF_PATHS_SPLIT_USR_NULSTR(n) "/lib/" n "\0"
#  define _CONF_PATHS_SPLIT_USR(n) , "/lib/" n
#else
#  define _CONF_PATHS_SPLIT_USR_NULSTR(n)
#  define _CONF_PATHS_SPLIT_USR(n)
#endif

/* Return a nulstr for a standard cascade of configuration paths,
 * suitable to pass to conf_files_list_nulstr() or config_parse_many_nulstr()
 * to implement drop-in directories for extending configuration
 * files. */
#define CONF_PATHS_NULSTR(n)                    \
        "/etc/" n "\0"                          \
        "/run/" n "\0"                          \
        "/usr/local/lib/" n "\0"                \
        "/usr/lib/" n "\0"                      \
        _CONF_PATHS_SPLIT_USR_NULSTR(n)

#define CONF_PATHS_STRV(n)                      \
        STRV_MAKE(                              \
                "/etc/" n,                      \
                "/run/" n,                      \
                "/usr/local/lib/" n,            \
                "/usr/lib/" n                   \
                _CONF_PATHS_SPLIT_USR(n))

#define LONG_LINE_MAX (1U*1024U*1024U)

#define HIGH_RLIMIT_MEMLOCK (1024ULL*1024ULL*64ULL)
