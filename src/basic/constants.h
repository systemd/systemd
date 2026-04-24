/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "time-util.h"

#define DEFAULT_RESTART_USEC (100*USEC_PER_MSEC)

/* Many different things, but also system unit start/stop */
#define DEFAULT_TIMEOUT_USEC (DEFAULT_TIMEOUT_SEC*USEC_PER_SEC)
/* User unit start/stop */
#define DEFAULT_USER_TIMEOUT_USEC (DEFAULT_USER_TIMEOUT_SEC*USEC_PER_SEC)
/* Timeout for user confirmation on the console */
#define DEFAULT_CONFIRM_USEC (30*USEC_PER_SEC)

/* daemon-reload/-reexec is a multi-step pipeline (re-run every
 * generator, reload every unit, rebuild all jobs); align with the
 * device-timeout patience multiplier (6×) rather than the
 * fail-fast service multiplier (1×). */
#define DAEMON_RELOAD_TIMEOUT_SEC (DEFAULT_TIMEOUT_USEC * 6)

#define DEFAULT_START_LIMIT_INTERVAL (10*USEC_PER_SEC)
#define DEFAULT_START_LIMIT_BURST 5

/* The default time after which exit-on-idle services exit. This
 * should be kept lower than the watchdog timeout, because otherwise
 * the watchdog pings will keep the loop busy. */
#define DEFAULT_EXIT_USEC (30*USEC_PER_SEC)

/* The default value for the net.unix.max_dgram_qlen sysctl */
#define DEFAULT_UNIX_MAX_DGRAM_QLEN 512

#define SIGNALS_CRASH_HANDLER SIGSEGV,SIGILL,SIGFPE,SIGBUS,SIGQUIT,SIGABRT
#define SIGNALS_IGNORE SIGPIPE

#define NOTIFY_FD_MAX 768
#define NOTIFY_BUFFER_MAX PIPE_BUF

/* Return a nulstr for a standard cascade of configuration paths, suitable to pass to
 * conf_files_list_nulstr() to implement drop-in directories for extending configuration files. */
#define CONF_PATHS_NULSTR(n)                    \
        "/etc/" n "\0"                          \
        "/run/" n "\0"                          \
        "/usr/local/lib/" n "\0"                \
        "/usr/lib/" n "\0"

#define CONF_PATHS(n)                           \
        "/etc/" n,                              \
        "/run/" n,                              \
        "/usr/local/lib/" n,                    \
        "/usr/lib/" n

#define CONF_PATHS_STRV(n)                      \
        STRV_MAKE(CONF_PATHS(n))

/* The limit for PID 1 itself (which is not inherited to children) */
#define HIGH_RLIMIT_MEMLOCK (1024ULL*1024ULL*64ULL)

/* Since kernel 5.16 the kernel default limit was raised to 8M. Let's adjust things on old kernels too, and
 * in containers so that our children inherit that. */
#define DEFAULT_RLIMIT_MEMLOCK (1024ULL*1024ULL*8ULL)

/* Path where PID1 listens for varlink subscriptions from systemd-oomd to notify of changes in ManagedOOM settings. */
#define VARLINK_PATH_MANAGED_OOM_SYSTEM "/run/systemd/io.systemd.ManagedOOM"
/* Path where systemd-oomd listens for varlink connections from user managers to report changes in ManagedOOM settings. */
#define VARLINK_PATH_MANAGED_OOM_USER "/run/systemd/oom/io.systemd.ManagedOOM"
/* Path where systemd-machined listens to userdb varlink queries */
#define VARLINK_PATH_MACHINED_USERDB "/run/systemd/userdb/io.systemd.Machine"
/* Path where systemd-machined listens to resolve.hook varlink queries */
#define VARLINK_PATH_MACHINED_RESOLVE_HOOK "/run/systemd/resolve.hook/io.systemd.Machine"
/* Path where to connect to send varlink prekill events */
#define VARLINK_DIR_OOMD_PREKILL_HOOK "/run/systemd/oomd.prekill.hook/"

/* Recommended baseline - see README for details */
#define KERNEL_BASELINE_VERSION "5.14"
