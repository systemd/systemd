/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#  if defined(__has_feature)
#    if __has_feature(memory_sanitizer)
#      define HAS_FEATURE_MEMORY_SANITIZER 1
#    endif
#  endif
#  if !defined(HAS_FEATURE_MEMORY_SANITIZER)
#    define HAS_FEATURE_MEMORY_SANITIZER 0
#  endif
#endif

#if !defined(HAS_FEATURE_ADDRESS_SANITIZER)
#  ifdef __SANITIZE_ADDRESS__
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#  elif defined(__has_feature)
#    if __has_feature(address_sanitizer)
#      define HAS_FEATURE_ADDRESS_SANITIZER 1
#    endif
#  endif
#  if !defined(HAS_FEATURE_ADDRESS_SANITIZER)
#    define HAS_FEATURE_ADDRESS_SANITIZER 0
#  endif
#endif

#define DEFAULT_RESTART_USEC (100*USEC_PER_MSEC)

/* Many different things, but also system unit start/stop */
#define DEFAULT_TIMEOUT_USEC (DEFAULT_TIMEOUT_SEC*USEC_PER_SEC)
/* User unit start/stop */
#define DEFAULT_USER_TIMEOUT_USEC (DEFAULT_USER_TIMEOUT_SEC*USEC_PER_SEC)
/* Timeout for user confirmation on the console */
#define DEFAULT_CONFIRM_USEC (30*USEC_PER_SEC)

/* We use an extra-long timeout for the reload. This is because a reload or reexec means generators are rerun
 * which are timed out after DEFAULT_TIMEOUT_USEC. Let's use twice that time here, so that the generators can
 * have their timeout, and for everything else there's the same time budget in place. */
#define DAEMON_RELOAD_TIMEOUT_SEC (DEFAULT_TIMEOUT_USEC * 2)

#define DEFAULT_START_LIMIT_INTERVAL (10*USEC_PER_SEC)
#define DEFAULT_START_LIMIT_BURST 5

/* Wait for 1.5 seconds at maximum for freeze operation */
#define FREEZE_TIMEOUT (1500 * USEC_PER_MSEC)

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

#define CONF_PATHS_RUN_FIRST(n)                 \
        "/run/" n,                              \
        "/etc/" n,                              \
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
#define VARLINK_ADDR_PATH_MANAGED_OOM_SYSTEM "/run/systemd/io.systemd.ManagedOOM"
/* Path where systemd-oomd listens for varlink connections from user managers to report changes in ManagedOOM settings. */
#define VARLINK_ADDR_PATH_MANAGED_OOM_USER "/run/systemd/oom/io.systemd.ManagedOOM"

#define KERNEL_BASELINE_VERSION "4.15"
