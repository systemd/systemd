/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "env-util.h"
#include "fd-util.h"
#include "initreq.h"
#include "install.h"
#include "io-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "strv.h"
#include "systemctl-sysv-compat.h"
#include "systemctl.h"

int talk_initctl(char rl) {
#if HAVE_SYSV_COMPAT
        _cleanup_close_ int fd = -1;
        const char *path;
        int r;

        /* Try to switch to the specified SysV runlevel. Returns == 0 if the operation does not apply on this
         * system, and > 0 on success. */

        if (rl == 0)
                return 0;

        FOREACH_STRING(_path, "/run/initctl", "/dev/initctl") {
                path = _path;

                fd = open(path, O_WRONLY|O_NONBLOCK|O_CLOEXEC|O_NOCTTY);
                if (fd < 0 && errno != ENOENT)
                        return log_error_errno(errno, "Failed to open %s: %m", path);
                if (fd >= 0)
                        break;
        }
        if (fd < 0)
                return 0;

        struct init_request request = {
                .magic = INIT_MAGIC,
                .sleeptime = 0,
                .cmd = INIT_CMD_RUNLVL,
                .runlevel = rl,
        };

        r = loop_write(fd, &request, sizeof(request), false);
        if (r < 0)
                return log_error_errno(r, "Failed to write to %s: %m", path);

        return 1;
#else
        return -EOPNOTSUPP;
#endif
}

int parse_shutdown_time_spec(const char *t, usec_t *ret) {
        assert(t);
        assert(ret);

        if (streq(t, "now"))
                *ret = 0;
        else if (!strchr(t, ':')) {
                uint64_t u;

                if (safe_atou64(t, &u) < 0)
                        return -EINVAL;

                *ret = now(CLOCK_REALTIME) + USEC_PER_MINUTE * u;
        } else {
                char *e = NULL;
                long hour, minute;
                struct tm tm = {};
                time_t s;
                usec_t n;

                errno = 0;
                hour = strtol(t, &e, 10);
                if (errno > 0 || *e != ':' || hour < 0 || hour > 23)
                        return -EINVAL;

                minute = strtol(e+1, &e, 10);
                if (errno > 0 || *e != 0 || minute < 0 || minute > 59)
                        return -EINVAL;

                n = now(CLOCK_REALTIME);
                s = (time_t) (n / USEC_PER_SEC);

                assert_se(localtime_r(&s, &tm));

                tm.tm_hour = (int) hour;
                tm.tm_min = (int) minute;
                tm.tm_sec = 0;

                s = mktime(&tm);
                assert(s >= 0);

                *ret = (usec_t) s * USEC_PER_SEC;

                while (*ret <= n)
                        *ret += USEC_PER_DAY;
        }

        return 0;
}

int enable_sysv_units(const char *verb, char **args) {
        int r = 0;

#if HAVE_SYSV_COMPAT
        _cleanup_(lookup_paths_free) LookupPaths paths = {};
        unsigned f = 0;

        /* Processes all SysV units, and reshuffles the array so that afterwards only the native units remain */

        if (arg_scope != LOOKUP_SCOPE_SYSTEM)
                return 0;

        if (getenv_bool("SYSTEMCTL_SKIP_SYSV") > 0)
                return 0;

        if (!STR_IN_SET(verb,
                        "enable",
                        "disable",
                        "is-enabled"))
                return 0;

        r = lookup_paths_init_or_warn(&paths, arg_scope, LOOKUP_PATHS_EXCLUDE_GENERATED, arg_root);
        if (r < 0)
                return r;

        r = 0;
        while (args[f]) {

                const char *argv[] = {
                        ROOTLIBEXECDIR "/systemd-sysv-install",
                        NULL, /* --root= */
                        NULL, /* verb */
                        NULL, /* service */
                        NULL,
                };

                _cleanup_free_ char *p = NULL, *q = NULL, *l = NULL, *v = NULL;
                bool found_native = false, found_sysv;
                const char *name;
                unsigned c = 1;
                pid_t pid;
                int j;

                name = args[f++];

                if (!endswith(name, ".service"))
                        continue;

                if (path_is_absolute(name))
                        continue;

                j = unit_file_exists(arg_scope, &paths, name);
                if (j < 0 && !IN_SET(j, -ELOOP, -ERFKILL, -EADDRNOTAVAIL))
                        return log_error_errno(j, "Failed to look up unit file state: %m");
                found_native = j != 0;

                /* If we have both a native unit and a SysV script, enable/disable them both (below); for
                 * is-enabled, prefer the native unit */
                if (found_native && streq(verb, "is-enabled"))
                        continue;

                p = path_join(arg_root, SYSTEM_SYSVINIT_PATH, name);
                if (!p)
                        return log_oom();

                p[strlen(p) - STRLEN(".service")] = 0;
                found_sysv = access(p, F_OK) >= 0;
                if (!found_sysv)
                        continue;

                if (!arg_quiet) {
                        if (found_native)
                                log_info("Synchronizing state of %s with SysV service script with %s.", name, argv[0]);
                        else
                                log_info("%s is not a native service, redirecting to systemd-sysv-install.", name);
                }

                if (!isempty(arg_root)) {
                        q = strjoin("--root=", arg_root);
                        if (!q)
                                return log_oom();

                        argv[c++] = q;
                }

                /* Let's copy the verb, since it's still pointing directly into the original argv[] array we
                 * got passed, but safe_fork() is likely going to rewrite that for the new child */
                v = strdup(verb);
                if (!v)
                        return log_oom();

                argv[c++] = v;
                argv[c++] = basename(p);
                argv[c] = NULL;

                l = strv_join((char**)argv, " ");
                if (!l)
                        return log_oom();

                if (!arg_quiet)
                        log_info("Executing: %s", l);

                j = safe_fork("(sysv-install)", FORK_RESET_SIGNALS|FORK_DEATHSIG|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
                if (j < 0)
                        return j;
                if (j == 0) {
                        /* Child */
                        execv(argv[0], (char**) argv);
                        log_error_errno(errno, "Failed to execute %s: %m", argv[0]);
                        _exit(EXIT_FAILURE);
                }

                j = wait_for_terminate_and_check("sysv-install", pid, WAIT_LOG_ABNORMAL);
                if (j < 0)
                        return j;
                if (streq(verb, "is-enabled")) {
                        if (j == EXIT_SUCCESS) {
                                if (!arg_quiet)
                                        puts("enabled");
                                r = 1;
                        } else {
                                if (!arg_quiet)
                                        puts("disabled");
                        }

                } else if (j != EXIT_SUCCESS)
                        return -EBADE; /* We don't warn here, under the assumption the script already showed an explanation */

                if (found_native)
                        continue;

                /* Remove this entry, so that we don't try enabling it as native unit */
                assert(f > 0);
                f--;
                assert(args[f] == name);
                strv_remove(args + f, name);
        }

#endif
        return r;
}

int action_to_runlevel(void) {
#if HAVE_SYSV_COMPAT
        static const char table[_ACTION_MAX] = {
                [ACTION_HALT] =      '0',
                [ACTION_POWEROFF] =  '0',
                [ACTION_REBOOT] =    '6',
                [ACTION_RUNLEVEL2] = '2',
                [ACTION_RUNLEVEL3] = '3',
                [ACTION_RUNLEVEL4] = '4',
                [ACTION_RUNLEVEL5] = '5',
                [ACTION_RESCUE] =    '1'
        };

        assert(arg_action >= 0 && arg_action < _ACTION_MAX);
        return table[arg_action];
#else
        return -EOPNOTSUPP;
#endif
}
