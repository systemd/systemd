/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <stdlib.h>
#include <unistd.h>

#include "env-util.h"
#include "install.h"
#include "log.h"
#include "path-lookup.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"
#include "systemctl.h"
#include "systemctl-sysv-compat.h"

int enable_sysv_units(const char *verb, char **args) {
        int r = 0;

#if HAVE_SYSV_COMPAT
        _cleanup_(lookup_paths_done) LookupPaths paths = {};
        unsigned f = 0;
        SysVUnitEnableState enable_state = SYSV_UNIT_NOT_FOUND;

        /* Processes all SysV units, and reshuffles the array so that afterwards only the native units remain */

        if (arg_runtime_scope != RUNTIME_SCOPE_SYSTEM)
                return 0;

        if (getenv_bool("SYSTEMCTL_SKIP_SYSV") > 0)
                return 0;

        if (!STR_IN_SET(verb,
                        "enable",
                        "disable",
                        "is-enabled"))
                return 0;

        r = lookup_paths_init_or_warn(&paths, arg_runtime_scope, LOOKUP_PATHS_EXCLUDE_GENERATED, arg_root);
        if (r < 0)
                return r;

        r = 0;
        while (args[f]) {

                const char *argv[] = {
                        LIBEXECDIR "/systemd-sysv-install",
                        NULL, /* --root= */
                        NULL, /* verb */
                        NULL, /* service */
                        NULL,
                };

                _cleanup_free_ char *p = NULL, *q = NULL, *l = NULL, *v = NULL, *b = NULL;
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

                j = unit_file_exists(arg_runtime_scope, &paths, name);
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

                j = path_extract_filename(p, &b);
                if (j < 0)
                        return log_error_errno(j, "Failed to extract file name from '%s': %m", p);

                argv[c++] = v;
                argv[c++] = b;
                argv[c] = NULL;

                l = strv_join((char**)argv, " ");
                if (!l)
                        return log_oom();

                if (!arg_quiet)
                        log_info("Executing: %s", l);

                j = safe_fork("(sysv-install)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
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
                                enable_state = SYSV_UNIT_ENABLED;
                        } else {
                                if (!arg_quiet)
                                        puts("disabled");
                                if (enable_state != SYSV_UNIT_ENABLED)
                                        enable_state = SYSV_UNIT_DISABLED;
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

        if (streq(verb, "is-enabled"))
                return enable_state;
#endif
        return r;
}
