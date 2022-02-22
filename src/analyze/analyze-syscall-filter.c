/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze-syscall-filter.h"
#include "analyze.h"
#include "fd-util.h"
#include "fileio.h"
#include "nulstr-util.h"
#include "seccomp-util.h"
#include "set.h"
#include "strv.h"
#include "terminal-util.h"

#if HAVE_SECCOMP

static int load_kernel_syscalls(Set **ret) {
        _cleanup_set_free_ Set *syscalls = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        /* Let's read the available system calls from the list of available tracing events. Slightly dirty,
         * but good enough for analysis purposes. */

        f = fopen("/sys/kernel/tracing/available_events", "re");
        if (!f) {
                /* We tried the non-debugfs mount point and that didn't work. If it wasn't mounted, maybe the
                 * old debugfs mount point works? */
                f = fopen("/sys/kernel/debug/tracing/available_events", "re");
                if (!f)
                        return log_full_errno(IN_SET(errno, EPERM, EACCES, ENOENT) ? LOG_DEBUG : LOG_WARNING, errno,
                                              "Can't read open tracefs' available_events file: %m");
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *e;

                r = read_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_error_errno(r, "Failed to read system call list: %m");
                if (r == 0)
                        break;

                e = startswith(line, "syscalls:sys_enter_");
                if (!e)
                        continue;

                /* These are named differently inside the kernel than their external name for historical
                 * reasons. Let's hide them here. */
                if (STR_IN_SET(e, "newuname", "newfstat", "newstat", "newlstat", "sysctl"))
                        continue;

                r = set_put_strdup(&syscalls, e);
                if (r < 0)
                        return log_error_errno(r, "Failed to add system call to list: %m");
        }

        *ret = TAKE_PTR(syscalls);
        return 0;
}

static void syscall_set_remove(Set *s, const SyscallFilterSet *set) {
        const char *syscall;

        if (!set)
                return;

        NULSTR_FOREACH(syscall, set->value) {
                if (syscall[0] == '@')
                        continue;

                free(set_remove(s, syscall));
        }
}

static void dump_syscall_filter(const SyscallFilterSet *set) {
        const char *syscall;

        printf("%s%s%s\n"
               "    # %s\n",
               ansi_highlight(),
               set->name,
               ansi_normal(),
               set->help);

        NULSTR_FOREACH(syscall, set->value)
                printf("    %s%s%s\n", syscall[0] == '@' ? ansi_underline() : "", syscall, ansi_normal());
}

int verb_syscall_filters(int argc, char *argv[], void *userdata) {
        bool first = true;

        pager_open(arg_pager_flags);

        if (strv_isempty(strv_skip(argv, 1))) {
                _cleanup_set_free_ Set *kernel = NULL, *known = NULL;
                const char *sys;
                int k = 0;  /* explicit initialization to appease gcc */

                NULSTR_FOREACH(sys, syscall_filter_sets[SYSCALL_FILTER_SET_KNOWN].value)
                        if (set_put_strdup(&known, sys) < 0)
                                return log_oom();

                if (!arg_quiet)
                        k = load_kernel_syscalls(&kernel);

                for (int i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                        const SyscallFilterSet *set = syscall_filter_sets + i;
                        if (!first)
                                puts("");

                        dump_syscall_filter(set);
                        syscall_set_remove(kernel, set);
                        if (i != SYSCALL_FILTER_SET_KNOWN)
                                syscall_set_remove(known, set);
                        first = false;
                }

                if (arg_quiet)  /* Let's not show the extra stuff in quiet mode */
                        return 0;

                if (!set_isempty(known)) {
                        _cleanup_free_ char **l = NULL;
                        char **syscall;

                        printf("\n"
                               "# %sUngrouped System Calls%s (known but not included in any of the groups except @known):\n",
                               ansi_highlight(), ansi_normal());

                        l = set_get_strv(known);
                        if (!l)
                                return log_oom();

                        strv_sort(l);

                        STRV_FOREACH(syscall, l)
                                printf("#   %s\n", *syscall);
                }

                if (k < 0) {
                        fputc('\n', stdout);
                        fflush(stdout);
                        if (!arg_quiet)
                                log_notice_errno(k, "# Not showing unlisted system calls, couldn't retrieve kernel system call list: %m");
                } else if (!set_isempty(kernel)) {
                        _cleanup_free_ char **l = NULL;
                        char **syscall;

                        printf("\n"
                               "# %sUnlisted System Calls%s (supported by the local kernel, but not included in any of the groups listed above):\n",
                               ansi_highlight(), ansi_normal());

                        l = set_get_strv(kernel);
                        if (!l)
                                return log_oom();

                        strv_sort(l);

                        STRV_FOREACH(syscall, l)
                                printf("#   %s\n", *syscall);
                }
        } else {
                char **name;

                STRV_FOREACH(name, strv_skip(argv, 1)) {
                        const SyscallFilterSet *set;

                        if (!first)
                                puts("");

                        set = syscall_filter_set_find(*name);
                        if (!set) {
                                /* make sure the error appears below normal output */
                                fflush(stdout);

                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                                       "Filter set \"%s\" not found.", *name);
                        }

                        dump_syscall_filter(set);
                        first = false;
                }
        }

        return 0;
}

#else
int verb_syscall_filters(int argc, char *argv[], void *userdata) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not compiled with syscall filters, sorry.");
}
#endif
