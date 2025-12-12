/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-syscall-filter.h"
#include "ansi-color.h"
#include "fd-util.h"
#include "fileio.h"
#include "log.h"
#include "nulstr-util.h"
#include "pager.h"
#include "seccomp-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"

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

static int syscall_set_add(Set **s, const SyscallFilterSet *set) {
        int r;

        assert(s);

        if (!set)
                return 0;

        NULSTR_FOREACH(sc, set->value) {
                if (sc[0] == '@')
                        continue;

                r = set_put_strdup(s, sc);
                if (r < 0)
                        return r;
        }

        return 0;
}

static void syscall_set_remove(Set *s, const SyscallFilterSet *set) {
        if (!set)
                return;

        NULSTR_FOREACH(sc, set->value) {
                if (sc[0] == '@')
                        continue;

                free(set_remove(s, sc));
        }
}

static void dump_syscall_filter(const SyscallFilterSet *set) {
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
        int r;

        pager_open(arg_pager_flags);

        char **args = strv_skip(argv, 1);
        if (args)
                STRV_FOREACH(name, args) {
                        const SyscallFilterSet *set;

                        if (name != args)
                                puts("");

                        set = syscall_filter_set_find(*name);
                        if (!set) {
                                /* make sure the error appears below normal output */
                                fflush(stdout);

                                return log_error_errno(SYNTHETIC_ERRNO(ENOENT),
                                                       "Filter set \"%s\" not found.", *name);
                        }

                        dump_syscall_filter(set);
                }
        else {
                _cleanup_set_free_ Set *kernel = NULL, *known = NULL;
                int k = 0;  /* explicit initialization to appease gcc */

                r = syscall_set_add(&known, syscall_filter_sets + SYSCALL_FILTER_SET_KNOWN);
                if (r < 0)
                        return log_error_errno(r, "Failed to prepare set of known system calls: %m");

                if (!arg_quiet)
                        k = load_kernel_syscalls(&kernel);

                for (int i = 0; i < _SYSCALL_FILTER_SET_MAX; i++) {
                        const SyscallFilterSet *set = syscall_filter_sets + i;
                        if (i > 0)
                                puts("");

                        dump_syscall_filter(set);
                        syscall_set_remove(kernel, set);
                        if (i != SYSCALL_FILTER_SET_KNOWN)
                                syscall_set_remove(known, set);
                }

                if (arg_quiet)  /* Let's not show the extra stuff in quiet mode */
                        return 0;

                if (!set_isempty(known)) {
                        printf("\n"
                               "# %sUngrouped System Calls%s (known but not included in any of the groups except @known):\n",
                               ansi_highlight(), ansi_normal());

                        _cleanup_free_ char **l = set_get_strv(known);
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
                        printf("\n"
                               "# %sUnlisted System Calls%s (supported by the local kernel, but not included in any of the groups listed above):\n",
                               ansi_highlight(), ansi_normal());

                        _cleanup_free_ char **l = set_get_strv(kernel);
                        if (!l)
                                return log_oom();

                        strv_sort(l);

                        STRV_FOREACH(syscall, l)
                                printf("#   %s\n", *syscall);
                }
        }

        return EXIT_SUCCESS;
}

#else
int verb_syscall_filters(int argc, char *argv[], void *userdata) {
        return log_error_errno(SYNTHETIC_ERRNO(EOPNOTSUPP), "Not compiled with syscall filters, sorry.");
}
#endif
