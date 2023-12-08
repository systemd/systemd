/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sched.h>
#include <sys/mman.h>
#include <sys/prctl.h>
#include <unistd.h>

#include "argv-util.h"
#include "capability-util.h"
#include "errno-util.h"
#include "missing_sched.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "string-util.h"
#include "strv.h"

int saved_argc = 0;
char **saved_argv = NULL;

bool invoked_as(char *argv[], const char *token) {
        if (!argv || isempty(argv[0]))
                return false;

        if (isempty(token))
                return false;

        return strstr(last_path_component(argv[0]), token);
}

bool invoked_by_systemd(void) {
        int r;

        /* If the process is directly executed by PID1 (e.g. ExecStart= or generator), systemd-importd,
         * or systemd-homed, then $SYSTEMD_EXEC_PID= is set, and read the command line. */
        const char *e = getenv("SYSTEMD_EXEC_PID");
        if (!e)
                return false;

        if (streq(e, "*"))
                /* For testing. */
                return true;

        pid_t p;
        r = parse_pid(e, &p);
        if (r < 0) {
                /* We know that systemd sets the variable correctly. Something else must have set it. */
                log_debug_errno(r, "Failed to parse \"SYSTEMD_EXEC_PID=%s\", ignoring: %m", e);
                return false;
        }

        return getpid_cached() == p;
}

bool argv_looks_like_help(int argc, char **argv) {
        char **l;

        /* Scans the command line for indications the user asks for help. This is supposed to be called by
         * tools that do not implement getopt() style command line parsing because they are not primarily
         * user-facing. Detects four ways of asking for help:
         *
         * 1. Passing zero arguments
         * 2. Passing "help" as first argument
         * 3. Passing --help as any argument
         * 4. Passing -h as any argument
         */

        if (argc <= 1)
                return true;

        if (streq_ptr(argv[1], "help"))
                return true;

        l = strv_skip(argv, 1);

        return strv_contains(l, "--help") ||
                strv_contains(l, "-h");
}

static int update_argv(const char name[], size_t l) {
        static int can_do = -1;
        int r;

        assert(name);
        assert(l < SIZE_MAX);

        if (can_do == 0)
                return 0;
        can_do = false; /* We'll set it to true only if the whole process works */

        /* Calling prctl() with PR_SET_MM_ARG_{START,END} requires CAP_SYS_RESOURCE so let's use this as quick bypass
         * check, to avoid calling mmap() should PR_SET_MM_ARG_{START,END} fail with EPERM later on anyway. */
        r = have_effective_cap(CAP_SYS_RESOURCE);
        if (r < 0)
                return log_debug_errno(r, "Failed to check if we have enough privileges: %m");
        if (r == 0)
                return log_debug_errno(SYNTHETIC_ERRNO(EPERM),
                                       "Skipping PR_SET_MM, as we don't have privileges.");

        static size_t mm_size = 0;
        static char *mm = NULL;

        if (mm_size < l+1) {
                size_t nn_size;
                char *nn;

                nn_size = PAGE_ALIGN(l+1);
                if (nn_size >= SIZE_MAX)
                        return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "The requested argument is too long.");

                nn = mmap(NULL, nn_size, PROT_READ|PROT_WRITE, MAP_PRIVATE|MAP_ANONYMOUS, -1, 0);
                if (nn == MAP_FAILED)
                        return log_debug_errno(errno, "mmap() failed: %m");

                strncpy(nn, name, nn_size);

                /* Now, let's tell the kernel about this new memory */
                if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0) {
                        if (ERRNO_IS_PRIVILEGE(errno))
                                return log_debug_errno(errno, "PR_SET_MM_ARG_START failed: %m");

                        /* HACK: prctl() API is kind of dumb on this point.  The existing end address may already be
                         * below the desired start address, in which case the kernel may have kicked this back due
                         * to a range-check failure (see linux/kernel/sys.c:validate_prctl_map() to see this in
                         * action).  The proper solution would be to have a prctl() API that could set both start+end
                         * simultaneously, or at least let us query the existing address to anticipate this condition
                         * and respond accordingly.  For now, we can only guess at the cause of this failure and try
                         * a workaround--which will briefly expand the arg space to something potentially huge before
                         * resizing it to what we want. */
                        log_debug_errno(errno, "PR_SET_MM_ARG_START failed, attempting PR_SET_MM_ARG_END hack: %m");

                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) nn + l + 1, 0, 0) < 0) {
                                r = log_debug_errno(errno, "PR_SET_MM_ARG_END hack failed, proceeding without: %m");
                                (void) munmap(nn, nn_size);
                                return r;
                        }

                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_START, (unsigned long) nn, 0, 0) < 0)
                                return log_debug_errno(errno, "PR_SET_MM_ARG_START still failed, proceeding without: %m");
                } else {
                        /* And update the end pointer to the new end, too. If this fails, we don't really know what
                         * to do, it's pretty unlikely that we can rollback, hence we'll just accept the failure,
                         * and continue. */
                        if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) nn + l + 1, 0, 0) < 0)
                                log_debug_errno(errno, "PR_SET_MM_ARG_END failed, proceeding without: %m");
                }

                if (mm)
                        (void) munmap(mm, mm_size);

                mm = nn;
                mm_size = nn_size;
        } else {
                strncpy(mm, name, mm_size);

                /* Update the end pointer, continuing regardless of any failure. */
                if (prctl(PR_SET_MM, PR_SET_MM_ARG_END, (unsigned long) mm + l + 1, 0, 0) < 0)
                        log_debug_errno(errno, "PR_SET_MM_ARG_END failed, proceeding without: %m");
        }

        can_do = true;
        return 0;
}

int rename_process(const char name[]) {
        bool truncated = false;

        /* This is a like a poor man's setproctitle(). It changes the comm field, argv[0], and also the glibc's
         * internally used name of the process. For the first one a limit of 16 chars applies; to the second one in
         * many cases one of 10 (i.e. length of "/sbin/init") — however if we have CAP_SYS_RESOURCES it is unbounded;
         * to the third one 7 (i.e. the length of "systemd". If you pass a longer string it will likely be
         * truncated.
         *
         * Returns 0 if a name was set but truncated, > 0 if it was set but not truncated. */

        if (isempty(name))
                return -EINVAL; /* let's not confuse users unnecessarily with an empty name */

        if (!is_main_thread())
                return -EPERM; /* Let's not allow setting the process name from other threads than the main one, as we
                                * cache things without locking, and we make assumptions that PR_SET_NAME sets the
                                * process name that isn't correct on any other threads */

        size_t l = strlen(name);

        /* First step, change the comm field. The main thread's comm is identical to the process comm. This means we
         * can use PR_SET_NAME, which sets the thread name for the calling thread. */
        if (prctl(PR_SET_NAME, name) < 0)
                log_debug_errno(errno, "PR_SET_NAME failed: %m");
        if (l >= TASK_COMM_LEN) /* Linux userspace process names can be 15 chars at max */
                truncated = true;

        bool invocation_name_is_argv0 = false;

        /* Second step, change glibc's ID of the process name. */
        if (program_invocation_name) {
                invocation_name_is_argv0 = program_invocation_name == argv[0];

                size_t k = strlen(program_invocation_name);
                strncpy(program_invocation_name, name, k);
                if (l > k)
                        truncated = true;

                /* Also update the short name. */
                char *p = strrchr(program_invocation_name, '/');
                program_invocation_short_name = p ? p + 1 : program_invocation_name;
        }

        /* Third step, completely replace the argv[] array the kernel maintains for us. This requires privileges, but
         * has the advantage that the argv[] array is exactly what we want it to be, and not filled up with zeros at
         * the end. This is the best option for changing /proc/self/cmdline. */
        (void) update_argv(name, l);

        /* Fourth step: in all cases we'll also update the original argv[], so that our own code gets it right too if
         * it still looks here */
        if (saved_argc > 0) {
                if (!invocation_name_is_argv0 && saved_argv[0]) {
                        size_t k;

                        k = strlen(saved_argv[0]);
                        strncpy(saved_argv[0], name, k);
                        if (l > k)
                                truncated = true;
                }

                for (int i = 1; i < saved_argc; i++) {
                        if (!saved_argv[i])
                                break;

                        memzero(saved_argv[i], strlen(saved_argv[i]));
                }
        }

        return !truncated;
}
