/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sd-login.h"

#include "copy.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "pager.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"

static pid_t pager_pid = 0;

static int stored_stdout = -1;
static int stored_stderr = -1;
static bool stdout_redirected = false;
static bool stderr_redirected = false;

_noreturn_ static void pager_fallback(void) {
        int r;

        r = copy_bytes(STDIN_FILENO, STDOUT_FILENO, UINT64_MAX, 0);
        if (r < 0) {
                log_error_errno(r, "Internal pager failed: %m");
                _exit(EXIT_FAILURE);
        }

        _exit(EXIT_SUCCESS);
}

static int no_quit_on_interrupt(int exe_name_fd, const char *less_opts) {
        _cleanup_fclose_ FILE *file = NULL;
        _cleanup_free_ char *line = NULL;
        int r;

        assert(exe_name_fd >= 0);
        assert(less_opts);

        /* This takes ownership of exe_name_fd */
        file = fdopen(exe_name_fd, "r");
        if (!file) {
                safe_close(exe_name_fd);
                return log_error_errno(errno, "Failed to create FILE object: %m");
        }

        /* Find the last line */
        for (;;) {
                _cleanup_free_ char *t = NULL;

                r = read_line(file, LONG_LINE_MAX, &t);
                if (r < 0)
                        return log_error_errno(r, "Failed to read from socket: %m");
                if (r == 0)
                        break;

                free_and_replace(line, t);
        }

        /* We only treat "less" specially.
         * Return true whenever option K is *not* set. */
        r = streq_ptr(line, "less") && !strchr(less_opts, 'K');

        log_debug("Pager executable is \"%s\", options \"%s\", quit_on_interrupt: %s",
                  strnull(line), less_opts, yes_no(!r));
        return r;
}

static bool running_with_escalated_privileges(void) {
        int r;

        if (getenv("SUDO_UID"))
                return true;

        uid_t uid;
        r = sd_pid_get_owner_uid(0, &uid);
        if (r < 0) {
                log_debug_errno(r, "sd_pid_get_owner_uid() failed, enabling pager secure mode: %m");
                return true;
        }

        return uid != geteuid();
}

void pager_open(PagerFlags flags) {
        _cleanup_close_pair_ int fd[2] = EBADF_PAIR, exe_name_pipe[2] = EBADF_PAIR;
        _cleanup_strv_free_ char **pager_args = NULL;
        _cleanup_free_ char *l = NULL;
        const char *pager, *less_opts;
        int r;

        if (flags & PAGER_DISABLE)
                return;

        if (pager_pid > 0)
                return;

        if (terminal_is_dumb())
                return;

        if (!is_main_thread())
                return (void) log_error_errno(SYNTHETIC_ERRNO(EPERM), "Pager invoked from wrong thread.");

        pager = getenv("SYSTEMD_PAGER");
        if (!pager)
                pager = getenv("PAGER");

        if (pager) {
                pager_args = strv_split(pager, WHITESPACE);
                if (!pager_args)
                        return (void) log_oom();

                /* If the pager is explicitly turned off, honour it */
                if (strv_isempty(pager_args) || strv_equal(pager_args, STRV_MAKE("cat")))
                        return;
        }

        /* Determine and cache number of columns/lines before we spawn the pager so that we get the value from the
         * actual tty */
        (void) columns();
        (void) lines();

        if (pipe2(fd, O_CLOEXEC) < 0)
                return (void) log_error_errno(errno, "Failed to create pager pipe: %m");

        /* This is a pipe to feed the name of the executed pager binary into the parent */
        if (pipe2(exe_name_pipe, O_CLOEXEC) < 0)
                return (void) log_error_errno(errno, "Failed to create exe_name pipe: %m");

        /* Initialize a good set of less options */
        less_opts = getenv("SYSTEMD_LESS");
        if (!less_opts)
                less_opts = "FRSXMK";
        if (flags & PAGER_JUMP_TO_END) {
                l = strjoin(less_opts, " +G");
                if (!l)
                        return (void) log_oom();
                less_opts = l;
        }

        /* We set SIGINT as PR_DEATHSIG signal here, to match the "K" parameter we set in $LESS, which enables SIGINT behaviour. */
        r = safe_fork("(pager)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGINT|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pager_pid);
        if (r < 0)
                return;
        if (r == 0) {
                const char *less_charset;

                /* In the child start the pager */

                if (dup2(fd[0], STDIN_FILENO) < 0) {
                        log_error_errno(errno, "Failed to duplicate file descriptor to STDIN: %m");
                        _exit(EXIT_FAILURE);
                }

                safe_close_pair(fd);

                if (setenv("LESS", less_opts, 1) < 0) {
                        log_error_errno(errno, "Failed to set environment variable LESS: %m");
                        _exit(EXIT_FAILURE);
                }

                /* Initialize a good charset for less. This is particularly important if we output UTF-8
                 * characters. */
                less_charset = getenv("SYSTEMD_LESSCHARSET");
                if (!less_charset && is_locale_utf8())
                        less_charset = "utf-8";
                if (less_charset &&
                    setenv("LESSCHARSET", less_charset, 1) < 0) {
                        log_error_errno(errno, "Failed to set environment variable LESSCHARSET: %m");
                        _exit(EXIT_FAILURE);
                }

                /* People might invoke us from sudo, don't needlessly allow less to be a way to shell out
                 * privileged stuff. If the user set $SYSTEMD_PAGERSECURE, trust their configuration of the
                 * pager. If they didn't, use secure mode when under euid is changed. If $SYSTEMD_PAGERSECURE
                 * wasn't explicitly set, and we autodetect the need for secure mode, only use the pager we
                 * know to be good. */
                int use_secure_mode = secure_getenv_bool("SYSTEMD_PAGERSECURE");
                bool trust_pager = use_secure_mode >= 0;
                if (use_secure_mode == -ENXIO)
                        use_secure_mode = running_with_escalated_privileges();
                else if (use_secure_mode < 0) {
                        log_warning_errno(use_secure_mode, "Unable to parse $SYSTEMD_PAGERSECURE, assuming true: %m");
                        use_secure_mode = true;
                }

                /* We generally always set variables used by less, even if we end up using a different pager.
                 * They shouldn't hurt in any case, and ideally other pagers would look at them too. */
                r = set_unset_env("LESSSECURE", use_secure_mode ? "1" : NULL, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to adjust environment variable LESSSECURE: %m");
                        _exit(EXIT_FAILURE);
                }

                if (trust_pager && pager_args) { /* The pager config might be set globally, and we cannot
                                                  * know if the user adjusted it to be appropriate for the
                                                  * secure mode. Thus, start the pager specified through
                                                  * envvars only when $SYSTEMD_PAGERSECURE was explicitly set
                                                  * as well. */
                        r = loop_write(exe_name_pipe[1], pager_args[0], strlen(pager_args[0]) + 1);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write pager name to socket: %m");
                                _exit(EXIT_FAILURE);
                        }

                        execvp(pager_args[0], pager_args);
                        log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                       "Failed to execute '%s', using fallback pagers: %m", pager_args[0]);
                }

                /* Debian's alternatives command for pagers is called 'pager'. Note that we do not call
                 * sensible-pagers here, since that is just a shell script that implements a logic that is
                 * similar to this one anyway, but is Debian-specific. */
                static const char* pagers[] = { "pager", "less", "more", "(built-in)" };

                for (unsigned i = 0; i < ELEMENTSOF(pagers); i++) {
                        /* Only less (and our trivial fallback) implement secure mode right now. */
                        if (use_secure_mode && !STR_IN_SET(pagers[i], "less", "(built-in)"))
                                continue;

                        r = loop_write(exe_name_pipe[1], pagers[i], strlen(pagers[i]) + 1);
                        if (r < 0) {
                                log_error_errno(r, "Failed to write pager name to socket: %m");
                                _exit(EXIT_FAILURE);
                        }

                        if (i < ELEMENTSOF(pagers) - 1) {
                                execlp(pagers[i], pagers[i], NULL);
                                log_full_errno(errno == ENOENT ? LOG_DEBUG : LOG_WARNING, errno,
                                               "Failed to execute '%s', will try '%s' next: %m", pagers[i], pagers[i+1]);
                        } else {
                                /* Close pipe to signal the parent to start sending data */
                                safe_close_pair(exe_name_pipe);
                                pager_fallback();
                                assert_not_reached();
                        }
                }
        }

        /* Return in the parent */
        stored_stdout = fcntl(STDOUT_FILENO, F_DUPFD_CLOEXEC, 3);
        if (dup2(fd[1], STDOUT_FILENO) < 0) {
                stored_stdout = safe_close(stored_stdout);
                return (void) log_error_errno(errno, "Failed to duplicate pager pipe: %m");
        }
        stdout_redirected = true;

        stored_stderr = fcntl(STDERR_FILENO, F_DUPFD_CLOEXEC, 3);
        if (dup2(fd[1], STDERR_FILENO) < 0) {
                stored_stderr = safe_close(stored_stderr);
                return (void) log_error_errno(errno, "Failed to duplicate pager pipe: %m");
        }
        stderr_redirected = true;

        exe_name_pipe[1] = safe_close(exe_name_pipe[1]);

        r = no_quit_on_interrupt(TAKE_FD(exe_name_pipe[0]), less_opts);
        if (r > 0)
                (void) ignore_signals(SIGINT);
}

void pager_close(void) {

        if (pager_pid <= 0)
                return;

        /* Inform pager that we are done */
        (void) fflush(stdout);
        if (stdout_redirected)
                if (stored_stdout < 0 || dup2(stored_stdout, STDOUT_FILENO) < 0)
                        (void) close(STDOUT_FILENO);
        stored_stdout = safe_close(stored_stdout);
        (void) fflush(stderr);
        if (stderr_redirected)
                if (stored_stderr < 0 || dup2(stored_stderr, STDERR_FILENO) < 0)
                        (void) close(STDERR_FILENO);
        stored_stderr = safe_close(stored_stderr);
        stdout_redirected = stderr_redirected = false;

        (void) kill(pager_pid, SIGCONT);
        (void) wait_for_terminate(TAKE_PID(pager_pid), NULL);
        pager_pid = 0;
}

bool pager_have(void) {
        return pager_pid > 0;
}

int show_man_page(const char *desc, bool null_stdio) {
        const char *args[4] = { "man", NULL, NULL, NULL };
        char *e = NULL;
        pid_t pid;
        size_t k;
        int r;

        k = strlen(desc);

        if (desc[k-1] == ')')
                e = strrchr(desc, '(');

        if (e) {
                char *page = NULL, *section = NULL;

                page = strndupa_safe(desc, e - desc);
                section = strndupa_safe(e + 1, desc + k - e - 2);

                args[1] = section;
                args[2] = page;
        } else
                args[1] = desc;

        r = safe_fork("(man)", FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGTERM|(null_stdio ? FORK_REARRANGE_STDIO : 0)|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                /* Child */
                execvp(args[0], (char**) args);
                log_error_errno(errno, "Failed to execute man: %m");
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(NULL, pid, 0);
}
