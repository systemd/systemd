/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <sys/prctl.h>
#include <linux/sched.h>
#include <sys/types.h>
#include <sys/stat.h>

#include "execute.h"
#include "strv.h"
#include "macro.h"
#include "util.h"
#include "log.h"
#include "ioprio.h"
#include "securebits.h"

static int close_fds(int except[], unsigned n_except) {
        DIR *d;
        struct dirent *de;
        int r = 0;

        /* Modifies the fds array! (sorts it) */

        if (!(d = opendir("/proc/self/fd")))
                return -errno;

        while ((de = readdir(d))) {
                int fd;

                if (de->d_name[0] == '.')
                        continue;

                if ((r = safe_atoi(de->d_name, &fd)) < 0)
                        goto finish;

                if (fd < 3)
                        continue;

                if (fd == dirfd(d))
                        continue;

                if (except) {
                        bool found;
                        unsigned i;

                        found = false;
                        for (i = 0; i < n_except; i++)
                                if (except[i] == fd) {
                                        found = true;
                                        break;
                                }

                        if (found)
                                continue;
                }

                if ((r = close_nointr(fd)) < 0)
                        goto finish;
        }

finish:
        closedir(d);
        return r;
}

static int shift_fds(int fds[], unsigned n_fds) {
        int start, restart_from;

        if (n_fds <= 0)
                return 0;

        assert(fds);

        start = 0;
        for (;;) {
                int i;

                restart_from = -1;

                for (i = start; i < (int) n_fds; i++) {
                        int nfd;

                        /* Already at right index? */
                        if (fds[i] == i+3)
                                continue;

                        if ((nfd = fcntl(fds[i], F_DUPFD, i+3)) < 0)
                                return -errno;

                        assert_se(close_nointr(fds[i]) == 0);
                        fds[i] = nfd;

                        /* Hmm, the fd we wanted isn't free? Then
                         * let's remember that and try again from here*/
                        if (nfd != i+3 && restart_from < 0)
                                restart_from = i;
                }

                if (restart_from < 0)
                        break;

                start = restart_from;
        }

        return 0;
}

static int flags_fds(int fds[], unsigned n_fds, bool nonblock) {
        unsigned i;

        if (n_fds <= 0)
                return 0;

        assert(fds);

        /* Drops/Sets O_NONBLOCK and FD_CLOEXEC from the file flags */

        for (i = 0; i < n_fds; i++) {
                int flags;

                if ((flags = fcntl(fds[i], F_GETFL, 0)) < 0)
                        return -errno;

                if (nonblock)
                        flags |= O_NONBLOCK;
                else
                        flags &= ~O_NONBLOCK;

                if (fcntl(fds[i], F_SETFL, flags) < 0)
                        return -errno;

                /* We unconditionally drop FD_CLOEXEC from the fds,
                 * since after all we want to pass these fds to our
                 * children */
                if ((flags = fcntl(fds[i], F_GETFD, 0)) < 0)
                        return -errno;

                if (fcntl(fds[i], F_SETFD, flags &~FD_CLOEXEC) < 0)
                        return -errno;
        }

        return 0;
}

static int replace_null_fd(int fd, int flags) {
        int nfd;
        assert(fd >= 0);

        close_nointr(fd);

        if ((nfd = open("/dev/null", flags|O_NOCTTY)) < 0)
                return -errno;

        if (nfd != fd) {
                close_nointr_nofail(nfd);
                return -EIO;
        }

        return 0;
}

static int setup_output(const ExecContext *context, const char *ident) {
        int r;

        assert(context);

        switch (context->output) {

        case EXEC_OUTPUT_CONSOLE:
                return 0;

        case EXEC_OUTPUT_NULL:

                if ((r = replace_null_fd(STDOUT_FILENO, O_WRONLY)) < 0 ||
                    (r = replace_null_fd(STDERR_FILENO, O_WRONLY)) < 0)
                        return r;

                return 0;

        case EXEC_OUTPUT_KERNEL:
        case EXEC_OUTPUT_SYSLOG: {

                int fd;
                union {
                        struct sockaddr sa;
                        struct sockaddr_un un;
                } sa;

                close_nointr(STDOUT_FILENO);
                close_nointr(STDERR_FILENO);

                if ((fd = socket(AF_UNIX, SOCK_STREAM, 0)) < 0)
                        return -errno;

                if (fd != STDOUT_FILENO) {
                        close_nointr_nofail(fd);
                        return -EIO;
                }

                zero(sa);
                sa.sa.sa_family = AF_UNIX;
                strncpy(sa.un.sun_path+1, LOGGER_SOCKET, sizeof(sa.un.sun_path)-1);

                if (connect(fd, &sa.sa, sizeof(sa)) < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                if (shutdown(fd, SHUT_RD) < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                if ((fd = dup(fd)) < 0) {
                        close_nointr_nofail(fd);
                        return -errno;
                }

                if (fd != STDERR_FILENO) {
                        close_nointr_nofail(fd);
                        return -EIO;
                }

                /* We speak a very simple protocol between log server
                 * and client: one line for the log destination (kmsg
                 * or syslog), followed by the priority field,
                 * followed by the process name. Since we replaced
                 * stdin/stderr we simple use stdio to write to
                 * it. Note that we use stderr, to minimize buffer
                 * flushing issues. */

                fprintf(stderr,
                        "%s\n"
                        "%i\n"
                        "%s\n",
                        context->output == EXEC_OUTPUT_KERNEL ? "kmsg" : "syslog",
                        context->syslog_priority,
                        context->syslog_identifier ? context->syslog_identifier : ident);

                return 0;
        }

        default:
                assert_not_reached("Unknown output type");
        }
}

static int setup_input(const ExecContext *context) {
        int r;

        assert(context);

        switch (context->input) {

        case EXEC_INPUT_CONSOLE:
                return 0;

        case EXEC_INPUT_NULL:
                if ((r = replace_null_fd(STDIN_FILENO, O_RDONLY)) < 0)
                        return r;

                return 0;

        default:
                assert_not_reached("Unknown input type");
        }
}

int exec_spawn(const ExecCommand *command, const ExecContext *context, int *fds, unsigned n_fds, pid_t *ret) {
        pid_t pid;

        assert(command);
        assert(context);
        assert(ret);
        assert(fds || n_fds <= 0);

        log_debug("about to execute %s", command->path);

        if ((pid = fork()) < 0)
                return -errno;

        if (pid == 0) {
                char **e, **f = NULL;
                int i, r;
                sigset_t ss;

                /* child */

                if (sigemptyset(&ss) < 0 ||
                    sigprocmask(SIG_SETMASK, &ss, NULL) < 0) {
                        r = EXIT_SIGNAL_MASK;
                        goto fail;
                }

                if (setpgid(0, 0) < 0) {
                        r = EXIT_PGID;
                        goto fail;
                }

                umask(context->umask);

                if (setup_input(context) < 0) {
                        r = EXIT_INPUT;
                        goto fail;
                }

                if (setup_output(context, file_name_from_path(command->path)) < 0) {
                        r = EXIT_OUTPUT;
                        goto fail;
                }

                if (context->oom_adjust_set) {
                        char t[16];

                        snprintf(t, sizeof(t), "%i", context->oom_adjust);
                        char_array_0(t);

                        if (write_one_line_file("/proc/self/oom_adj", t) < 0) {
                                r = EXIT_OOM_ADJUST;
                                goto fail;
                        }
                }

                if (context->root_directory)
                        if (chroot(context->root_directory) < 0) {
                                r = EXIT_CHROOT;
                                goto fail;
                        }

                if (chdir(context->working_directory ? context->working_directory : "/") < 0) {
                        r = EXIT_CHDIR;
                        goto fail;
                }

                if (context->nice_set)
                        if (setpriority(PRIO_PROCESS, 0, context->nice) < 0) {
                                r = EXIT_NICE;
                                goto fail;
                        }

                if (context->cpu_sched_set) {
                        struct sched_param param;

                        zero(param);
                        param.sched_priority = context->cpu_sched_priority;

                        if (sched_setscheduler(0, context->cpu_sched_policy |
                                               (context->cpu_sched_reset_on_fork ? SCHED_RESET_ON_FORK : 0), &param) < 0) {
                                r = EXIT_SETSCHEDULER;
                                goto fail;
                        }
                }

                if (context->cpu_affinity_set)
                        if (sched_setaffinity(0, sizeof(context->cpu_affinity), &context->cpu_affinity) < 0) {
                                r = EXIT_CPUAFFINITY;
                                goto fail;
                        }

                if (context->ioprio_set)
                        if (ioprio_set(IOPRIO_WHO_PROCESS, 0, context->ioprio) < 0) {
                                r = EXIT_IOPRIO;
                                goto fail;
                        }

                if (context->timer_slack_ns_set)
                        if (prctl(PR_SET_TIMERSLACK, context->timer_slack_ns_set) < 0) {
                                r = EXIT_TIMERSLACK;
                                goto fail;
                        }

                if (close_fds(fds, n_fds) < 0 ||
                    shift_fds(fds, n_fds) < 0 ||
                    flags_fds(fds, n_fds, context->non_blocking) < 0) {
                        r = EXIT_FDS;
                        goto fail;
                }

                for (i = 0; i < RLIMIT_NLIMITS; i++) {
                        if (!context->rlimit[i])
                                continue;

                        if (setrlimit(i, context->rlimit[i]) < 0) {
                                r = EXIT_LIMITS;
                                goto fail;
                        }
                }

                if (context->secure_bits) {
                        if (prctl(PR_SET_SECUREBITS, context->secure_bits) < 0) {
                                r = EXIT_SECUREBITS;
                                goto fail;
                        }
                }

                if (n_fds > 0) {
                        char a[64], b[64];
                        char *listen_env[3] = {
                                a,
                                b,
                                NULL
                        };

                        snprintf(a, sizeof(a), "LISTEN_PID=%llu", (unsigned long long) getpid());
                        snprintf(b, sizeof(b), "LISTEN_FDS=%u", n_fds);

                        a[sizeof(a)-1] = 0;
                        b[sizeof(b)-1] = 0;

                        if (context->environment) {
                                if (!(f = strv_merge(listen_env, context->environment))) {
                                        r = EXIT_MEMORY;
                                        goto fail;
                                }
                                e = f;
                        } else
                                e = listen_env;

                } else
                        e = context->environment;

                execve(command->path, command->argv, e);
                r = EXIT_EXEC;

        fail:
                strv_free(f);
                _exit(r);
        }


        log_debug("executed %s as %llu", command->path, (unsigned long long) pid);

        *ret = pid;
        return 0;
}

void exec_context_init(ExecContext *c) {
        assert(c);

        c->umask = 0002;
        c->oom_adjust = 0;
        c->oom_adjust_set = false;
        c->nice = 0;
        c->nice_set = false;
        c->ioprio = IOPRIO_PRIO_VALUE(IOPRIO_CLASS_BE, 0);
        c->ioprio_set = false;
        c->cpu_sched_policy = SCHED_OTHER;
        c->cpu_sched_priority = 0;
        c->cpu_sched_set = false;
        CPU_ZERO(&c->cpu_affinity);
        c->cpu_affinity_set = false;

        c->input = 0;
        c->output = 0;
        c->syslog_priority = LOG_DAEMON|LOG_INFO;

        c->secure_bits = 0;
        c->capability_bounding_set_drop = 0;
}

void exec_context_done(ExecContext *c) {
        unsigned l;

        assert(c);

        strv_free(c->environment);
        c->environment = NULL;

        for (l = 0; l < ELEMENTSOF(c->rlimit); l++) {
                free(c->rlimit[l]);
                c->rlimit[l] = NULL;
        }

        free(c->working_directory);
        c->working_directory = NULL;
        free(c->root_directory);
        c->root_directory = NULL;

        free(c->syslog_identifier);
        c->syslog_identifier = NULL;

        free(c->user);
        c->user = NULL;

        free(c->group);
        c->group = NULL;

        strv_free(c->supplementary_groups);
        c->supplementary_groups = NULL;

        if (c->capabilities) {
                cap_free(c->capabilities);
                c->capabilities = NULL;
        }
}

void exec_command_free_list(ExecCommand *c) {
        ExecCommand *i;

        while ((i = c)) {
                LIST_REMOVE(ExecCommand, command, c, i);

                free(i->path);
                strv_free(i->argv);
                free(i);
        }
}

void exec_command_free_array(ExecCommand **c, unsigned n) {
        unsigned i;

        for (i = 0; i < n; i++) {
                exec_command_free_list(c[i]);
                c[i] = NULL;
        }
}

void exec_context_dump(ExecContext *c, FILE* f, const char *prefix) {
        char ** e;
        unsigned i;

        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sUMask: %04o\n"
                "%sWorkingDirectory: %s\n"
                "%sRootDirectory: %s\n"
                "%sNonBlocking: %s\n",
                prefix, c->umask,
                prefix, c->working_directory ? c->working_directory : "/",
                prefix, c->root_directory ? c->root_directory : "/",
                prefix, yes_no(c->non_blocking));

        if (c->environment)
                for (e = c->environment; *e; e++)
                        fprintf(f, "%sEnvironment: %s\n", prefix, *e);

        if (c->nice_set)
                fprintf(f,
                        "%sNice: %i\n",
                        prefix, c->nice);

        if (c->oom_adjust_set)
                fprintf(f,
                        "%sOOMAdjust: %i\n",
                        prefix, c->oom_adjust);

        for (i = 0; i < RLIM_NLIMITS; i++)
                if (c->rlimit[i])
                        fprintf(f, "%s%s: %llu\n", prefix, rlimit_to_string(i), (unsigned long long) c->rlimit[i]->rlim_max);

        if (c->ioprio_set)
                fprintf(f,
                        "%sIOSchedulingClass: %s\n"
                        "%sIOPriority: %i\n",
                        prefix, ioprio_class_to_string(IOPRIO_PRIO_CLASS(c->ioprio)),
                        prefix, (int) IOPRIO_PRIO_DATA(c->ioprio));

        if (c->cpu_sched_set)
                fprintf(f,
                        "%sCPUSchedulingPolicy: %s\n"
                        "%sCPUSchedulingPriority: %i\n"
                        "%sCPUSchedulingResetOnFork: %s\n",
                        prefix, sched_policy_to_string(c->cpu_sched_policy),
                        prefix, c->cpu_sched_priority,
                        prefix, yes_no(c->cpu_sched_reset_on_fork));

        if (c->cpu_affinity_set) {
                fprintf(f, "%sCPUAffinity:", prefix);
                for (i = 0; i < CPU_SETSIZE; i++)
                        if (CPU_ISSET(i, &c->cpu_affinity))
                                fprintf(f, " %i", i);
                fputs("\n", f);
        }

        if (c->timer_slack_ns_set)
                fprintf(f, "%sTimerSlackNS: %lu\n", prefix, c->timer_slack_ns);

        fprintf(f,
                "%sInput: %s\n"
                "%sOutput: %s\n",
                prefix, exec_input_to_string(c->input),
                prefix, exec_output_to_string(c->output));

        if (c->output == EXEC_OUTPUT_SYSLOG || c->output == EXEC_OUTPUT_KERNEL)
                fprintf(f,
                        "%sSyslogFacility: %s\n"
                        "%sSyslogLevel: %s\n",
                        prefix, log_facility_to_string(LOG_FAC(c->syslog_priority)),
                        prefix, log_level_to_string(LOG_PRI(c->syslog_priority)));

        if (c->capabilities) {
                char *t;
                if ((t = cap_to_text(c->capabilities, NULL))) {
                        fprintf(f, "%sCapabilities: %s\n",
                                prefix, t);
                        cap_free(t);
                }
        }

        if (c->secure_bits)
                fprintf(f, "%sSecure Bits:%s%s%s%s%s%s\n",
                        prefix,
                        (c->secure_bits & SECURE_KEEP_CAPS) ? " keep-caps" : "",
                        (c->secure_bits & SECURE_KEEP_CAPS_LOCKED) ? " keep-caps-locked" : "",
                        (c->secure_bits & SECURE_NO_SETUID_FIXUP) ? " no-setuid-fixup" : "",
                        (c->secure_bits & SECURE_NO_SETUID_FIXUP_LOCKED) ? " no-setuid-fixup-locked" : "",
                        (c->secure_bits & SECURE_NOROOT) ? " noroot" : "",
                        (c->secure_bits & SECURE_NOROOT_LOCKED) ? "noroot-locked" : "");

        if (c->capability_bounding_set_drop) {
                fprintf(f, "%sCapabilityBoundingSetDrop:", prefix);

                for (i = 0; i <= CAP_LAST_CAP; i++)
                        if (c->capability_bounding_set_drop & (1 << i)) {
                                char *t;

                                if ((t = cap_to_name(i))) {
                                        fprintf(f, " %s", t);
                                        free(t);
                                }
                        }

                fputs("\n", f);
        }

        if (c->user)
                fprintf(f, "%sUser: %s", prefix, c->user);
        if (c->group)
                fprintf(f, "%sGroup: %s", prefix, c->group);

        if (c->supplementary_groups) {
                char **g;

                fprintf(f, "%sSupplementaryGroups:", prefix);

                STRV_FOREACH(g, c->supplementary_groups)
                        fprintf(f, " %s", *g);

                fputs("\n", f);
        }
}

void exec_status_fill(ExecStatus *s, pid_t pid, int code, int status) {
        assert(s);

        s->pid = pid;
        s->code = code;
        s->status = status;
        s->timestamp = now(CLOCK_REALTIME);
}

char *exec_command_line(ExecCommand *c) {
        size_t k;
        char *n, *p, **a;
        bool first = true;

        assert(c);
        assert(c->argv);

        k = 1;
        STRV_FOREACH(a, c->argv)
                k += strlen(*a)+3;

        if (!(n = new(char, k)))
                return NULL;

        p = n;
        STRV_FOREACH(a, c->argv) {

                if (!first)
                        *(p++) = ' ';
                else
                        first = false;

                if (strpbrk(*a, WHITESPACE)) {
                        *(p++) = '\'';
                        p = stpcpy(p, *a);
                        *(p++) = '\'';
                } else
                        p = stpcpy(p, *a);

        }

        *p = 0;

        /* FIXME: this doesn't really handle arguments that have
         * spaces and ticks in them */

        return n;
}

void exec_command_dump(ExecCommand *c, FILE *f, const char *prefix) {
        char *cmd;

        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        cmd = exec_command_line(c);

        fprintf(f,
                "%sCommand Line: %s\n",
                prefix, cmd ? cmd : strerror(ENOMEM));

        free(cmd);
}

void exec_command_dump_list(ExecCommand *c, FILE *f, const char *prefix) {
        assert(f);

        if (!prefix)
                prefix = "";

        LIST_FOREACH(command, c, c)
                exec_command_dump(c, f, prefix);
}

static const char* const exec_output_table[_EXEC_OUTPUT_MAX] = {
        [EXEC_OUTPUT_CONSOLE] = "console",
        [EXEC_OUTPUT_NULL] = "null",
        [EXEC_OUTPUT_SYSLOG] = "syslog",
        [EXEC_OUTPUT_KERNEL] = "kernel"
};

DEFINE_STRING_TABLE_LOOKUP(exec_output, ExecOutput);

static const char* const exec_input_table[_EXEC_INPUT_MAX] = {
        [EXEC_INPUT_NULL] = "null",
        [EXEC_INPUT_CONSOLE] = "console"
};

DEFINE_STRING_TABLE_LOOKUP(exec_input, ExecInput);
