/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <signal.h>

#include "execute.h"
#include "strv.h"
#include "macro.h"
#include "util.h"
#include "log.h"

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
                char t[16];
                sigset_t ss;

                /* child */

                if (sigemptyset(&ss) < 0 ||
                    sigprocmask(SIG_SETMASK, &ss, NULL) < 0) {
                        r = EXIT_SIGNAL_MASK;
                        goto fail;
                }

                umask(context->umask);

                if (chdir(context->directory ? context->directory : "/") < 0) {
                        r = EXIT_CHDIR;
                        goto fail;
                }

                snprintf(t, sizeof(t), "%i", context->oom_adjust);
                char_array_0(t);

                if (write_one_line_file("/proc/self/oom_adj", t) < 0) {
                        r = EXIT_OOM_ADJUST;
                        goto fail;
                }

                if (setpriority(PRIO_PROCESS, 0, context->nice) < 0) {
                        r = EXIT_NICE;
                        goto fail;
                }

                if (close_fds(fds, n_fds) < 0 ||
                    shift_fds(fds, n_fds) < 0) {
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
        cap_clear(c->capabilities);
        c->oom_adjust = 0;
        c->nice = 0;
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

        free(c->directory);
        c->directory = NULL;

        free(c->user);
        c->user = NULL;

        free(c->group);
        c->group = NULL;

        strv_free(c->supplementary_groups);
        c->supplementary_groups = NULL;
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
        assert(c);
        assert(f);

        if (!prefix)
                prefix = "";

        fprintf(f,
                "%sUmask: %04o\n"
                "%sDirectory: %s\n"
                "%sNice: %i\n"
                "%sOOMAdjust: %i\n",
                prefix, c->umask,
                prefix, c->directory ? c->directory : "/",
                prefix, c->nice,
                prefix, c->oom_adjust);
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
