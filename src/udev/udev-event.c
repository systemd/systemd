/*
 * Copyright (C) 2003-2013 Kay Sievers <kay@vrfy.org>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <ctype.h>
#include <string.h>
#include <time.h>
#include <net/if.h>
#include <sys/prctl.h>
#include <sys/poll.h>
#include <sys/epoll.h>
#include <sys/wait.h>
#include <sys/signalfd.h>

#include "udev.h"
#include "rtnl-util.h"

struct udev_event *udev_event_new(struct udev_device *dev)
{
        struct udev *udev = udev_device_get_udev(dev);
        struct udev_event *event;

        event = new0(struct udev_event, 1);
        if (event == NULL)
                return NULL;
        event->dev = dev;
        event->udev = udev;
        udev_list_init(udev, &event->run_list, false);
        udev_list_init(udev, &event->seclabel_list, false);
        event->fd_signal = -1;
        event->birth_usec = now(CLOCK_MONOTONIC);
        event->timeout_usec = 30 * 1000 * 1000;
        return event;
}

void udev_event_unref(struct udev_event *event)
{
        if (event == NULL)
                return;
        udev_list_cleanup(&event->run_list);
        udev_list_cleanup(&event->seclabel_list);
        free(event->program_result);
        free(event->name);
        free(event);
}

size_t udev_event_apply_format(struct udev_event *event, const char *src, char *dest, size_t size)
{
        struct udev_device *dev = event->dev;
        enum subst_type {
                SUBST_UNKNOWN,
                SUBST_DEVNODE,
                SUBST_ATTR,
                SUBST_ENV,
                SUBST_KERNEL,
                SUBST_KERNEL_NUMBER,
                SUBST_DRIVER,
                SUBST_DEVPATH,
                SUBST_ID,
                SUBST_MAJOR,
                SUBST_MINOR,
                SUBST_RESULT,
                SUBST_PARENT,
                SUBST_NAME,
                SUBST_LINKS,
                SUBST_ROOT,
                SUBST_SYS,
        };
        static const struct subst_map {
                const char *name;
                const char fmt;
                enum subst_type type;
        } map[] = {
                { .name = "devnode",  .fmt = 'N', .type = SUBST_DEVNODE },
                { .name = "tempnode", .fmt = 'N', .type = SUBST_DEVNODE },
                { .name = "attr",     .fmt = 's', .type = SUBST_ATTR },
                { .name = "sysfs",    .fmt = 's', .type = SUBST_ATTR },
                { .name = "env",      .fmt = 'E', .type = SUBST_ENV },
                { .name = "kernel",   .fmt = 'k', .type = SUBST_KERNEL },
                { .name = "number",   .fmt = 'n', .type = SUBST_KERNEL_NUMBER },
                { .name = "driver",   .fmt = 'd', .type = SUBST_DRIVER },
                { .name = "devpath",  .fmt = 'p', .type = SUBST_DEVPATH },
                { .name = "id",       .fmt = 'b', .type = SUBST_ID },
                { .name = "major",    .fmt = 'M', .type = SUBST_MAJOR },
                { .name = "minor",    .fmt = 'm', .type = SUBST_MINOR },
                { .name = "result",   .fmt = 'c', .type = SUBST_RESULT },
                { .name = "parent",   .fmt = 'P', .type = SUBST_PARENT },
                { .name = "name",     .fmt = 'D', .type = SUBST_NAME },
                { .name = "links",    .fmt = 'L', .type = SUBST_LINKS },
                { .name = "root",     .fmt = 'r', .type = SUBST_ROOT },
                { .name = "sys",      .fmt = 'S', .type = SUBST_SYS },
        };
        const char *from;
        char *s;
        size_t l;

        from = src;
        s = dest;
        l = size;

        for (;;) {
                enum subst_type type = SUBST_UNKNOWN;
                char attrbuf[UTIL_PATH_SIZE];
                char *attr = NULL;

                while (from[0] != '\0') {
                        if (from[0] == '$') {
                                /* substitute named variable */
                                unsigned int i;

                                if (from[1] == '$') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (startswith(&from[1], map[i].name)) {
                                                type = map[i].type;
                                                from += strlen(map[i].name)+1;
                                                goto subst;
                                        }
                                }
                        } else if (from[0] == '%') {
                                /* substitute format char */
                                unsigned int i;

                                if (from[1] == '%') {
                                        from++;
                                        goto copy;
                                }

                                for (i = 0; i < ELEMENTSOF(map); i++) {
                                        if (from[1] == map[i].fmt) {
                                                type = map[i].type;
                                                from += 2;
                                                goto subst;
                                        }
                                }
                        }
copy:
                        /* copy char */
                        if (l == 0)
                                goto out;
                        s[0] = from[0];
                        from++;
                        s++;
                        l--;
                }

                goto out;
subst:
                /* extract possible $format{attr} */
                if (from[0] == '{') {
                        unsigned int i;

                        from++;
                        for (i = 0; from[i] != '}'; i++) {
                                if (from[i] == '\0') {
                                        log_error("missing closing brace for format '%s'", src);
                                        goto out;
                                }
                        }
                        if (i >= sizeof(attrbuf))
                                goto out;
                        memcpy(attrbuf, from, i);
                        attrbuf[i] = '\0';
                        from += i+1;
                        attr = attrbuf;
                } else {
                        attr = NULL;
                }

                switch (type) {
                case SUBST_DEVPATH:
                        l = strpcpy(&s, l, udev_device_get_devpath(dev));
                        break;
                case SUBST_KERNEL:
                        l = strpcpy(&s, l, udev_device_get_sysname(dev));
                        break;
                case SUBST_KERNEL_NUMBER:
                        if (udev_device_get_sysnum(dev) == NULL)
                                break;
                        l = strpcpy(&s, l, udev_device_get_sysnum(dev));
                        break;
                case SUBST_ID:
                        if (event->dev_parent == NULL)
                                break;
                        l = strpcpy(&s, l, udev_device_get_sysname(event->dev_parent));
                        break;
                case SUBST_DRIVER: {
                        const char *driver;

                        if (event->dev_parent == NULL)
                                break;

                        driver = udev_device_get_driver(event->dev_parent);
                        if (driver == NULL)
                                break;
                        l = strpcpy(&s, l, driver);
                        break;
                }
                case SUBST_MAJOR: {
                        char num[UTIL_PATH_SIZE];

                        sprintf(num, "%d", major(udev_device_get_devnum(dev)));
                        l = strpcpy(&s, l, num);
                        break;
                }
                case SUBST_MINOR: {
                        char num[UTIL_PATH_SIZE];

                        sprintf(num, "%d", minor(udev_device_get_devnum(dev)));
                        l = strpcpy(&s, l, num);
                        break;
                }
                case SUBST_RESULT: {
                        char *rest;
                        int i;

                        if (event->program_result == NULL)
                                break;
                        /* get part part of the result string */
                        i = 0;
                        if (attr != NULL)
                                i = strtoul(attr, &rest, 10);
                        if (i > 0) {
                                char result[UTIL_PATH_SIZE];
                                char tmp[UTIL_PATH_SIZE];
                                char *cpos;

                                strscpy(result, sizeof(result), event->program_result);
                                cpos = result;
                                while (--i) {
                                        while (cpos[0] != '\0' && !isspace(cpos[0]))
                                                cpos++;
                                        while (isspace(cpos[0]))
                                                cpos++;
                                        if (cpos[0] == '\0')
                                                break;
                                }
                                if (i > 0) {
                                        log_error("requested part of result string not found");
                                        break;
                                }
                                strscpy(tmp, sizeof(tmp), cpos);
                                /* %{2+}c copies the whole string from the second part on */
                                if (rest[0] != '+') {
                                        cpos = strchr(tmp, ' ');
                                        if (cpos)
                                                cpos[0] = '\0';
                                }
                                l = strpcpy(&s, l, tmp);
                        } else {
                                l = strpcpy(&s, l, event->program_result);
                        }
                        break;
                }
                case SUBST_ATTR: {
                        const char *value = NULL;
                        char vbuf[UTIL_NAME_SIZE];
                        size_t len;
                        int count;

                        if (attr == NULL) {
                                log_error("missing file parameter for attr");
                                break;
                        }

                        /* try to read the value specified by "[dmi/id]product_name" */
                        if (util_resolve_subsys_kernel(event->udev, attr, vbuf, sizeof(vbuf), 1) == 0)
                                value = vbuf;

                        /* try to read the attribute the device */
                        if (value == NULL)
                                value = udev_device_get_sysattr_value(event->dev, attr);

                        /* try to read the attribute of the parent device, other matches have selected */
                        if (value == NULL && event->dev_parent != NULL && event->dev_parent != event->dev)
                                value = udev_device_get_sysattr_value(event->dev_parent, attr);

                        if (value == NULL)
                                break;

                        /* strip trailing whitespace, and replace unwanted characters */
                        if (value != vbuf)
                                strscpy(vbuf, sizeof(vbuf), value);
                        len = strlen(vbuf);
                        while (len > 0 && isspace(vbuf[--len]))
                                vbuf[len] = '\0';
                        count = util_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                        if (count > 0)
                                log_debug("%i character(s) replaced" , count);
                        l = strpcpy(&s, l, vbuf);
                        break;
                }
                case SUBST_PARENT: {
                        struct udev_device *dev_parent;
                        const char *devnode;

                        dev_parent = udev_device_get_parent(event->dev);
                        if (dev_parent == NULL)
                                break;
                        devnode = udev_device_get_devnode(dev_parent);
                        if (devnode != NULL)
                                l = strpcpy(&s, l, devnode + strlen("/dev/"));
                        break;
                }
                case SUBST_DEVNODE:
                        if (udev_device_get_devnode(dev) != NULL)
                                l = strpcpy(&s, l, udev_device_get_devnode(dev));
                        break;
                case SUBST_NAME:
                        if (event->name != NULL)
                                l = strpcpy(&s, l, event->name);
                        else if (udev_device_get_devnode(dev) != NULL)
                                l = strpcpy(&s, l, udev_device_get_devnode(dev) + strlen("/dev/"));
                        else
                                l = strpcpy(&s, l, udev_device_get_sysname(dev));
                        break;
                case SUBST_LINKS: {
                        struct udev_list_entry *list_entry;

                        list_entry = udev_device_get_devlinks_list_entry(dev);
                        if (list_entry == NULL)
                                break;
                        l = strpcpy(&s, l, udev_list_entry_get_name(list_entry) + strlen("/dev/"));
                        udev_list_entry_foreach(list_entry, udev_list_entry_get_next(list_entry))
                                l = strpcpyl(&s, l, " ", udev_list_entry_get_name(list_entry) + strlen("/dev/"), NULL);
                        break;
                }
                case SUBST_ROOT:
                        l = strpcpy(&s, l, "/dev");
                        break;
                case SUBST_SYS:
                        l = strpcpy(&s, l, "/sys");
                        break;
                case SUBST_ENV:
                        if (attr == NULL) {
                                break;
                        } else {
                                const char *value;

                                value = udev_device_get_property_value(event->dev, attr);
                                if (value == NULL)
                                        break;
                                l = strpcpy(&s, l, value);
                                break;
                        }
                default:
                        log_error("unknown substitution type=%i", type);
                        break;
                }
        }

out:
        s[0] = '\0';
        return l;
}

static int spawn_exec(struct udev_event *event,
                      const char *cmd, char *const argv[], char **envp, const sigset_t *sigmask,
                      int fd_stdout, int fd_stderr)
{
        int err;
        int fd;

        /* discard child output or connect to pipe */
        fd = open("/dev/null", O_RDWR);
        if (fd >= 0) {
                dup2(fd, STDIN_FILENO);
                if (fd_stdout < 0)
                        dup2(fd, STDOUT_FILENO);
                if (fd_stderr < 0)
                        dup2(fd, STDERR_FILENO);
                close(fd);
        } else {
                log_error("open /dev/null failed: %m");
        }

        /* connect pipes to std{out,err} */
        if (fd_stdout >= 0) {
                dup2(fd_stdout, STDOUT_FILENO);
                        close(fd_stdout);
        }
        if (fd_stderr >= 0) {
                dup2(fd_stderr, STDERR_FILENO);
                close(fd_stderr);
        }

        /* terminate child in case parent goes away */
        prctl(PR_SET_PDEATHSIG, SIGTERM);

        /* restore original udev sigmask before exec */
        if (sigmask)
                sigprocmask(SIG_SETMASK, sigmask, NULL);

        execve(argv[0], argv, envp);

        /* exec failed */
        err = -errno;
        log_error("failed to execute '%s' '%s': %m", argv[0], cmd);
        return err;
}

static void spawn_read(struct udev_event *event,
                      const char *cmd,
                      int fd_stdout, int fd_stderr,
                      char *result, size_t ressize)
{
        size_t respos = 0;
        int fd_ep = -1;
        struct epoll_event ep_outpipe, ep_errpipe;

        /* read from child if requested */
        if (fd_stdout < 0 && fd_stderr < 0)
                return;

        fd_ep = epoll_create1(EPOLL_CLOEXEC);
        if (fd_ep < 0) {
                log_error("error creating epoll fd: %m");
                goto out;
        }

        if (fd_stdout >= 0) {
                memzero(&ep_outpipe, sizeof(struct epoll_event));
                ep_outpipe.events = EPOLLIN;
                ep_outpipe.data.ptr = &fd_stdout;
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stdout, &ep_outpipe) < 0) {
                        log_error("fail to add fd to epoll: %m");
                        goto out;
                }
        }

        if (fd_stderr >= 0) {
                memzero(&ep_errpipe, sizeof(struct epoll_event));
                ep_errpipe.events = EPOLLIN;
                ep_errpipe.data.ptr = &fd_stderr;
                if (epoll_ctl(fd_ep, EPOLL_CTL_ADD, fd_stderr, &ep_errpipe) < 0) {
                        log_error("fail to add fd to epoll: %m");
                        goto out;
                }
        }

        /* read child output */
        while (fd_stdout >= 0 || fd_stderr >= 0) {
                int timeout;
                int fdcount;
                struct epoll_event ev[4];
                int i;

                if (event->timeout_usec > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= event->timeout_usec) {
                                log_error("timeout '%s'", cmd);
                                goto out;
                        }
                        timeout = ((event->timeout_usec - age_usec) / 1000) + 1000;
                } else {
                        timeout = -1;
                }

                fdcount = epoll_wait(fd_ep, ev, ELEMENTSOF(ev), timeout);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        log_error("failed to poll: %m");
                        goto out;
                }
                if (fdcount == 0) {
                        log_error("timeout '%s'", cmd);
                        goto out;
                }

                for (i = 0; i < fdcount; i++) {
                        int *fd = (int *)ev[i].data.ptr;

                        if (ev[i].events & EPOLLIN) {
                                ssize_t count;
                                char buf[4096];

                                count = read(*fd, buf, sizeof(buf)-1);
                                if (count <= 0)
                                        continue;
                                buf[count] = '\0';

                                /* store stdout result */
                                if (result != NULL && *fd == fd_stdout) {
                                        if (respos + count < ressize) {
                                                memcpy(&result[respos], buf, count);
                                                respos += count;
                                        } else {
                                                log_error("'%s' ressize %zd too short", cmd, ressize);
                                        }
                                }

                                /* log debug output only if we watch stderr */
                                if (fd_stderr >= 0) {
                                        char *pos;
                                        char *line;

                                        pos = buf;
                                        while ((line = strsep(&pos, "\n"))) {
                                                if (pos != NULL || line[0] != '\0')
                                                        log_debug("'%s'(%s) '%s'", cmd, *fd == fd_stdout ? "out" : "err" , line);
                                        }
                                }
                        } else if (ev[i].events & EPOLLHUP) {
                                if (epoll_ctl(fd_ep, EPOLL_CTL_DEL, *fd, NULL) < 0) {
                                        log_error("failed to remove fd from epoll: %m");
                                        goto out;
                                }
                                *fd = -1;
                        }
                }
        }

        /* return the child's stdout string */
        if (result != NULL)
                result[respos] = '\0';
out:
        if (fd_ep >= 0)
                close(fd_ep);
}

static int spawn_wait(struct udev_event *event, const char *cmd, pid_t pid)
{
        struct pollfd pfd[1];
        int err = 0;

        pfd[0].events = POLLIN;
        pfd[0].fd = event->fd_signal;

        while (pid > 0) {
                int timeout;
                int fdcount;

                if (event->timeout_usec > 0) {
                        usec_t age_usec;

                        age_usec = now(CLOCK_MONOTONIC) - event->birth_usec;
                        if (age_usec >= event->timeout_usec)
                                timeout = 1000;
                        else
                                timeout = ((event->timeout_usec - age_usec) / 1000) + 1000;
                } else {
                        timeout = -1;
                }

                fdcount = poll(pfd, 1, timeout);
                if (fdcount < 0) {
                        if (errno == EINTR)
                                continue;
                        err = -errno;
                        log_error("failed to poll: %m");
                        goto out;
                }
                if (fdcount == 0) {
                        log_error("timeout: killing '%s' [%u]", cmd, pid);
                        kill(pid, SIGKILL);
                }

                if (pfd[0].revents & POLLIN) {
                        struct signalfd_siginfo fdsi;
                        int status;
                        ssize_t size;

                        size = read(event->fd_signal, &fdsi, sizeof(struct signalfd_siginfo));
                        if (size != sizeof(struct signalfd_siginfo))
                                continue;

                        switch (fdsi.ssi_signo) {
                        case SIGTERM:
                                event->sigterm = true;
                                break;
                        case SIGCHLD:
                                if (waitpid(pid, &status, WNOHANG) < 0)
                                        break;
                                if (WIFEXITED(status)) {
                                        log_debug("'%s' [%u] exit with return code %i", cmd, pid, WEXITSTATUS(status));
                                        if (WEXITSTATUS(status) != 0)
                                                err = -1;
                                } else if (WIFSIGNALED(status)) {
                                        log_error("'%s' [%u] terminated by signal %i (%s)", cmd, pid, WTERMSIG(status), strsignal(WTERMSIG(status)));
                                        err = -1;
                                } else if (WIFSTOPPED(status)) {
                                        log_error("'%s' [%u] stopped", cmd, pid);
                                        err = -1;
                                } else if (WIFCONTINUED(status)) {
                                        log_error("'%s' [%u] continued", cmd, pid);
                                        err = -1;
                                } else {
                                        log_error("'%s' [%u] exit with status 0x%04x", cmd, pid, status);
                                        err = -1;
                                }
                                pid = 0;
                                break;
                        }
                }
        }
out:
        return err;
}

int udev_build_argv(struct udev *udev, char *cmd, int *argc, char *argv[])
{
        int i = 0;
        char *pos;

        if (strchr(cmd, ' ') == NULL) {
                argv[i++] = cmd;
                goto out;
        }

        pos = cmd;
        while (pos != NULL && pos[0] != '\0') {
                if (pos[0] == '\'') {
                        /* do not separate quotes */
                        pos++;
                        argv[i] = strsep(&pos, "\'");
                        if (pos != NULL)
                                while (pos[0] == ' ')
                                        pos++;
                } else {
                        argv[i] = strsep(&pos, " ");
                        if (pos != NULL)
                                while (pos[0] == ' ')
                                        pos++;
                }
                i++;
        }
out:
        argv[i] = NULL;
        if (argc)
                *argc = i;
        return 0;
}

int udev_event_spawn(struct udev_event *event,
                     const char *cmd, char **envp, const sigset_t *sigmask,
                     char *result, size_t ressize)
{
        struct udev *udev = event->udev;
        int outpipe[2] = {-1, -1};
        int errpipe[2] = {-1, -1};
        pid_t pid;
        char arg[UTIL_PATH_SIZE];
        char *argv[128];
        char program[UTIL_PATH_SIZE];
        int err = 0;

        strscpy(arg, sizeof(arg), cmd);
        udev_build_argv(event->udev, arg, NULL, argv);

        /* pipes from child to parent */
        if (result != NULL || udev_get_log_priority(udev) >= LOG_INFO) {
                if (pipe2(outpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error("pipe failed: %m");
                        goto out;
                }
        }
        if (udev_get_log_priority(udev) >= LOG_INFO) {
                if (pipe2(errpipe, O_NONBLOCK) != 0) {
                        err = -errno;
                        log_error("pipe failed: %m");
                        goto out;
                }
        }

        /* allow programs in /usr/lib/udev/ to be called without the path */
        if (argv[0][0] != '/') {
                strscpyl(program, sizeof(program), UDEVLIBEXECDIR "/", argv[0], NULL);
                argv[0] = program;
        }

        pid = fork();
        switch(pid) {
        case 0:
                /* child closes parent's ends of pipes */
                if (outpipe[READ_END] >= 0) {
                        close(outpipe[READ_END]);
                        outpipe[READ_END] = -1;
                }
                if (errpipe[READ_END] >= 0) {
                        close(errpipe[READ_END]);
                        errpipe[READ_END] = -1;
                }

                log_debug("starting '%s'", cmd);

                spawn_exec(event, cmd, argv, envp, sigmask,
                           outpipe[WRITE_END], errpipe[WRITE_END]);

                _exit(2 );
        case -1:
                log_error("fork of '%s' failed: %m", cmd);
                err = -1;
                goto out;
        default:
                /* parent closed child's ends of pipes */
                if (outpipe[WRITE_END] >= 0) {
                        close(outpipe[WRITE_END]);
                        outpipe[WRITE_END] = -1;
                }
                if (errpipe[WRITE_END] >= 0) {
                        close(errpipe[WRITE_END]);
                        errpipe[WRITE_END] = -1;
                }

                spawn_read(event, cmd,
                         outpipe[READ_END], errpipe[READ_END],
                         result, ressize);

                err = spawn_wait(event, cmd, pid);
        }

out:
        if (outpipe[READ_END] >= 0)
                close(outpipe[READ_END]);
        if (outpipe[WRITE_END] >= 0)
                close(outpipe[WRITE_END]);
        if (errpipe[READ_END] >= 0)
                close(errpipe[READ_END]);
        if (errpipe[WRITE_END] >= 0)
                close(errpipe[WRITE_END]);
        return err;
}

static int rename_netif(struct udev_event *event)
{
        struct udev_device *dev = event->dev;
        _cleanup_rtnl_unref_ sd_rtnl *rtnl = NULL;
        char name[IFNAMSIZ];
        const char *oldname;
        int r;

        oldname = udev_device_get_sysname(dev);

        log_debug("changing net interface name from '%s' to '%s'",
                  oldname, event->name);

        strscpy(name, IFNAMSIZ, event->name);

        r = sd_rtnl_open(&rtnl, 0);
        if (r < 0)
                return r;

        r = rtnl_set_link_name(rtnl, udev_device_get_ifindex(dev), name);
        if (r < 0)
                log_error("error changing net interface name %s to %s: %s",
                          oldname, name, strerror(-r));
        else
                print_kmsg("renamed network interface %s to %s\n", oldname, name);

        return r;
}

void udev_event_execute_rules(struct udev_event *event, struct udev_rules *rules, const sigset_t *sigmask)
{
        struct udev_device *dev = event->dev;

        if (udev_device_get_subsystem(dev) == NULL)
                return;

        if (streq(udev_device_get_action(dev), "remove")) {
                udev_device_read_db(dev, NULL);
                udev_device_delete_db(dev);
                udev_device_tag_index(dev, NULL, false);

                if (major(udev_device_get_devnum(dev)) != 0)
                        udev_watch_end(event->udev, dev);

                udev_rules_apply_to_event(rules, event, sigmask);

                if (major(udev_device_get_devnum(dev)) != 0)
                        udev_node_remove(dev);
        } else {
                event->dev_db = udev_device_new(event->udev);
                if (event->dev_db != NULL) {
                        udev_device_set_syspath(event->dev_db, udev_device_get_syspath(dev));
                        udev_device_set_subsystem(event->dev_db, udev_device_get_subsystem(dev));
                        udev_device_read_db(event->dev_db, NULL);
                        udev_device_set_info_loaded(event->dev_db);

                        /* disable watch during event processing */
                        if (major(udev_device_get_devnum(dev)) != 0)
                                udev_watch_end(event->udev, event->dev_db);
                }

                udev_rules_apply_to_event(rules, event, sigmask);

                /* rename a new network interface, if needed */
                if (udev_device_get_ifindex(dev) > 0 && streq(udev_device_get_action(dev), "add") &&
                    event->name != NULL && !streq(event->name, udev_device_get_sysname(dev))) {
                        char syspath[UTIL_PATH_SIZE];
                        char *pos;
                        int r;

                        r = rename_netif(event);
                        if (r >= 0) {
                                log_debug("renamed netif to '%s'", event->name);

                                /* remember old name */
                                udev_device_add_property(dev, "INTERFACE_OLD", udev_device_get_sysname(dev));

                                /* now change the devpath, because the kernel device name has changed */
                                strscpy(syspath, sizeof(syspath), udev_device_get_syspath(dev));
                                pos = strrchr(syspath, '/');
                                if (pos != NULL) {
                                        pos++;
                                        strscpy(pos, sizeof(syspath) - (pos - syspath), event->name);
                                        udev_device_set_syspath(event->dev, syspath);
                                        udev_device_add_property(dev, "INTERFACE", udev_device_get_sysname(dev));
                                        log_debug("changed devpath to '%s'", udev_device_get_devpath(dev));
                                }
                        }
                }

                if (major(udev_device_get_devnum(dev)) > 0) {
                        bool apply;

                        /* remove/update possible left-over symlinks from old database entry */
                        if (event->dev_db != NULL)
                                udev_node_update_old_links(dev, event->dev_db);

                        if (!event->owner_set)
                                event->uid = udev_device_get_devnode_uid(dev);

                        if (!event->group_set)
                                event->gid = udev_device_get_devnode_gid(dev);

                        if (!event->mode_set) {
                                if (udev_device_get_devnode_mode(dev) > 0) {
                                        /* kernel supplied value */
                                        event->mode = udev_device_get_devnode_mode(dev);
                                } else if (event->gid > 0) {
                                        /* default 0660 if a group is assigned */
                                        event->mode = 0660;
                                } else {
                                        /* default 0600 */
                                        event->mode = 0600;
                                }
                        }

                        apply = streq(udev_device_get_action(dev), "add") || event->owner_set || event->group_set || event->mode_set;
                        udev_node_add(dev, apply, event->mode, event->uid, event->gid, &event->seclabel_list);
                }

                /* preserve old, or get new initialization timestamp */
                if (event->dev_db != NULL && udev_device_get_usec_initialized(event->dev_db) > 0)
                        udev_device_set_usec_initialized(event->dev, udev_device_get_usec_initialized(event->dev_db));
                else if (udev_device_get_usec_initialized(event->dev) == 0)
                        udev_device_set_usec_initialized(event->dev, now(CLOCK_MONOTONIC));

                /* (re)write database file */
                udev_device_update_db(dev);
                udev_device_tag_index(dev, event->dev_db, true);
                udev_device_set_is_initialized(dev);

                udev_device_unref(event->dev_db);
                event->dev_db = NULL;
        }
}

void udev_event_execute_run(struct udev_event *event, const sigset_t *sigmask)
{
        struct udev_list_entry *list_entry;

        udev_list_entry_foreach(list_entry, udev_list_get_entry(&event->run_list)) {
                const char *cmd = udev_list_entry_get_name(list_entry);
                enum udev_builtin_cmd builtin_cmd = udev_list_entry_get_num(list_entry);

                if (builtin_cmd < UDEV_BUILTIN_MAX) {
                        char command[UTIL_PATH_SIZE];

                        udev_event_apply_format(event, cmd, command, sizeof(command));
                        udev_builtin_run(event->dev, builtin_cmd, command, false);
                } else {
                        char program[UTIL_PATH_SIZE];
                        char **envp;

                        if (event->exec_delay > 0) {
                                log_debug("delay execution of '%s'", program);
                                sleep(event->exec_delay);
                        }

                        udev_event_apply_format(event, cmd, program, sizeof(program));
                        envp = udev_device_get_properties_envp(event->dev);
                        udev_event_spawn(event, program, envp, sigmask, NULL, 0);
                }
        }
}
