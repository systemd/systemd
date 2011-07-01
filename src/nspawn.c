/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include <signal.h>
#include <sched.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/syscall.h>
#include <sys/mount.h>
#include <sys/wait.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include <sys/prctl.h>
#include <sys/capability.h>
#include <getopt.h>
#include <sys/epoll.h>
#include <termios.h>
#include <sys/signalfd.h>
#include <grp.h>

#include "log.h"
#include "util.h"
#include "missing.h"
#include "cgroup-util.h"
#include "sd-daemon.h"
#include "strv.h"

static char *arg_directory = NULL;
static char *arg_user = NULL;

static int help(void) {

        printf("%s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "Spawn a minimal namespace container for debugging, testing and building.\n\n"
               "  -h --help            Show this help\n"
               "  -D --directory=NAME  Root directory for the container\n"
               "  -u --user=USER       Run the command under specified user or uid\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h' },
                { "directory", required_argument, NULL, 'D' },
                { "user",      optional_argument, NULL, 'u' },
                { NULL,        0,                 NULL, 0   }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:u:", options, NULL)) >= 0) {

                switch (c) {

                case 'h':
                        help();
                        return 0;

                case 'D':
                        free(arg_directory);
                        if (!(arg_directory = strdup(optarg))) {
                                log_error("Failed to duplicate root directory.");
                                return -ENOMEM;
                        }

                        break;

                case 'u':
                        free(arg_user);
                        if (!(arg_user = strdup(optarg))) {
                                log_error("Failed to duplicate user name.");
                                return -ENOMEM;
                        }

                        break;

                case '?':
                        return -EINVAL;

                default:
                        log_error("Unknown option code %c", c);
                        return -EINVAL;
                }
        }

        return 1;
}

static int mount_all(const char *dest) {

        typedef struct MountPoint {
                const char *what;
                const char *where;
                const char *type;
                const char *options;
                unsigned long flags;
                bool fatal;
        } MountPoint;

        static const MountPoint mount_table[] = {
                { "proc",      "/proc",     "proc",      NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV, true },
                { "/proc/sys", "/proc/sys", "bind",      NULL,        MS_BIND, true },                      /* Bind mount first */
                { "/proc/sys", "/proc/sys", "bind",      NULL,        MS_BIND|MS_RDONLY|MS_REMOUNT, true }, /* Then, make it r/o */
                { "sysfs",     "/sys",      "sysfs",     NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, true },
                { "tmpfs",     "/dev",      "tmpfs",     "mode=755",  MS_NOSUID, true },
                { "/dev/pts",  "/dev/pts",  "bind",      NULL,        MS_BIND, true },
                { "tmpfs",     "/run",      "tmpfs",     "mode=755",  MS_NOSUID|MS_NODEV, true },
#ifdef HAVE_SELINUX
                { "selinux",   "/selinux",  "selinuxfs", NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY, false },
#endif
        };

        unsigned k;
        int r = 0;
        char *where;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                int t;

                if (asprintf(&where, "%s/%s", dest, mount_table[k].where) < 0) {
                        log_error("Out of memory");

                        if (r == 0)
                                r = -ENOMEM;

                        break;
                }

                if ((t = path_is_mount_point(where)) < 0) {
                        log_error("Failed to detect whether %s is a mount point: %s", where, strerror(-t));
                        free(where);

                        if (r == 0)
                                r = t;

                        continue;
                }

                mkdir_p(where, 0755);

                if (mount(mount_table[k].what,
                          where,
                          mount_table[k].type,
                          mount_table[k].flags,
                          mount_table[k].options) < 0 &&
                    mount_table[k].fatal) {

                        log_error("mount(%s) failed: %m", where);

                        if (r == 0)
                                r = -errno;
                }

                free(where);
        }

        /* Fix the timezone, if possible */
        if (asprintf(&where, "%s/%s", dest, "/etc/localtime") >= 0) {
                mount("/etc/localtime", where, "bind", MS_BIND, NULL);
                mount("/etc/localtime", where, "bind", MS_BIND|MS_REMOUNT|MS_RDONLY, NULL);
                free(where);
        }

        return r;
}

static int copy_devnodes(const char *dest, const char *console) {

        static const char devnodes[] =
                "null\0"
                "zero\0"
                "full\0"
                "random\0"
                "urandom\0"
                "tty\0"
                "ptmx\0"
                "kmsg\0"
                "rtc0\0";

        const char *d;
        int r = 0, k;
        mode_t u;
        struct stat st;
        char *from = NULL, *to = NULL;

        assert(dest);
        assert(console);

        u = umask(0000);

        NULSTR_FOREACH(d, devnodes) {
                from = to = NULL;

                asprintf(&from, "/dev/%s", d);
                asprintf(&to, "%s/dev/%s", dest, d);

                if (!from || !to) {
                        log_error("Failed to allocate devnode path");

                        free(from);
                        free(to);

                        from = to = NULL;

                        if (r == 0)
                                r = -ENOMEM;

                        break;
                }

                if (stat(from, &st) < 0) {

                        if (errno != ENOENT) {
                                log_error("Failed to stat %s: %m", from);
                                if (r == 0)
                                        r = -errno;
                        }

                } else if (!S_ISCHR(st.st_mode) && !S_ISBLK(st.st_mode)) {

                        log_error("%s is not a char or block device, cannot copy.", from);
                        if (r == 0)
                                r = -EIO;

                } else if (mknod(to, st.st_mode, st.st_rdev) < 0) {

                        log_error("mknod(%s) failed: %m", dest);
                        if (r == 0)
                                r = -errno;
                }

                free(from);
                free(to);
        }

        if (stat(console, &st) < 0) {

                log_error("Failed to stat %s: %m", console);
                if (r == 0)
                        r = -errno;

                goto finish;

        } else if (!S_ISCHR(st.st_mode)) {

                log_error("/dev/console is not a char device.");
                if (r == 0)
                        r = -EIO;

                goto finish;
        }

        if (asprintf(&to, "%s/dev/console", dest) < 0) {

                log_error("Out of memory");
                if (r == 0)
                        r = -ENOMEM;

                 goto finish;
        }

        /* We need to bind mount the right tty to /dev/console since
         * ptys can only exist on pts file systems. To have something
         * to bind mount things on we create a device node first, that
         * has the right major/minor (note that the major minor
         * doesn't actually matter here, since we mount it over
         * anyway). */

        if (mknod(to, (st.st_mode & ~07777) | 0600, st.st_rdev) < 0)
                log_error("mknod for /dev/console failed: %m");

        if (mount(console, to, "bind", MS_BIND, NULL) < 0) {
                log_error("bind mount for /dev/console failed: %m");

                if (r == 0)
                        r = -errno;
        }

        free(to);

        if ((k = chmod_and_chown(console, 0600, 0, 0)) < 0) {
                log_error("Failed to correct access mode for TTY: %s", strerror(-k));

                if (r == 0)
                        r = k;
        }

finish:

        umask(u);

        return r;
}

static int drop_capabilities(void) {
        static const unsigned long retain[] = {
                CAP_CHOWN,
                CAP_DAC_OVERRIDE,
                CAP_DAC_READ_SEARCH,
                CAP_FOWNER,
                CAP_FSETID,
                CAP_IPC_OWNER,
                CAP_KILL,
                CAP_LEASE,
                CAP_LINUX_IMMUTABLE,
                CAP_NET_BIND_SERVICE,
                CAP_NET_BROADCAST,
                CAP_NET_RAW,
                CAP_SETGID,
                CAP_SETFCAP,
                CAP_SETPCAP,
                CAP_SETUID,
                CAP_SYS_ADMIN,
                CAP_SYS_CHROOT,
                CAP_SYS_NICE,
                CAP_SYS_PTRACE,
                CAP_SYS_TTY_CONFIG
        };

        unsigned long l;

        for (l = 0; l <= MAX(63LU, (unsigned long) CAP_LAST_CAP); l++) {
                unsigned i;

                for (i = 0; i < ELEMENTSOF(retain); i++)
                        if (retain[i] == l)
                                break;

                if (i < ELEMENTSOF(retain))
                        continue;

                if (prctl(PR_CAPBSET_DROP, l) < 0) {

                        /* If this capability is not known, EINVAL
                         * will be returned, let's ignore this. */
                        if (errno == EINVAL)
                                break;

                        log_error("PR_CAPBSET_DROP failed: %m");
                        return -errno;
                }
        }

        return 0;
}

static int is_os_tree(const char *path) {
        int r;
        char *p;
        /* We use /bin/sh as flag file if something is an OS */

        if (asprintf(&p, "%s/bin/sh", path) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        return r < 0 ? 0 : 1;
}

#define BUFFER_SIZE 1024

static int process_pty(int master, sigset_t *mask) {

        char in_buffer[BUFFER_SIZE], out_buffer[BUFFER_SIZE];
        size_t in_buffer_full = 0, out_buffer_full = 0;
        struct epoll_event stdin_ev, stdout_ev, master_ev, signal_ev;
        bool stdin_readable = false, stdout_writable = false, master_readable = false, master_writable = false;
        int ep = -1, signal_fd = -1, r;

        fd_nonblock(STDIN_FILENO, 1);
        fd_nonblock(STDOUT_FILENO, 1);
        fd_nonblock(master, 1);

        if ((signal_fd = signalfd(-1, mask, SFD_NONBLOCK|SFD_CLOEXEC)) < 0) {
                log_error("signalfd(): %m");
                r = -errno;
                goto finish;
        }

        if ((ep = epoll_create1(EPOLL_CLOEXEC)) < 0) {
                log_error("Failed to create epoll: %m");
                r = -errno;
                goto finish;
        }

        zero(stdin_ev);
        stdin_ev.events = EPOLLIN|EPOLLET;
        stdin_ev.data.fd = STDIN_FILENO;

        zero(stdout_ev);
        stdout_ev.events = EPOLLOUT|EPOLLET;
        stdout_ev.data.fd = STDOUT_FILENO;

        zero(master_ev);
        master_ev.events = EPOLLIN|EPOLLOUT|EPOLLET;
        master_ev.data.fd = master;

        zero(signal_ev);
        signal_ev.events = EPOLLIN;
        signal_ev.data.fd = signal_fd;

        if (epoll_ctl(ep, EPOLL_CTL_ADD, STDIN_FILENO, &stdin_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, STDOUT_FILENO, &stdout_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, master, &master_ev) < 0 ||
            epoll_ctl(ep, EPOLL_CTL_ADD, signal_fd, &signal_ev) < 0) {
                log_error("Failed to regiser fds in epoll: %m");
                r = -errno;
                goto finish;
        }

        for (;;) {
                struct epoll_event ev[16];
                ssize_t k;
                int i, nfds;

                if ((nfds = epoll_wait(ep, ev, ELEMENTSOF(ev), -1)) < 0) {

                        if (errno == EINTR || errno == EAGAIN)
                                continue;

                        log_error("epoll_wait(): %m");
                        r = -errno;
                        goto finish;
                }

                assert(nfds >= 1);

                for (i = 0; i < nfds; i++) {
                        if (ev[i].data.fd == STDIN_FILENO) {

                                if (ev[i].events & (EPOLLIN|EPOLLHUP))
                                        stdin_readable = true;

                        } else if (ev[i].data.fd == STDOUT_FILENO) {

                                if (ev[i].events & (EPOLLOUT|EPOLLHUP))
                                        stdout_writable = true;

                        } else if (ev[i].data.fd == master) {

                                if (ev[i].events & (EPOLLIN|EPOLLHUP))
                                        master_readable = true;

                                if (ev[i].events & (EPOLLOUT|EPOLLHUP))
                                        master_writable = true;

                        } else if (ev[i].data.fd == signal_fd) {
                                struct signalfd_siginfo sfsi;
                                ssize_t n;

                                if ((n = read(signal_fd, &sfsi, sizeof(sfsi))) != sizeof(sfsi)) {

                                        if (n >= 0) {
                                                log_error("Failed to read from signalfd: invalid block size");
                                                r = -EIO;
                                                goto finish;
                                        }

                                        if (errno != EINTR && errno != EAGAIN) {
                                                log_error("Failed to read from signalfd: %m");
                                                r = -errno;
                                                goto finish;
                                        }
                                } else {

                                        if (sfsi.ssi_signo == SIGWINCH) {
                                                struct winsize ws;

                                                /* The window size changed, let's forward that. */
                                                if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0)
                                                        ioctl(master, TIOCSWINSZ, &ws);
                                        } else {
                                                r = 0;
                                                goto finish;
                                        }
                                }
                        }
                }

                while ((stdin_readable && in_buffer_full <= 0) ||
                       (master_writable && in_buffer_full > 0) ||
                       (master_readable && out_buffer_full <= 0) ||
                       (stdout_writable && out_buffer_full > 0)) {

                        if (stdin_readable && in_buffer_full < BUFFER_SIZE) {

                                if ((k = read(STDIN_FILENO, in_buffer + in_buffer_full, BUFFER_SIZE - in_buffer_full)) < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                stdin_readable = false;
                                        else {
                                                log_error("read(): %m");
                                                r = -errno;
                                                goto finish;
                                        }
                                } else
                                        in_buffer_full += (size_t) k;
                        }

                        if (master_writable && in_buffer_full > 0) {

                                if ((k = write(master, in_buffer, in_buffer_full)) < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                master_writable = false;
                                        else {
                                                log_error("write(): %m");
                                                r = -errno;
                                                goto finish;
                                        }

                                } else {
                                        assert(in_buffer_full >= (size_t) k);
                                        memmove(in_buffer, in_buffer + k, in_buffer_full - k);
                                        in_buffer_full -= k;
                                }
                        }

                        if (master_readable && out_buffer_full < BUFFER_SIZE) {

                                if ((k = read(master, out_buffer + out_buffer_full, BUFFER_SIZE - out_buffer_full)) < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                master_readable = false;
                                        else {
                                                log_error("read(): %m");
                                                r = -errno;
                                                goto finish;
                                        }
                                }  else
                                        out_buffer_full += (size_t) k;
                        }

                        if (stdout_writable && out_buffer_full > 0) {

                                if ((k = write(STDOUT_FILENO, out_buffer, out_buffer_full)) < 0) {

                                        if (errno == EAGAIN || errno == EPIPE || errno == ECONNRESET || errno == EIO)
                                                stdout_writable = false;
                                        else {
                                                log_error("write(): %m");
                                                r = -errno;
                                                goto finish;
                                        }

                                } else {
                                        assert(out_buffer_full >= (size_t) k);
                                        memmove(out_buffer, out_buffer + k, out_buffer_full - k);
                                        out_buffer_full -= k;
                                }
                        }
                }
        }

finish:
        if (ep >= 0)
                close_nointr_nofail(ep);

        if (signal_fd >= 0)
                close_nointr_nofail(signal_fd);

        return r;
}

int main(int argc, char *argv[]) {
        pid_t pid = 0;
        int r = EXIT_FAILURE, k;
        char *oldcg = NULL, *newcg = NULL;
        int master = -1;
        const char *console = NULL;
        struct termios saved_attr, raw_attr;
        sigset_t mask;
        bool saved_attr_valid = false;
        struct winsize ws;

        log_parse_environment();
        log_open();

        if ((r = parse_argv(argc, argv)) <= 0)
                goto finish;

        if (arg_directory) {
                char *p;

                p = path_make_absolute_cwd(arg_directory);
                free(arg_directory);
                arg_directory = p;
        } else
                arg_directory = get_current_dir_name();

        if (!arg_directory) {
                log_error("Failed to determine path");
                goto finish;
        }

        path_kill_slashes(arg_directory);

        if (geteuid() != 0) {
                log_error("Need to be root.");
                goto finish;
        }

        if (sd_booted() <= 0) {
                log_error("Not running on a systemd system.");
                goto finish;
        }

        if (path_equal(arg_directory, "/")) {
                log_error("Spawning container on root directory not supported.");
                goto finish;
        }

        if (is_os_tree(arg_directory) <= 0) {
                log_error("Directory %s doesn't look like an OS root directory. Refusing.", arg_directory);
                goto finish;
        }

        if ((k = cg_get_by_pid(SYSTEMD_CGROUP_CONTROLLER, 0, &oldcg)) < 0) {
                log_error("Failed to determine current cgroup: %s", strerror(-k));
                goto finish;
        }

        if (asprintf(&newcg, "%s/nspawn-%lu", oldcg, (unsigned long) getpid()) < 0) {
                log_error("Failed to allocate cgroup path.");
                goto finish;
        }

        if ((k = cg_create_and_attach(SYSTEMD_CGROUP_CONTROLLER, newcg, 0)) < 0)  {
                log_error("Failed to create cgroup: %s", strerror(-k));
                goto finish;
        }

        if ((master = posix_openpt(O_RDWR|O_NOCTTY|O_CLOEXEC|O_NDELAY)) < 0) {
                log_error("Failed to acquire pseudo tty: %m");
                goto finish;
        }

        if (!(console = ptsname(master))) {
                log_error("Failed to determine tty name: %m");
                goto finish;
        }

        log_info("Spawning namespace container on %s (console is %s).", arg_directory, console);

        if (ioctl(STDIN_FILENO, TIOCGWINSZ, &ws) >= 0)
                ioctl(master, TIOCSWINSZ, &ws);

        if (unlockpt(master) < 0) {
                log_error("Failed to unlock tty: %m");
                goto finish;
        }

        if (tcgetattr(STDIN_FILENO, &saved_attr) < 0) {
                log_error("Failed to get terminal attributes: %m");
                goto finish;
        }

        saved_attr_valid = true;

        raw_attr = saved_attr;
        cfmakeraw(&raw_attr);
        raw_attr.c_lflag &= ~ECHO;

        if (tcsetattr(STDIN_FILENO, TCSANOW, &raw_attr) < 0) {
                log_error("Failed to set terminal attributes: %m");
                goto finish;
        }

        assert_se(sigemptyset(&mask) == 0);
        sigset_add_many(&mask, SIGCHLD, SIGWINCH, SIGTERM, SIGINT, -1);
        assert_se(sigprocmask(SIG_BLOCK, &mask, NULL) == 0);

        if ((pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS, NULL)) < 0) {
                log_error("clone() failed: %m");
                goto finish;
        }

        if (pid == 0) {
                /* child */

                const char *hn;
                const char *home = NULL;
                uid_t uid = (uid_t) -1;
                gid_t gid = (gid_t) -1;
                const char *envp[] = {
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        NULL, /* TERM */
                        NULL, /* HOME */
                        NULL, /* USER */
                        NULL, /* LOGNAME */
                        NULL
                };

                envp[1] = strv_find_prefix(environ, "TERM=");

                close_nointr_nofail(master);

                close_nointr(STDIN_FILENO);
                close_nointr(STDOUT_FILENO);
                close_nointr(STDERR_FILENO);

                close_all_fds(NULL, 0);

                reset_all_signal_handlers();

                assert_se(sigemptyset(&mask) == 0);
                assert_se(sigprocmask(SIG_SETMASK, &mask, NULL) == 0);

                if (setsid() < 0)
                        goto child_fail;

                if (prctl(PR_SET_PDEATHSIG, SIGKILL) < 0)
                        goto child_fail;

                if (mount_all(arg_directory) < 0)
                        goto child_fail;

                if (copy_devnodes(arg_directory, console) < 0)
                        goto child_fail;

                if (chdir(arg_directory) < 0) {
                        log_error("chdir(%s) failed: %m", arg_directory);
                        goto child_fail;
                }

                if (open_terminal("dev/console", O_RDWR) != STDIN_FILENO ||
                    dup2(STDIN_FILENO, STDOUT_FILENO) != STDOUT_FILENO ||
                    dup2(STDIN_FILENO, STDERR_FILENO) != STDERR_FILENO)
                        goto child_fail;

                if (mount(arg_directory, "/", "bind", MS_BIND|MS_MOVE, NULL) < 0) {
                        log_error("mount(MS_MOVE) failed: %m");
                        goto child_fail;
                }

                if (chroot(".") < 0) {
                        log_error("chroot() failed: %m");
                        goto child_fail;
                }

                if (chdir("/") < 0) {
                        log_error("chdir() failed: %m");
                        goto child_fail;
                }

                umask(0002);

                if (drop_capabilities() < 0)
                        goto child_fail;

                if (arg_user) {

                        if (get_user_creds((const char**)&arg_user, &uid, &gid, &home) < 0) {
                                log_error("get_user_creds() failed: %m");
                                goto child_fail;
                        }

                        if (mkdir_parents(home, 0775) < 0) {
                                log_error("mkdir_parents() failed: %m");
                                goto child_fail;
                        }

                        if (safe_mkdir(home, 0775, uid, gid) < 0) {
                                log_error("safe_mkdir() failed: %m");
                                goto child_fail;
                        }

                        if (initgroups((const char*)arg_user, gid) < 0) {
                                log_error("initgroups() failed: %m");
                                goto child_fail;
                        }

                        if (setresgid(gid, gid, gid) < 0) {
                                log_error("setregid() failed: %m");
                                goto child_fail;
                        }

                        if (setresuid(uid, uid, uid) < 0) {
                                log_error("setreuid() failed: %m");
                                goto child_fail;
                        }
                }

                if ((asprintf((char**)(envp + 2), "HOME=%s", home? home: "/root") < 0) ||
                    (asprintf((char**)(envp + 3), "USER=%s", arg_user? arg_user : "root") < 0) ||
                    (asprintf((char**)(envp + 4), "LOGNAME=%s", arg_user? arg_user : "root") < 0)) {
                    log_error("Out of memory");
                    goto child_fail;
                }

                if ((hn = file_name_from_path(arg_directory)))
                        sethostname(hn, strlen(hn));

                if (argc > optind)
                        execvpe(argv[optind], argv + optind, (char**) envp);
                else {
                        chdir(home ? home : "/root");
                        execle("/bin/bash", "-bash", NULL, (char**) envp);
                }

                log_error("execv() failed: %m");

        child_fail:
                _exit(EXIT_FAILURE);
        }

        if (process_pty(master, &mask) < 0)
                goto finish;

        if (saved_attr_valid) {
                tcsetattr(STDIN_FILENO, TCSANOW, &saved_attr);
                saved_attr_valid = false;
        }

        r = wait_for_terminate_and_warn(argc > optind ? argv[optind] : "bash", pid);

        if (r < 0)
                r = EXIT_FAILURE;

finish:
        if (saved_attr_valid)
                tcsetattr(STDIN_FILENO, TCSANOW, &saved_attr);

        if (master >= 0)
                close_nointr_nofail(master);

        if (oldcg)
                cg_attach(SYSTEMD_CGROUP_CONTROLLER, oldcg, 0);

        if (newcg)
                cg_kill_recursive_and_wait(SYSTEMD_CGROUP_CONTROLLER, newcg, true);

        free(arg_directory);
        free(oldcg);
        free(newcg);

        return r;
}
