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

#include "log.h"
#include "util.h"
#include "missing.h"

static char *arg_directory = NULL;

static int help(void) {

        printf("%s [OPTIONS...] [PATH] [ARGUMENTS...]\n\n"
               "Spawn a minimal namespace container for debugging, testing and building.\n\n"
               "  -h --help            Show this help\n"
               "  -D --directory=NAME  Root directory for the container\n",
               program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        static const struct option options[] = {
                { "help",      no_argument,       NULL, 'h' },
                { "directory", required_argument, NULL, 'D' },
                { NULL,        0,                 NULL, 0   }
        };

        int c;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "+hD:", options, NULL)) >= 0) {

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
        } MountPoint;

        static const MountPoint mount_table[] = {
                { "proc",      "/proc",     "proc",   NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV },
                { "/proc/sys", "/proc/sys", "bind",   NULL,        MS_BIND },                      /* Bind mount first */
                { "/proc/sys", "/proc/sys", "bind",   NULL,        MS_BIND|MS_RDONLY|MS_REMOUNT }, /* Then, make it r/o */
                { "sysfs",     "/sys",      "sysfs",  NULL,        MS_NOSUID|MS_NOEXEC|MS_NODEV|MS_RDONLY },
                { "tmpfs",     "/dev",      "tmpfs",  "mode=755",  MS_NOSUID },
                { "/dev/pts",  "/dev/pts",  "bind",   NULL,        MS_BIND },
                { "tmpfs",     "/dev/.run", "tmpfs",  "mode=755",  MS_NOSUID|MS_NOEXEC|MS_NODEV },
        };

        unsigned k;
        int r = 0;

        for (k = 0; k < ELEMENTSOF(mount_table); k++) {
                char *where;
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
                          mount_table[k].options) < 0) {

                        log_error("mount(%s) failed: %m", where);

                        if (r == 0)
                                r = -errno;
                }

                free(where);
        }

        return r;
}

static int copy_devnodes(const char *dest) {

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
        char *tty = NULL;
        dev_t tty_devnum;
        mode_t u;

        u = umask(0000);

        NULSTR_FOREACH(d, devnodes) {
                char *from = NULL, *to = NULL;
                struct stat st;

                asprintf(&from, "/dev/%s", d);
                asprintf(&to, "%s/dev/%s", dest, d);

                if (!from || !to) {
                        log_error("Failed to allocate devnode path");

                        free(from);
                        free(to);

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

                } else {
                        if (mknod(to, st.st_mode, st.st_rdev) < 0) {
                                log_error("mknod(%s) failed: %m", dest);

                                if (r == 0)
                                        r = -errno;
                        }
                }

                free(from);
                free(to);
        }

        if ((k = get_ctty(&tty, &tty_devnum)) < 0) {
                log_error("Failed to determine controlling tty: %s", strerror(-k));

                if (r == 0)
                        r = k;
        } else {
                char *from = NULL, *to = NULL;

                asprintf(&from, "/dev/%s", tty);
                asprintf(&to, "%s/dev/console", dest);

                if (!from || !to) {
                        log_error("Out of memory");

                        if (r == 0)
                                r = k;
                } else {
                        /* We need to bind mount our own tty on
                         * /dev/console, since ptys cannot be used
                         * unless on a devpts file system. But to bind
                         * mount it we first have to create a device
                         * node where we can bind mount it on. This is
                         * kinda ugly since the TTY will very likely
                         * be owned by a user/group that does not
                         * exist in the container. */

                        if (mknod(to, S_IFCHR|0600, tty_devnum) < 0) {
                                log_error("mknod for /dev/console failed: %m");

                                if (r == 0)
                                        r = -errno;
                        }

                        if (mount(from, to, "bind", MS_BIND, NULL) < 0) {
                                log_error("bind mount for /dev/console failed: %m");

                                if (r == 0)
                                        r = -errno;
                        }
                }

                free(from);
                free(to);
        }

        free(tty);

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

        for (l = 0; l <= MAX(63LU, (unsigned long) CAP_LAST_CAP); l ++) {
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
                                continue;

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


int main(int argc, char *argv[]) {
        pid_t pid = 0;
        int r = EXIT_FAILURE;

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

        if (path_equal(arg_directory, "/")) {
                log_error("Spawning container on root directory not supported.");
                goto finish;
        }

        if (is_os_tree(arg_directory) <= 0) {
                log_error("Directory %s doesn't look like an OS root directory. Refusing.", arg_directory);
                goto finish;
        }

        log_info("Spawning namespace container on %s.", arg_directory);

        if ((pid = syscall(__NR_clone, SIGCHLD|CLONE_NEWIPC|CLONE_NEWNS|CLONE_NEWPID|CLONE_NEWUTS|CLONE_NEWNET, NULL)) < 0) {
                log_error("clone() failed: %m");
                goto finish;
        }

        if (pid == 0) {
                const char *hn;
                const char *envp[] = {
                        "HOME=/root",
                        "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
                        NULL
                };

                /* child */

                if (mount_all(arg_directory) < 0)
                        goto child_fail;

                if (copy_devnodes(arg_directory) < 0)
                        goto child_fail;

                if (chdir(arg_directory) < 0) {
                        log_error("chdir(%s) failed: %m", arg_directory);
                        goto child_fail;
                }
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

                if (drop_capabilities() < 0)
                        goto child_fail;

                if ((hn = file_name_from_path(arg_directory)))
                        sethostname(hn, strlen(hn));

                if (argc > optind)
                        execvpe(argv[optind], argv + optind, (char**) envp);
                else {
                        chdir("/root");
                        execle("/bin/bash", "-bash", NULL, (char**) envp);
                }

                log_error("execv() failed: %m");

        child_fail:
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate_and_warn(argc > optind ? argv[optind] : "bash", pid);

        if (r < 0)
                r = EXIT_FAILURE;

finish:
        free(arg_directory);

        if (pid > 0)
                kill(pid, SIGTERM);

        return r;
}
