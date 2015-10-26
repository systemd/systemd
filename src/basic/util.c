/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <glob.h>
#include <grp.h>
#include <langinfo.h>
#include <libintl.h>
#include <limits.h>
#include <linux/magic.h>
#include <linux/oom.h>
#include <linux/sched.h>
#include <locale.h>
#include <poll.h>
#include <pwd.h>
#include <sched.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/mman.h>
#include <sys/mount.h>
#include <sys/personality.h>
#include <sys/prctl.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <sys/vfs.h>
#include <sys/wait.h>
#include <syslog.h>
#include <unistd.h>

/* When we include libgen.h because we need dirname() we immediately
 * undefine basename() since libgen.h defines it as a macro to the
 * POSIX version which is really broken. We prefer GNU basename(). */
#include <libgen.h>
#undef basename

#ifdef HAVE_SYS_AUXV_H
#include <sys/auxv.h>
#endif

/* We include linux/fs.h as last of the system headers, as it
 * otherwise conflicts with sys/mount.h. Yay, Linux is great! */
#include <linux/fs.h>

#include "build.h"
#include "def.h"
#include "device-nodes.h"
#include "env-util.h"
#include "escape.h"
#include "exit-status.h"
#include "fd-util.h"
#include "fileio.h"
#include "formats-util.h"
#include "gunicode.h"
#include "hashmap.h"
#include "hostname-util.h"
#include "ioprio.h"
#include "log.h"
#include "macro.h"
#include "missing.h"
#include "mkdir.h"
#include "hexdecoct.h"
#include "parse-util.h"
#include "path-util.h"
#include "process-util.h"
#include "random-util.h"
#include "signal-util.h"
#include "sparse-endian.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "utf8.h"
#include "util.h"
#include "virt.h"
#include "dirent-util.h"
#include "stat-util.h"

/* Put this test here for a lack of better place */
assert_cc(EAGAIN == EWOULDBLOCK);

int saved_argc = 0;
char **saved_argv = NULL;

size_t page_size(void) {
        static thread_local size_t pgsz = 0;
        long r;

        if (_likely_(pgsz > 0))
                return pgsz;

        r = sysconf(_SC_PAGESIZE);
        assert(r > 0);

        pgsz = (size_t) r;
        return pgsz;
}

bool fstype_is_network(const char *fstype) {
        static const char table[] =
                "afs\0"
                "cifs\0"
                "smbfs\0"
                "sshfs\0"
                "ncpfs\0"
                "ncp\0"
                "nfs\0"
                "nfs4\0"
                "gfs\0"
                "gfs2\0"
                "glusterfs\0";

        const char *x;

        x = startswith(fstype, "fuse.");
        if (x)
                fstype = x;

        return nulstr_contains(table, fstype);
}

void rename_process(const char name[8]) {
        assert(name);

        /* This is a like a poor man's setproctitle(). It changes the
         * comm field, argv[0], and also the glibc's internally used
         * name of the process. For the first one a limit of 16 chars
         * applies, to the second one usually one of 10 (i.e. length
         * of "/sbin/init"), to the third one one of 7 (i.e. length of
         * "systemd"). If you pass a longer string it will be
         * truncated */

        prctl(PR_SET_NAME, name);

        if (program_invocation_name)
                strncpy(program_invocation_name, name, strlen(program_invocation_name));

        if (saved_argc > 0) {
                int i;

                if (saved_argv[0])
                        strncpy(saved_argv[0], name, strlen(saved_argv[0]));

                for (i = 1; i < saved_argc; i++) {
                        if (!saved_argv[i])
                                break;

                        memzero(saved_argv[i], strlen(saved_argv[i]));
                }
        }
}

int running_in_chroot(void) {
        int ret;

        ret = files_same("/proc/1/root", "/");
        if (ret < 0)
                return ret;

        return ret == 0;
}

noreturn void freeze(void) {

        /* Make sure nobody waits for us on a socket anymore */
        close_all_fds(NULL, 0);

        sync();

        for (;;)
                pause();
}

static int do_execute(char **directories, usec_t timeout, char *argv[]) {
        _cleanup_hashmap_free_free_ Hashmap *pids = NULL;
        _cleanup_set_free_free_ Set *seen = NULL;
        char **directory;

        /* We fork this all off from a child process so that we can
         * somewhat cleanly make use of SIGALRM to set a time limit */

        (void) reset_all_signal_handlers();
        (void) reset_signal_mask();

        assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

        pids = hashmap_new(NULL);
        if (!pids)
                return log_oom();

        seen = set_new(&string_hash_ops);
        if (!seen)
                return log_oom();

        STRV_FOREACH(directory, directories) {
                _cleanup_closedir_ DIR *d;
                struct dirent *de;

                d = opendir(*directory);
                if (!d) {
                        if (errno == ENOENT)
                                continue;

                        return log_error_errno(errno, "Failed to open directory %s: %m", *directory);
                }

                FOREACH_DIRENT(de, d, break) {
                        _cleanup_free_ char *path = NULL;
                        pid_t pid;
                        int r;

                        if (!dirent_is_file(de))
                                continue;

                        if (set_contains(seen, de->d_name)) {
                                log_debug("%1$s/%2$s skipped (%2$s was already seen).", *directory, de->d_name);
                                continue;
                        }

                        r = set_put_strdup(seen, de->d_name);
                        if (r < 0)
                                return log_oom();

                        path = strjoin(*directory, "/", de->d_name, NULL);
                        if (!path)
                                return log_oom();

                        if (null_or_empty_path(path)) {
                                log_debug("%s is empty (a mask).", path);
                                continue;
                        }

                        pid = fork();
                        if (pid < 0) {
                                log_error_errno(errno, "Failed to fork: %m");
                                continue;
                        } else if (pid == 0) {
                                char *_argv[2];

                                assert_se(prctl(PR_SET_PDEATHSIG, SIGTERM) == 0);

                                if (!argv) {
                                        _argv[0] = path;
                                        _argv[1] = NULL;
                                        argv = _argv;
                                } else
                                        argv[0] = path;

                                execv(path, argv);
                                return log_error_errno(errno, "Failed to execute %s: %m", path);
                        }

                        log_debug("Spawned %s as " PID_FMT ".", path, pid);

                        r = hashmap_put(pids, UINT_TO_PTR(pid), path);
                        if (r < 0)
                                return log_oom();
                        path = NULL;
                }
        }

        /* Abort execution of this process after the timout. We simply
         * rely on SIGALRM as default action terminating the process,
         * and turn on alarm(). */

        if (timeout != USEC_INFINITY)
                alarm((timeout + USEC_PER_SEC - 1) / USEC_PER_SEC);

        while (!hashmap_isempty(pids)) {
                _cleanup_free_ char *path = NULL;
                pid_t pid;

                pid = PTR_TO_UINT(hashmap_first_key(pids));
                assert(pid > 0);

                path = hashmap_remove(pids, UINT_TO_PTR(pid));
                assert(path);

                wait_for_terminate_and_warn(path, pid, true);
        }

        return 0;
}

void execute_directories(const char* const* directories, usec_t timeout, char *argv[]) {
        pid_t executor_pid;
        int r;
        char *name;
        char **dirs = (char**) directories;

        assert(!strv_isempty(dirs));

        name = basename(dirs[0]);
        assert(!isempty(name));

        /* Executes all binaries in the directories in parallel and waits
         * for them to finish. Optionally a timeout is applied. If a file
         * with the same name exists in more than one directory, the
         * earliest one wins. */

        executor_pid = fork();
        if (executor_pid < 0) {
                log_error_errno(errno, "Failed to fork: %m");
                return;

        } else if (executor_pid == 0) {
                r = do_execute(dirs, timeout, argv);
                _exit(r < 0 ? EXIT_FAILURE : EXIT_SUCCESS);
        }

        wait_for_terminate_and_warn(name, executor_pid, true);
}

bool plymouth_running(void) {
        return access("/run/plymouth/pid", F_OK) >= 0;
}

bool display_is_local(const char *display) {
        assert(display);

        return
                display[0] == ':' &&
                display[1] >= '0' &&
                display[1] <= '9';
}

int socket_from_display(const char *display, char **path) {
        size_t k;
        char *f, *c;

        assert(display);
        assert(path);

        if (!display_is_local(display))
                return -EINVAL;

        k = strspn(display+1, "0123456789");

        f = new(char, strlen("/tmp/.X11-unix/X") + k + 1);
        if (!f)
                return -ENOMEM;

        c = stpcpy(f, "/tmp/.X11-unix/X");
        memcpy(c, display+1, k);
        c[k] = 0;

        *path = f;

        return 0;
}

int glob_exists(const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;

        assert(path);

        errno = 0;
        k = glob(path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);

        if (k == GLOB_NOMATCH)
                return 0;
        else if (k == GLOB_NOSPACE)
                return -ENOMEM;
        else if (k == 0)
                return !strv_isempty(g.gl_pathv);
        else
                return errno ? -errno : -EIO;
}

int glob_extend(char ***strv, const char *path) {
        _cleanup_globfree_ glob_t g = {};
        int k;
        char **p;

        errno = 0;
        k = glob(path, GLOB_NOSORT|GLOB_BRACE, NULL, &g);

        if (k == GLOB_NOMATCH)
                return -ENOENT;
        else if (k == GLOB_NOSPACE)
                return -ENOMEM;
        else if (k != 0 || strv_isempty(g.gl_pathv))
                return errno ? -errno : -EIO;

        STRV_FOREACH(p, g.gl_pathv) {
                k = strv_extend(strv, *p);
                if (k < 0)
                        break;
        }

        return k;
}

bool is_main_thread(void) {
        static thread_local int cached = 0;

        if (_unlikely_(cached == 0))
                cached = getpid() == gettid() ? 1 : -1;

        return cached > 0;
}

int block_get_whole_disk(dev_t d, dev_t *ret) {
        char *p, *s;
        int r;
        unsigned n, m;

        assert(ret);

        /* If it has a queue this is good enough for us */
        if (asprintf(&p, "/sys/dev/block/%u:%u/queue", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r >= 0) {
                *ret = d;
                return 0;
        }

        /* If it is a partition find the originating device */
        if (asprintf(&p, "/sys/dev/block/%u:%u/partition", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r < 0)
                return -ENOENT;

        /* Get parent dev_t */
        if (asprintf(&p, "/sys/dev/block/%u:%u/../dev", major(d), minor(d)) < 0)
                return -ENOMEM;

        r = read_one_line_file(p, &s);
        free(p);

        if (r < 0)
                return r;

        r = sscanf(s, "%u:%u", &m, &n);
        free(s);

        if (r != 2)
                return -EINVAL;

        /* Only return this if it is really good enough for us. */
        if (asprintf(&p, "/sys/dev/block/%u:%u/queue", m, n) < 0)
                return -ENOMEM;

        r = access(p, F_OK);
        free(p);

        if (r >= 0) {
                *ret = makedev(m, n);
                return 0;
        }

        return -ENOENT;
}

static const char *const ioprio_class_table[] = {
        [IOPRIO_CLASS_NONE] = "none",
        [IOPRIO_CLASS_RT] = "realtime",
        [IOPRIO_CLASS_BE] = "best-effort",
        [IOPRIO_CLASS_IDLE] = "idle"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(ioprio_class, int, INT_MAX);

static const char *const sigchld_code_table[] = {
        [CLD_EXITED] = "exited",
        [CLD_KILLED] = "killed",
        [CLD_DUMPED] = "dumped",
        [CLD_TRAPPED] = "trapped",
        [CLD_STOPPED] = "stopped",
        [CLD_CONTINUED] = "continued",
};

DEFINE_STRING_TABLE_LOOKUP(sigchld_code, int);

static const char *const log_facility_unshifted_table[LOG_NFACILITIES] = {
        [LOG_FAC(LOG_KERN)] = "kern",
        [LOG_FAC(LOG_USER)] = "user",
        [LOG_FAC(LOG_MAIL)] = "mail",
        [LOG_FAC(LOG_DAEMON)] = "daemon",
        [LOG_FAC(LOG_AUTH)] = "auth",
        [LOG_FAC(LOG_SYSLOG)] = "syslog",
        [LOG_FAC(LOG_LPR)] = "lpr",
        [LOG_FAC(LOG_NEWS)] = "news",
        [LOG_FAC(LOG_UUCP)] = "uucp",
        [LOG_FAC(LOG_CRON)] = "cron",
        [LOG_FAC(LOG_AUTHPRIV)] = "authpriv",
        [LOG_FAC(LOG_FTP)] = "ftp",
        [LOG_FAC(LOG_LOCAL0)] = "local0",
        [LOG_FAC(LOG_LOCAL1)] = "local1",
        [LOG_FAC(LOG_LOCAL2)] = "local2",
        [LOG_FAC(LOG_LOCAL3)] = "local3",
        [LOG_FAC(LOG_LOCAL4)] = "local4",
        [LOG_FAC(LOG_LOCAL5)] = "local5",
        [LOG_FAC(LOG_LOCAL6)] = "local6",
        [LOG_FAC(LOG_LOCAL7)] = "local7"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_facility_unshifted, int, LOG_FAC(~0));

bool log_facility_unshifted_is_valid(int facility) {
        return facility >= 0 && facility <= LOG_FAC(~0);
}

static const char *const log_level_table[] = {
        [LOG_EMERG] = "emerg",
        [LOG_ALERT] = "alert",
        [LOG_CRIT] = "crit",
        [LOG_ERR] = "err",
        [LOG_WARNING] = "warning",
        [LOG_NOTICE] = "notice",
        [LOG_INFO] = "info",
        [LOG_DEBUG] = "debug"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(log_level, int, LOG_DEBUG);

bool log_level_is_valid(int level) {
        return level >= 0 && level <= LOG_DEBUG;
}

static const char* const sched_policy_table[] = {
        [SCHED_OTHER] = "other",
        [SCHED_BATCH] = "batch",
        [SCHED_IDLE] = "idle",
        [SCHED_FIFO] = "fifo",
        [SCHED_RR] = "rr"
};

DEFINE_STRING_TABLE_LOOKUP_WITH_FALLBACK(sched_policy, int, INT_MAX);

bool kexec_loaded(void) {
       bool loaded = false;
       char *s;

       if (read_one_line_file("/sys/kernel/kexec_loaded", &s) >= 0) {
               if (s[0] == '1')
                       loaded = true;
               free(s);
       }
       return loaded;
}

int prot_from_flags(int flags) {

        switch (flags & O_ACCMODE) {

        case O_RDONLY:
                return PROT_READ;

        case O_WRONLY:
                return PROT_WRITE;

        case O_RDWR:
                return PROT_READ|PROT_WRITE;

        default:
                return -EINVAL;
        }
}

void* memdup(const void *p, size_t l) {
        void *r;

        assert(p);

        r = malloc(l);
        if (!r)
                return NULL;

        memcpy(r, p, l);
        return r;
}

int fork_agent(pid_t *pid, const int except[], unsigned n_except, const char *path, ...) {
        bool stdout_is_tty, stderr_is_tty;
        pid_t parent_pid, agent_pid;
        sigset_t ss, saved_ss;
        unsigned n, i;
        va_list ap;
        char **l;

        assert(pid);
        assert(path);

        /* Spawns a temporary TTY agent, making sure it goes away when
         * we go away */

        parent_pid = getpid();

        /* First we temporarily block all signals, so that the new
         * child has them blocked initially. This way, we can be sure
         * that SIGTERMs are not lost we might send to the agent. */
        assert_se(sigfillset(&ss) >= 0);
        assert_se(sigprocmask(SIG_SETMASK, &ss, &saved_ss) >= 0);

        agent_pid = fork();
        if (agent_pid < 0) {
                assert_se(sigprocmask(SIG_SETMASK, &saved_ss, NULL) >= 0);
                return -errno;
        }

        if (agent_pid != 0) {
                assert_se(sigprocmask(SIG_SETMASK, &saved_ss, NULL) >= 0);
                *pid = agent_pid;
                return 0;
        }

        /* In the child:
         *
         * Make sure the agent goes away when the parent dies */
        if (prctl(PR_SET_PDEATHSIG, SIGTERM) < 0)
                _exit(EXIT_FAILURE);

        /* Make sure we actually can kill the agent, if we need to, in
         * case somebody invoked us from a shell script that trapped
         * SIGTERM or so... */
        (void) reset_all_signal_handlers();
        (void) reset_signal_mask();

        /* Check whether our parent died before we were able
         * to set the death signal and unblock the signals */
        if (getppid() != parent_pid)
                _exit(EXIT_SUCCESS);

        /* Don't leak fds to the agent */
        close_all_fds(except, n_except);

        stdout_is_tty = isatty(STDOUT_FILENO);
        stderr_is_tty = isatty(STDERR_FILENO);

        if (!stdout_is_tty || !stderr_is_tty) {
                int fd;

                /* Detach from stdout/stderr. and reopen
                 * /dev/tty for them. This is important to
                 * ensure that when systemctl is started via
                 * popen() or a similar call that expects to
                 * read EOF we actually do generate EOF and
                 * not delay this indefinitely by because we
                 * keep an unused copy of stdin around. */
                fd = open("/dev/tty", O_WRONLY);
                if (fd < 0) {
                        log_error_errno(errno, "Failed to open /dev/tty: %m");
                        _exit(EXIT_FAILURE);
                }

                if (!stdout_is_tty)
                        dup2(fd, STDOUT_FILENO);

                if (!stderr_is_tty)
                        dup2(fd, STDERR_FILENO);

                if (fd > 2)
                        close(fd);
        }

        /* Count arguments */
        va_start(ap, path);
        for (n = 0; va_arg(ap, char*); n++)
                ;
        va_end(ap);

        /* Allocate strv */
        l = alloca(sizeof(char *) * (n + 1));

        /* Fill in arguments */
        va_start(ap, path);
        for (i = 0; i <= n; i++)
                l[i] = va_arg(ap, char*);
        va_end(ap);

        execv(path, l);
        _exit(EXIT_FAILURE);
}

bool http_etag_is_valid(const char *etag) {
        if (isempty(etag))
                return false;

        if (!endswith(etag, "\""))
                return false;

        if (!startswith(etag, "\"") && !startswith(etag, "W/\""))
                return false;

        return true;
}

bool http_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        p = startswith(url, "http://");
        if (!p)
                p = startswith(url, "https://");
        if (!p)
                return false;

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool documentation_url_is_valid(const char *url) {
        const char *p;

        if (isempty(url))
                return false;

        if (http_url_is_valid(url))
                return true;

        p = startswith(url, "file:/");
        if (!p)
                p = startswith(url, "info:");
        if (!p)
                p = startswith(url, "man:");

        if (isempty(p))
                return false;

        return ascii_is_valid(p);
}

bool in_initrd(void) {
        static int saved = -1;
        struct statfs s;

        if (saved >= 0)
                return saved;

        /* We make two checks here:
         *
         * 1. the flag file /etc/initrd-release must exist
         * 2. the root file system must be a memory file system
         *
         * The second check is extra paranoia, since misdetecting an
         * initrd can have bad bad consequences due the initrd
         * emptying when transititioning to the main systemd.
         */

        saved = access("/etc/initrd-release", F_OK) >= 0 &&
                statfs("/", &s) >= 0 &&
                is_temporary_fs(&s);

        return saved;
}

/* hey glibc, APIs with callbacks without a user pointer are so useless */
void *xbsearch_r(const void *key, const void *base, size_t nmemb, size_t size,
                 int (*compar) (const void *, const void *, void *), void *arg) {
        size_t l, u, idx;
        const void *p;
        int comparison;

        l = 0;
        u = nmemb;
        while (l < u) {
                idx = (l + u) / 2;
                p = (void *)(((const char *) base) + (idx * size));
                comparison = compar(key, p, arg);
                if (comparison < 0)
                        u = idx;
                else if (comparison > 0)
                        l = idx + 1;
                else
                        return (void *)p;
        }
        return NULL;
}

void init_gettext(void) {
        setlocale(LC_ALL, "");
        textdomain(GETTEXT_PACKAGE);
}

bool is_locale_utf8(void) {
        const char *set;
        static int cached_answer = -1;

        if (cached_answer >= 0)
                goto out;

        if (!setlocale(LC_ALL, "")) {
                cached_answer = true;
                goto out;
        }

        set = nl_langinfo(CODESET);
        if (!set) {
                cached_answer = true;
                goto out;
        }

        if (streq(set, "UTF-8")) {
                cached_answer = true;
                goto out;
        }

        /* For LC_CTYPE=="C" return true, because CTYPE is effectly
         * unset and everything can do to UTF-8 nowadays. */
        set = setlocale(LC_CTYPE, NULL);
        if (!set) {
                cached_answer = true;
                goto out;
        }

        /* Check result, but ignore the result if C was set
         * explicitly. */
        cached_answer =
                STR_IN_SET(set, "C", "POSIX") &&
                !getenv("LC_ALL") &&
                !getenv("LC_CTYPE") &&
                !getenv("LANG");

out:
        return (bool) cached_answer;
}

const char *draw_special_char(DrawSpecialChar ch) {
        static const char *draw_table[2][_DRAW_SPECIAL_CHAR_MAX] = {

                /* UTF-8 */ {
                        [DRAW_TREE_VERTICAL]      = "\342\224\202 ",            /* │  */
                        [DRAW_TREE_BRANCH]        = "\342\224\234\342\224\200", /* ├─ */
                        [DRAW_TREE_RIGHT]         = "\342\224\224\342\224\200", /* └─ */
                        [DRAW_TREE_SPACE]         = "  ",                       /*    */
                        [DRAW_TRIANGULAR_BULLET]  = "\342\200\243",             /* ‣ */
                        [DRAW_BLACK_CIRCLE]       = "\342\227\217",             /* ● */
                        [DRAW_ARROW]              = "\342\206\222",             /* → */
                        [DRAW_DASH]               = "\342\200\223",             /* – */
                },

                /* ASCII fallback */ {
                        [DRAW_TREE_VERTICAL]      = "| ",
                        [DRAW_TREE_BRANCH]        = "|-",
                        [DRAW_TREE_RIGHT]         = "`-",
                        [DRAW_TREE_SPACE]         = "  ",
                        [DRAW_TRIANGULAR_BULLET]  = ">",
                        [DRAW_BLACK_CIRCLE]       = "*",
                        [DRAW_ARROW]              = "->",
                        [DRAW_DASH]               = "-",
                }
        };

        return draw_table[!is_locale_utf8()][ch];
}

int on_ac_power(void) {
        bool found_offline = false, found_online = false;
        _cleanup_closedir_ DIR *d = NULL;

        d = opendir("/sys/class/power_supply");
        if (!d)
                return errno == ENOENT ? true : -errno;

        for (;;) {
                struct dirent *de;
                _cleanup_close_ int fd = -1, device = -1;
                char contents[6];
                ssize_t n;

                errno = 0;
                de = readdir(d);
                if (!de && errno != 0)
                        return -errno;

                if (!de)
                        break;

                if (hidden_file(de->d_name))
                        continue;

                device = openat(dirfd(d), de->d_name, O_DIRECTORY|O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (device < 0) {
                        if (errno == ENOENT || errno == ENOTDIR)
                                continue;

                        return -errno;
                }

                fd = openat(device, "type", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                n = read(fd, contents, sizeof(contents));
                if (n < 0)
                        return -errno;

                if (n != 6 || memcmp(contents, "Mains\n", 6))
                        continue;

                safe_close(fd);
                fd = openat(device, "online", O_RDONLY|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (errno == ENOENT)
                                continue;

                        return -errno;
                }

                n = read(fd, contents, sizeof(contents));
                if (n < 0)
                        return -errno;

                if (n != 2 || contents[1] != '\n')
                        return -EIO;

                if (contents[0] == '1') {
                        found_online = true;
                        break;
                } else if (contents[0] == '0')
                        found_offline = true;
                else
                        return -EIO;
        }

        return found_online || !found_offline;
}

void* greedy_realloc(void **p, size_t *allocated, size_t need, size_t size) {
        size_t a, newalloc;
        void *q;

        assert(p);
        assert(allocated);

        if (*allocated >= need)
                return *p;

        newalloc = MAX(need * 2, 64u / size);
        a = newalloc * size;

        /* check for overflows */
        if (a < size * need)
                return NULL;

        q = realloc(*p, a);
        if (!q)
                return NULL;

        *p = q;
        *allocated = newalloc;
        return q;
}

void* greedy_realloc0(void **p, size_t *allocated, size_t need, size_t size) {
        size_t prev;
        uint8_t *q;

        assert(p);
        assert(allocated);

        prev = *allocated;

        q = greedy_realloc(p, allocated, need, size);
        if (!q)
                return NULL;

        if (*allocated > prev)
                memzero(q + prev * size, (*allocated - prev) * size);

        return q;
}

bool id128_is_valid(const char *s) {
        size_t i, l;

        l = strlen(s);
        if (l == 32) {

                /* Simple formatted 128bit hex string */

                for (i = 0; i < l; i++) {
                        char c = s[i];

                        if (!(c >= '0' && c <= '9') &&
                            !(c >= 'a' && c <= 'z') &&
                            !(c >= 'A' && c <= 'Z'))
                                return false;
                }

        } else if (l == 36) {

                /* Formatted UUID */

                for (i = 0; i < l; i++) {
                        char c = s[i];

                        if ((i == 8 || i == 13 || i == 18 || i == 23)) {
                                if (c != '-')
                                        return false;
                        } else {
                                if (!(c >= '0' && c <= '9') &&
                                    !(c >= 'a' && c <= 'z') &&
                                    !(c >= 'A' && c <= 'Z'))
                                        return false;
                        }
                }

        } else
                return false;

        return true;
}

int shall_restore_state(void) {
        _cleanup_free_ char *value = NULL;
        int r;

        r = get_proc_cmdline_key("systemd.restore_state=", &value);
        if (r < 0)
                return r;
        if (r == 0)
                return true;

        return parse_boolean(value) != 0;
}

int proc_cmdline(char **ret) {
        assert(ret);

        if (detect_container() > 0)
                return get_process_cmdline(1, 0, false, ret);
        else
                return read_one_line_file("/proc/cmdline", ret);
}

int parse_proc_cmdline(int (*parse_item)(const char *key, const char *value)) {
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(parse_item);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                char *value = NULL;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                value = strchr(word, '=');
                if (value)
                        *(value++) = 0;

                r = parse_item(word, value);
                if (r < 0)
                        return r;
        }

        return 0;
}

int get_proc_cmdline_key(const char *key, char **value) {
        _cleanup_free_ char *line = NULL, *ret = NULL;
        bool found = false;
        const char *p;
        int r;

        assert(key);

        r = proc_cmdline(&line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *e;

                r = extract_first_word(&p, &word, NULL, EXTRACT_QUOTES|EXTRACT_RELAX);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Filter out arguments that are intended only for the
                 * initrd */
                if (!in_initrd() && startswith(word, "rd."))
                        continue;

                if (value) {
                        e = startswith(word, key);
                        if (!e)
                                continue;

                        r = free_and_strdup(&ret, e);
                        if (r < 0)
                                return r;

                        found = true;
                } else {
                        if (streq(word, key))
                                found = true;
                }
        }

        if (value) {
                *value = ret;
                ret = NULL;
        }

        return found;

}

int container_get_leader(const char *machine, pid_t *pid) {
        _cleanup_free_ char *s = NULL, *class = NULL;
        const char *p;
        pid_t leader;
        int r;

        assert(machine);
        assert(pid);

        if (!machine_name_is_valid(machine))
                return -EINVAL;

        p = strjoina("/run/systemd/machines/", machine);
        r = parse_env_file(p, NEWLINE, "LEADER", &s, "CLASS", &class, NULL);
        if (r == -ENOENT)
                return -EHOSTDOWN;
        if (r < 0)
                return r;
        if (!s)
                return -EIO;

        if (!streq_ptr(class, "container"))
                return -EIO;

        r = parse_pid(s, &leader);
        if (r < 0)
                return r;
        if (leader <= 1)
                return -EIO;

        *pid = leader;
        return 0;
}

int namespace_open(pid_t pid, int *pidns_fd, int *mntns_fd, int *netns_fd, int *userns_fd, int *root_fd) {
        _cleanup_close_ int pidnsfd = -1, mntnsfd = -1, netnsfd = -1, usernsfd = -1;
        int rfd = -1;

        assert(pid >= 0);

        if (mntns_fd) {
                const char *mntns;

                mntns = procfs_file_alloca(pid, "ns/mnt");
                mntnsfd = open(mntns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (mntnsfd < 0)
                        return -errno;
        }

        if (pidns_fd) {
                const char *pidns;

                pidns = procfs_file_alloca(pid, "ns/pid");
                pidnsfd = open(pidns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (pidnsfd < 0)
                        return -errno;
        }

        if (netns_fd) {
                const char *netns;

                netns = procfs_file_alloca(pid, "ns/net");
                netnsfd = open(netns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (netnsfd < 0)
                        return -errno;
        }

        if (userns_fd) {
                const char *userns;

                userns = procfs_file_alloca(pid, "ns/user");
                usernsfd = open(userns, O_RDONLY|O_NOCTTY|O_CLOEXEC);
                if (usernsfd < 0 && errno != ENOENT)
                        return -errno;
        }

        if (root_fd) {
                const char *root;

                root = procfs_file_alloca(pid, "root");
                rfd = open(root, O_RDONLY|O_NOCTTY|O_CLOEXEC|O_DIRECTORY);
                if (rfd < 0)
                        return -errno;
        }

        if (pidns_fd)
                *pidns_fd = pidnsfd;

        if (mntns_fd)
                *mntns_fd = mntnsfd;

        if (netns_fd)
                *netns_fd = netnsfd;

        if (userns_fd)
                *userns_fd = usernsfd;

        if (root_fd)
                *root_fd = rfd;

        pidnsfd = mntnsfd = netnsfd = usernsfd = -1;

        return 0;
}

int namespace_enter(int pidns_fd, int mntns_fd, int netns_fd, int userns_fd, int root_fd) {
        if (userns_fd >= 0) {
                /* Can't setns to your own userns, since then you could
                 * escalate from non-root to root in your own namespace, so
                 * check if namespaces equal before attempting to enter. */
                _cleanup_free_ char *userns_fd_path = NULL;
                int r;
                if (asprintf(&userns_fd_path, "/proc/self/fd/%d", userns_fd) < 0)
                        return -ENOMEM;

                r = files_same(userns_fd_path, "/proc/self/ns/user");
                if (r < 0)
                        return r;
                if (r)
                        userns_fd = -1;
        }

        if (pidns_fd >= 0)
                if (setns(pidns_fd, CLONE_NEWPID) < 0)
                        return -errno;

        if (mntns_fd >= 0)
                if (setns(mntns_fd, CLONE_NEWNS) < 0)
                        return -errno;

        if (netns_fd >= 0)
                if (setns(netns_fd, CLONE_NEWNET) < 0)
                        return -errno;

        if (userns_fd >= 0)
                if (setns(userns_fd, CLONE_NEWUSER) < 0)
                        return -errno;

        if (root_fd >= 0) {
                if (fchdir(root_fd) < 0)
                        return -errno;

                if (chroot(".") < 0)
                        return -errno;
        }

        return reset_uid_gid();
}

unsigned long personality_from_string(const char *p) {

        /* Parse a personality specifier. We introduce our own
         * identifiers that indicate specific ABIs, rather than just
         * hints regarding the register size, since we want to keep
         * things open for multiple locally supported ABIs for the
         * same register size. We try to reuse the ABI identifiers
         * used by libseccomp. */

#if defined(__x86_64__)

        if (streq(p, "x86"))
                return PER_LINUX32;

        if (streq(p, "x86-64"))
                return PER_LINUX;

#elif defined(__i386__)

        if (streq(p, "x86"))
                return PER_LINUX;

#elif defined(__s390x__)

        if (streq(p, "s390"))
                return PER_LINUX32;

        if (streq(p, "s390x"))
                return PER_LINUX;

#elif defined(__s390__)

        if (streq(p, "s390"))
                return PER_LINUX;
#endif

        return PERSONALITY_INVALID;
}

const char* personality_to_string(unsigned long p) {

#if defined(__x86_64__)

        if (p == PER_LINUX32)
                return "x86";

        if (p == PER_LINUX)
                return "x86-64";

#elif defined(__i386__)

        if (p == PER_LINUX)
                return "x86";

#elif defined(__s390x__)

        if (p == PER_LINUX)
                return "s390x";

        if (p == PER_LINUX32)
                return "s390";

#elif defined(__s390__)

        if (p == PER_LINUX)
                return "s390";

#endif

        return NULL;
}

uint64_t physical_memory(void) {
        long mem;

        /* We return this as uint64_t in case we are running as 32bit
         * process on a 64bit kernel with huge amounts of memory */

        mem = sysconf(_SC_PHYS_PAGES);
        assert(mem > 0);

        return (uint64_t) mem * (uint64_t) page_size();
}

int update_reboot_param_file(const char *param) {
        int r = 0;

        if (param) {
                r = write_string_file(REBOOT_PARAM_FILE, param, WRITE_STRING_FILE_CREATE);
                if (r < 0)
                        return log_error_errno(r, "Failed to write reboot param to "REBOOT_PARAM_FILE": %m");
        } else
                (void) unlink(REBOOT_PARAM_FILE);

        return 0;
}

int syslog_parse_priority(const char **p, int *priority, bool with_facility) {
        int a = 0, b = 0, c = 0;
        int k;

        assert(p);
        assert(*p);
        assert(priority);

        if ((*p)[0] != '<')
                return 0;

        if (!strchr(*p, '>'))
                return 0;

        if ((*p)[2] == '>') {
                c = undecchar((*p)[1]);
                k = 3;
        } else if ((*p)[3] == '>') {
                b = undecchar((*p)[1]);
                c = undecchar((*p)[2]);
                k = 4;
        } else if ((*p)[4] == '>') {
                a = undecchar((*p)[1]);
                b = undecchar((*p)[2]);
                c = undecchar((*p)[3]);
                k = 5;
        } else
                return 0;

        if (a < 0 || b < 0 || c < 0 ||
            (!with_facility && (a || b || c > 7)))
                return 0;

        if (with_facility)
                *priority = a*100 + b*10 + c;
        else
                *priority = (*priority & LOG_FACMASK) | c;

        *p += k;
        return 1;
}

int version(void) {
        puts(PACKAGE_STRING "\n"
             SYSTEMD_FEATURES);
        return 0;
}

bool fdname_is_valid(const char *s) {
        const char *p;

        /* Validates a name for $LISTEN_FDNAMES. We basically allow
         * everything ASCII that's not a control character. Also, as
         * special exception the ":" character is not allowed, as we
         * use that as field separator in $LISTEN_FDNAMES.
         *
         * Note that the empty string is explicitly allowed
         * here. However, we limit the length of the names to 255
         * characters. */

        if (!s)
                return false;

        for (p = s; *p; p++) {
                if (*p < ' ')
                        return false;
                if (*p >= 127)
                        return false;
                if (*p == ':')
                        return false;
        }

        return p - s < 256;
}

bool oom_score_adjust_is_valid(int oa) {
        return oa >= OOM_SCORE_ADJ_MIN && oa <= OOM_SCORE_ADJ_MAX;
}
