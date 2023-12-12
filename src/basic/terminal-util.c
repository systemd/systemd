/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#include <poll.h>
#include <signal.h>
#include <stdarg.h>
#include <stddef.h>
#include <stdlib.h>
#include <sys/inotify.h>
#include <sys/ioctl.h>
#include <sys/sysmacros.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/utsname.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "constants.h"
#include "devnum-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "inotify-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "socket-util.h"
#include "stat-util.h"
#include "stdio-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "time-util.h"
#include "user-util.h"

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

static volatile int cached_on_tty = -1;
static volatile int cached_on_dev_null = -1;
static volatile int cached_color_mode = _COLOR_INVALID;
static volatile int cached_underline_enabled = -1;

int chvt(int vt) {
        _cleanup_close_ int fd = -EBADF;

        /* Switch to the specified vt number. If the VT is specified <= 0 switch to the VT the kernel log messages go,
         * if that's configured. */

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        if (vt <= 0) {
                int tiocl[2] = {
                        TIOCL_GETKMSGREDIRECT,
                        0
                };

                if (ioctl(fd, TIOCLINUX, tiocl) < 0)
                        return -errno;

                vt = tiocl[0] <= 0 ? 1 : tiocl[0];
        }

        return RET_NERRNO(ioctl(fd, VT_ACTIVATE, vt));
}

int read_one_char(FILE *f, char *ret, usec_t t, bool *need_nl) {
        _cleanup_free_ char *line = NULL;
        struct termios old_termios;
        int r, fd;

        assert(f);
        assert(ret);

        /* If this is a terminal, then switch canonical mode off, so that we can read a single
         * character. (Note that fmemopen() streams do not have an fd associated with them, let's handle that
         * nicely.) */
        fd = fileno(f);
        if (fd >= 0 && tcgetattr(fd, &old_termios) >= 0) {
                struct termios new_termios = old_termios;

                new_termios.c_lflag &= ~ICANON;
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(fd, TCSADRAIN, &new_termios) >= 0) {
                        char c;

                        if (t != USEC_INFINITY) {
                                if (fd_wait_for_event(fd, POLLIN, t) <= 0) {
                                        (void) tcsetattr(fd, TCSADRAIN, &old_termios);
                                        return -ETIMEDOUT;
                                }
                        }

                        r = safe_fgetc(f, &c);
                        (void) tcsetattr(fd, TCSADRAIN, &old_termios);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                return -EIO;

                        if (need_nl)
                                *need_nl = c != '\n';

                        *ret = c;
                        return 0;
                }
        }

        if (t != USEC_INFINITY && fd > 0) {
                /* Let's wait the specified amount of time for input. When we have no fd we skip this, under
                 * the assumption that this is an fmemopen() stream or so where waiting doesn't make sense
                 * anyway, as the data is either already in the stream or cannot possible be placed there
                 * while we access the stream */

                if (fd_wait_for_event(fd, POLLIN, t) <= 0)
                        return -ETIMEDOUT;
        }

        /* If this is not a terminal, then read a full line instead */

        r = read_line(f, 16, &line); /* longer than necessary, to eat up UTF-8 chars/vt100 key sequences */
        if (r < 0)
                return r;
        if (r == 0)
                return -EIO;

        if (strlen(line) != 1)
                return -EBADMSG;

        if (need_nl)
                *need_nl = false;

        *ret = line[0];
        return 0;
}

#define DEFAULT_ASK_REFRESH_USEC (2*USEC_PER_SEC)

int ask_char(char *ret, const char *replies, const char *fmt, ...) {
        int r;

        assert(ret);
        assert(replies);
        assert(fmt);

        for (;;) {
                va_list ap;
                char c;
                bool need_nl = true;

                fputs(ansi_highlight(), stdout);

                putchar('\r');

                va_start(ap, fmt);
                vprintf(fmt, ap);
                va_end(ap);

                fputs(ansi_normal(), stdout);

                fflush(stdout);

                r = read_one_char(stdin, &c, DEFAULT_ASK_REFRESH_USEC, &need_nl);
                if (r < 0) {

                        if (r == -ETIMEDOUT)
                                continue;

                        if (r == -EBADMSG) {
                                puts("Bad input, please try again.");
                                continue;
                        }

                        putchar('\n');
                        return r;
                }

                if (need_nl)
                        putchar('\n');

                if (strchr(replies, c)) {
                        *ret = c;
                        return 0;
                }

                puts("Read unexpected character, please try again.");
        }
}

int ask_string(char **ret, const char *text, ...) {
        _cleanup_free_ char *line = NULL;
        va_list ap;
        int r;

        assert(ret);
        assert(text);

        fputs(ansi_highlight(), stdout);

        va_start(ap, text);
        vprintf(text, ap);
        va_end(ap);

        fputs(ansi_normal(), stdout);

        fflush(stdout);

        r = read_line(stdin, LONG_LINE_MAX, &line);
        if (r < 0)
                return r;
        if (r == 0)
                return -EIO;

        *ret = TAKE_PTR(line);
        return 0;
}

int reset_terminal_fd(int fd, bool switch_to_text) {
        struct termios termios;
        int r;

        /* Set terminal to some sane defaults */

        assert(fd >= 0);

        if (isatty(fd) < 1)
                return log_debug_errno(errno, "Asked to reset a terminal that actually isn't a terminal: %m");

        /* We leave locked terminal attributes untouched, so that Plymouth may set whatever it wants to set,
         * and we don't interfere with that. */

        /* Disable exclusive mode, just in case */
        if (ioctl(fd, TIOCNXCL) < 0)
                log_debug_errno(errno, "TIOCNXCL ioctl failed on TTY, ignoring: %m");

        /* Switch to text mode */
        if (switch_to_text)
                if (ioctl(fd, KDSETMODE, KD_TEXT) < 0)
                        log_debug_errno(errno, "KDSETMODE ioctl for switching to text mode failed on TTY, ignoring: %m");


        /* Set default keyboard mode */
        r = vt_reset_keyboard(fd);
        if (r < 0)
                log_debug_errno(r, "Failed to reset VT keyboard, ignoring: %m");

        if (tcgetattr(fd, &termios) < 0) {
                r = log_debug_errno(errno, "Failed to get terminal parameters: %m");
                goto finish;
        }

        /* We only reset the stuff that matters to the software. How
         * hardware is set up we don't touch assuming that somebody
         * else will do that for us */

        termios.c_iflag &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | IUCLC);
        termios.c_iflag |= ICRNL | IMAXBEL | IUTF8;
        termios.c_oflag |= ONLCR | OPOST;
        termios.c_cflag |= CREAD;
        termios.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOKE;

        termios.c_cc[VINTR]    =   03;  /* ^C */
        termios.c_cc[VQUIT]    =  034;  /* ^\ */
        termios.c_cc[VERASE]   = 0177;
        termios.c_cc[VKILL]    =  025;  /* ^X */
        termios.c_cc[VEOF]     =   04;  /* ^D */
        termios.c_cc[VSTART]   =  021;  /* ^Q */
        termios.c_cc[VSTOP]    =  023;  /* ^S */
        termios.c_cc[VSUSP]    =  032;  /* ^Z */
        termios.c_cc[VLNEXT]   =  026;  /* ^V */
        termios.c_cc[VWERASE]  =  027;  /* ^W */
        termios.c_cc[VREPRINT] =  022;  /* ^R */
        termios.c_cc[VEOL]     =    0;
        termios.c_cc[VEOL2]    =    0;

        termios.c_cc[VTIME]  = 0;
        termios.c_cc[VMIN]   = 1;

        r = RET_NERRNO(tcsetattr(fd, TCSANOW, &termios));

finish:
        /* Just in case, flush all crap out */
        (void) tcflush(fd, TCIOFLUSH);

        return r;
}

int reset_terminal(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        /* We open the terminal with O_NONBLOCK here, to ensure we
         * don't block on carrier if this is a terminal with carrier
         * configured. */

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

        return reset_terminal_fd(fd, true);
}

int open_terminal(const char *name, int mode) {
        _cleanup_close_ int fd = -EBADF;
        unsigned c = 0;

        /*
         * If a TTY is in the process of being closed opening it might cause EIO. This is horribly awful, but
         * unlikely to be changed in the kernel. Hence we work around this problem by retrying a couple of
         * times.
         *
         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/554172/comments/245
         */

        if (mode & O_CREAT)
                return -EINVAL;

        for (;;) {
                fd = open(name, mode, 0);
                if (fd >= 0)
                        break;

                if (errno != EIO)
                        return -errno;

                /* Max 1s in total */
                if (c >= 20)
                        return -errno;

                (void) usleep_safe(50 * USEC_PER_MSEC);
                c++;
        }

        if (isatty(fd) < 1)
                return negative_errno();

        return TAKE_FD(fd);
}

int acquire_terminal(
                const char *name,
                AcquireTerminalFlags flags,
                usec_t timeout) {

        _cleanup_close_ int notify = -EBADF, fd = -EBADF;
        usec_t ts = USEC_INFINITY;
        int r, wd = -1;

        assert(name);
        assert(IN_SET(flags & ~ACQUIRE_TERMINAL_PERMISSIVE, ACQUIRE_TERMINAL_TRY, ACQUIRE_TERMINAL_FORCE, ACQUIRE_TERMINAL_WAIT));

        /* We use inotify to be notified when the tty is closed. We create the watch before checking if we can actually
         * acquire it, so that we don't lose any event.
         *
         * Note: strictly speaking this actually watches for the device being closed, it does *not* really watch
         * whether a tty loses its controlling process. However, unless some rogue process uses TIOCNOTTY on /dev/tty
         * *after* closing its tty otherwise this will not become a problem. As long as the administrator makes sure to
         * not configure any service on the same tty as an untrusted user this should not be a problem. (Which they
         * probably should not do anyway.) */

        if ((flags & ~ACQUIRE_TERMINAL_PERMISSIVE) == ACQUIRE_TERMINAL_WAIT) {
                notify = inotify_init1(IN_CLOEXEC | (timeout != USEC_INFINITY ? IN_NONBLOCK : 0));
                if (notify < 0)
                        return -errno;

                wd = inotify_add_watch(notify, name, IN_CLOSE);
                if (wd < 0)
                        return -errno;

                if (timeout != USEC_INFINITY)
                        ts = now(CLOCK_MONOTONIC);
        }

        for (;;) {
                struct sigaction sa_old, sa_new = {
                        .sa_handler = SIG_IGN,
                        .sa_flags = SA_RESTART,
                };

                if (notify >= 0) {
                        r = flush_fd(notify);
                        if (r < 0)
                                return r;
                }

                /* We pass here O_NOCTTY only so that we can check the return value TIOCSCTTY and have a reliable way
                 * to figure out if we successfully became the controlling process of the tty */
                fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed if we already own the tty. */
                assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

                /* First, try to get the tty */
                r = RET_NERRNO(ioctl(fd, TIOCSCTTY, (flags & ~ACQUIRE_TERMINAL_PERMISSIVE) == ACQUIRE_TERMINAL_FORCE));

                /* Reset signal handler to old value */
                assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

                /* Success? Exit the loop now! */
                if (r >= 0)
                        break;

                /* Any failure besides -EPERM? Fail, regardless of the mode. */
                if (r != -EPERM)
                        return r;

                if (flags & ACQUIRE_TERMINAL_PERMISSIVE) /* If we are in permissive mode, then EPERM is fine, turn this
                                                          * into a success. Note that EPERM is also returned if we
                                                          * already are the owner of the TTY. */
                        break;

                if (flags != ACQUIRE_TERMINAL_WAIT) /* If we are in TRY or FORCE mode, then propagate EPERM as EPERM */
                        return r;

                assert(notify >= 0);
                assert(wd >= 0);

                for (;;) {
                        union inotify_event_buffer buffer;
                        ssize_t l;

                        if (timeout != USEC_INFINITY) {
                                usec_t n;

                                assert(ts != USEC_INFINITY);

                                n = usec_sub_unsigned(now(CLOCK_MONOTONIC), ts);
                                if (n >= timeout)
                                        return -ETIMEDOUT;

                                r = fd_wait_for_event(notify, POLLIN, usec_sub_unsigned(timeout, n));
                                if (r < 0)
                                        return r;
                                if (r == 0)
                                        return -ETIMEDOUT;
                        }

                        l = read(notify, &buffer, sizeof(buffer));
                        if (l < 0) {
                                if (ERRNO_IS_TRANSIENT(errno))
                                        continue;

                                return -errno;
                        }

                        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                                if (e->mask & IN_Q_OVERFLOW) /* If we hit an inotify queue overflow, simply check if the terminal is up for grabs now. */
                                        break;

                                if (e->wd != wd || !(e->mask & IN_CLOSE)) /* Safety checks */
                                        return -EIO;
                        }

                        break;
                }

                /* We close the tty fd here since if the old session ended our handle will be dead. It's important that
                 * we do this after sleeping, so that we don't enter an endless loop. */
                fd = safe_close(fd);
        }

        return TAKE_FD(fd);
}

int release_terminal(void) {
        static const struct sigaction sa_new = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };

        _cleanup_close_ int fd = -EBADF;
        struct sigaction sa_old;
        int r;

        fd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
         * by our own TIOCNOTTY */
        assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

        r = RET_NERRNO(ioctl(fd, TIOCNOTTY));

        assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

        return r;
}

int terminal_vhangup_fd(int fd) {
        assert(fd >= 0);
        return RET_NERRNO(ioctl(fd, TIOCVHANGUP));
}

int terminal_vhangup(const char *name) {
        _cleanup_close_ int fd = -EBADF;

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

        return terminal_vhangup_fd(fd);
}

int vt_disallocate(const char *name) {
        const char *e;
        int r;

        /* Deallocate the VT if possible. If not possible
         * (i.e. because it is the active one), at least clear it
         * entirely (including the scrollback buffer). */

        e = path_startswith(name, "/dev/");
        if (!e)
                return -EINVAL;

        if (tty_is_vc(name)) {
                _cleanup_close_ int fd = -EBADF;
                unsigned u;
                const char *n;

                n = startswith(e, "tty");
                if (!n)
                        return -EINVAL;

                r = safe_atou(n, &u);
                if (r < 0)
                        return r;

                if (u <= 0)
                        return -EINVAL;

                /* Try to deallocate */
                fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0)
                        return fd;

                r = ioctl(fd, VT_DISALLOCATE, u);
                if (r >= 0)
                        return 0;
                if (errno != EBUSY)
                        return -errno;
        }

        /* So this is not a VT (in which case we cannot deallocate it),
         * or we failed to deallocate. Let's at least clear the screen. */

        _cleanup_close_ int fd2 = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd2 < 0)
                return fd2;

        (void) loop_write(fd2,
                          "\033[r"   /* clear scrolling region */
                          "\033[H"   /* move home */
                          "\033[3J", /* clear screen including scrollback, requires Linux 2.6.40 */
                          10);
        return 0;
}

int make_console_stdio(void) {
        int fd, r;

        /* Make /dev/console the controlling terminal and stdin/stdout/stderr, if we can. If we can't use
         * /dev/null instead. This is particularly useful if /dev/console is turned off, e.g. if console=null
         * is specified on the kernel command line. */

        fd = acquire_terminal("/dev/console", ACQUIRE_TERMINAL_FORCE|ACQUIRE_TERMINAL_PERMISSIVE, USEC_INFINITY);
        if (fd < 0) {
                log_warning_errno(fd, "Failed to acquire terminal, using /dev/null stdin/stdout/stderr instead: %m");

                r = make_null_stdio();
                if (r < 0)
                        return log_error_errno(r, "Failed to make /dev/null stdin/stdout/stderr: %m");

        } else {
                unsigned rows, cols;

                r = reset_terminal_fd(fd, /* switch_to_text= */ true);
                if (r < 0)
                        log_warning_errno(r, "Failed to reset terminal, ignoring: %m");

                r = proc_cmdline_tty_size("/dev/console", &rows, &cols);
                if (r < 0)
                        log_warning_errno(r, "Failed to get terminal size, ignoring: %m");
                else {
                        r = terminal_set_size_fd(fd, NULL, rows, cols);
                        if (r < 0)
                                log_warning_errno(r, "Failed to set terminal size, ignoring: %m");
                }

                r = rearrange_stdio(fd, fd, fd); /* This invalidates 'fd' both on success and on failure. */
                if (r < 0)
                        return log_error_errno(r, "Failed to make terminal stdin/stdout/stderr: %m");
        }

        reset_terminal_feature_caches();
        return 0;
}

bool tty_is_vc(const char *tty) {
        assert(tty);

        return vtnr_from_tty(tty) >= 0;
}

bool tty_is_console(const char *tty) {
        assert(tty);

        return streq(skip_dev_prefix(tty), "console");
}

int vtnr_from_tty(const char *tty) {
        int i, r;

        assert(tty);

        tty = skip_dev_prefix(tty);

        if (!startswith(tty, "tty") )
                return -EINVAL;

        if (!ascii_isdigit(tty[3]))
                return -EINVAL;

        r = safe_atoi(tty+3, &i);
        if (r < 0)
                return r;

        if (i < 0 || i > 63)
                return -EINVAL;

        return i;
}

 int resolve_dev_console(char **ret) {
        _cleanup_free_ char *active = NULL;
        char *tty;
        int r;

        assert(ret);

        /* Resolve where /dev/console is pointing to, if /sys is actually ours (i.e. not read-only-mounted which is a
         * sign for container setups) */

        if (path_is_read_only_fs("/sys") > 0)
                return -ENOMEDIUM;

        r = read_one_line_file("/sys/class/tty/console/active", &active);
        if (r < 0)
                return r;

        /* If multiple log outputs are configured the last one is what /dev/console points to */
        tty = strrchr(active, ' ');
        if (tty)
                tty++;
        else
                tty = active;

        if (streq(tty, "tty0")) {
                active = mfree(active);

                /* Get the active VC (e.g. tty1) */
                r = read_one_line_file("/sys/class/tty/tty0/active", &active);
                if (r < 0)
                        return r;

                tty = active;
        }

        if (tty == active)
                *ret = TAKE_PTR(active);
        else {
                char *tmp;

                tmp = strdup(tty);
                if (!tmp)
                        return -ENOMEM;

                *ret = tmp;
        }

        return 0;
}

int get_kernel_consoles(char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *line = NULL;
        const char *p;
        int r;

        assert(ret);

        /* If /sys is mounted read-only this means we are running in some kind of container environment. In that
         * case /sys would reflect the host system, not us, hence ignore the data we can read from it. */
        if (path_is_read_only_fs("/sys") > 0)
                goto fallback;

        r = read_one_line_file("/sys/class/tty/console/active", &line);
        if (r < 0)
                return r;

        p = line;
        for (;;) {
                _cleanup_free_ char *tty = NULL, *path = NULL;

                r = extract_first_word(&p, &tty, NULL, 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (streq(tty, "tty0")) {
                        tty = mfree(tty);
                        r = read_one_line_file("/sys/class/tty/tty0/active", &tty);
                        if (r < 0)
                                return r;
                }

                path = path_join("/dev", tty);
                if (!path)
                        return -ENOMEM;

                if (access(path, F_OK) < 0) {
                        log_debug_errno(errno, "Console device %s is not accessible, skipping: %m", path);
                        continue;
                }

                r = strv_consume(&l, TAKE_PTR(path));
                if (r < 0)
                        return r;
        }

        if (strv_isempty(l)) {
                log_debug("No devices found for system console");
                goto fallback;
        }

        *ret = TAKE_PTR(l);

        return 0;

fallback:
        r = strv_extend(&l, "/dev/console");
        if (r < 0)
                return r;

        *ret = TAKE_PTR(l);

        return 0;
}

bool tty_is_vc_resolve(const char *tty) {
        _cleanup_free_ char *resolved = NULL;

        assert(tty);

        tty = skip_dev_prefix(tty);

        if (streq(tty, "console")) {
                if (resolve_dev_console(&resolved) < 0)
                        return false;

                tty = resolved;
        }

        return tty_is_vc(tty);
}

const char *default_term_for_tty(const char *tty) {
        return tty && tty_is_vc_resolve(tty) ? "linux" : "vt220";
}

int fd_columns(int fd) {
        struct winsize ws = {};

        if (fd < 0)
                return -EBADF;

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_col <= 0)
                return -EIO;

        return ws.ws_col;
}

unsigned columns(void) {
        const char *e;
        int c;

        if (cached_columns > 0)
                return cached_columns;

        c = 0;
        e = getenv("COLUMNS");
        if (e)
                (void) safe_atoi(e, &c);

        if (c <= 0 || c > USHRT_MAX) {
                c = fd_columns(STDOUT_FILENO);
                if (c <= 0)
                        c = 80;
        }

        cached_columns = c;
        return cached_columns;
}

int fd_lines(int fd) {
        struct winsize ws = {};

        if (fd < 0)
                return -EBADF;

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_row <= 0)
                return -EIO;

        return ws.ws_row;
}

unsigned lines(void) {
        const char *e;
        int l;

        if (cached_lines > 0)
                return cached_lines;

        l = 0;
        e = getenv("LINES");
        if (e)
                (void) safe_atoi(e, &l);

        if (l <= 0 || l > USHRT_MAX) {
                l = fd_lines(STDOUT_FILENO);
                if (l <= 0)
                        l = 24;
        }

        cached_lines = l;
        return cached_lines;
}

int terminal_set_size_fd(int fd, const char *ident, unsigned rows, unsigned cols) {
        struct winsize ws;

        if (rows == UINT_MAX && cols == UINT_MAX)
                return 0;

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return log_debug_errno(errno,
                                       "TIOCGWINSZ ioctl for getting %s size failed, not setting terminal size: %m",
                                       ident ?: "TTY");

        if (rows == UINT_MAX)
                rows = ws.ws_row;
        else if (rows > USHRT_MAX)
                rows = USHRT_MAX;

        if (cols == UINT_MAX)
                cols = ws.ws_col;
        else if (cols > USHRT_MAX)
                cols = USHRT_MAX;

        if (rows == ws.ws_row && cols == ws.ws_col)
                return 0;

        ws.ws_row = rows;
        ws.ws_col = cols;

        if (ioctl(fd, TIOCSWINSZ, &ws) < 0)
                return log_debug_errno(errno, "TIOCSWINSZ ioctl for setting %s size failed: %m", ident ?: "TTY");

        return 0;
}

int proc_cmdline_tty_size(const char *tty, unsigned *ret_rows, unsigned *ret_cols) {
        _cleanup_free_ char *rowskey = NULL, *rowsvalue = NULL, *colskey = NULL, *colsvalue = NULL;
        unsigned rows = UINT_MAX, cols = UINT_MAX;
        int r;

        assert(tty);

        if (!ret_rows && !ret_cols)
                return 0;

        tty = skip_dev_prefix(tty);
        if (!in_charset(tty, ALPHANUMERICAL))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL), "%s contains non-alphanumeric characters", tty);

        rowskey = strjoin("systemd.tty.rows.", tty);
        if (!rowskey)
                return -ENOMEM;

        colskey = strjoin("systemd.tty.columns.", tty);
        if (!colskey)
                return -ENOMEM;

        r = proc_cmdline_get_key_many(/* flags = */ 0,
                                      rowskey, &rowsvalue,
                                      colskey, &colsvalue);
        if (r < 0)
                return log_debug_errno(r, "Failed to read TTY size of %s from kernel cmdline: %m", tty);

        if (rowsvalue) {
                r = safe_atou(rowsvalue, &rows);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse %s=%s: %m", rowskey, rowsvalue);
        }

        if (colsvalue) {
                r = safe_atou(colsvalue, &cols);
                if (r < 0)
                        return log_debug_errno(r, "Failed to parse %s=%s: %m", colskey, colsvalue);
        }

        if (ret_rows)
                *ret_rows = rows;
        if (ret_cols)
                *ret_cols = cols;

        return 0;
}

/* intended to be used as a SIGWINCH sighandler */
void columns_lines_cache_reset(int signum) {
        cached_columns = 0;
        cached_lines = 0;
}

void reset_terminal_feature_caches(void) {
        cached_columns = 0;
        cached_lines = 0;

        cached_color_mode = _COLOR_INVALID;
        cached_underline_enabled = -1;
        cached_on_tty = -1;
        cached_on_dev_null = -1;
}

bool on_tty(void) {

        /* We check both stdout and stderr, so that situations where pipes on the shell are used are reliably
         * recognized, regardless if only the output or the errors are piped to some place. Since on_tty() is generally
         * used to default to a safer, non-interactive, non-color mode of operation it's probably good to be defensive
         * here, and check for both. Note that we don't check for STDIN_FILENO, because it should fine to use fancy
         * terminal functionality when outputting stuff, even if the input is piped to us. */

        if (cached_on_tty < 0)
                cached_on_tty =
                        isatty(STDOUT_FILENO) > 0 &&
                        isatty(STDERR_FILENO) > 0;

        return cached_on_tty;
}

int getttyname_malloc(int fd, char **ret) {
        char path[PATH_MAX], *c; /* PATH_MAX is counted *with* the trailing NUL byte */
        int r;

        assert(fd >= 0);
        assert(ret);

        r = ttyname_r(fd, path, sizeof path); /* positive error */
        assert(r >= 0);
        if (r == ERANGE)
                return -ENAMETOOLONG;
        if (r > 0)
                return -r;

        c = strdup(skip_dev_prefix(path));
        if (!c)
                return -ENOMEM;

        *ret = c;
        return 0;
}

int getttyname_harder(int fd, char **ret) {
        _cleanup_free_ char *s = NULL;
        int r;

        r = getttyname_malloc(fd, &s);
        if (r < 0)
                return r;

        if (streq(s, "tty"))
                return get_ctty(0, NULL, ret);

        *ret = TAKE_PTR(s);
        return 0;
}

int get_ctty_devnr(pid_t pid, dev_t *d) {
        int r;
        _cleanup_free_ char *line = NULL;
        const char *p;
        unsigned long ttynr;

        assert(pid >= 0);

        p = procfs_file_alloca(pid, "stat");
        r = read_one_line_file(p, &line);
        if (r < 0)
                return r;

        p = strrchr(line, ')');
        if (!p)
                return -EIO;

        p++;

        if (sscanf(p, " "
                   "%*c "  /* state */
                   "%*d "  /* ppid */
                   "%*d "  /* pgrp */
                   "%*d "  /* session */
                   "%lu ", /* ttynr */
                   &ttynr) != 1)
                return -EIO;

        if (devnum_is_zero(ttynr))
                return -ENXIO;

        if (d)
                *d = (dev_t) ttynr;

        return 0;
}

int get_ctty(pid_t pid, dev_t *ret_devnr, char **ret) {
        char pty[STRLEN("/dev/pts/") + DECIMAL_STR_MAX(dev_t) + 1];
        _cleanup_free_ char *buf = NULL;
        const char *fn = NULL, *w;
        dev_t devnr;
        int r;

        r = get_ctty_devnr(pid, &devnr);
        if (r < 0)
                return r;

        r = device_path_make_canonical(S_IFCHR, devnr, &buf);
        if (r < 0) {
                struct stat st;

                if (r != -ENOENT) /* No symlink for this in /dev/char/? */
                        return r;

                /* Maybe this is PTY? PTY devices are not listed in /dev/char/, as they don't follow the
                 * Linux device model and hence device_path_make_canonical() doesn't work for them. Let's
                 * assume this is a PTY for a moment, and check if the device node this would then map to in
                 * /dev/pts/ matches the one we are looking for. This way we don't have to hardcode the major
                 * number (which is 136 btw), but we still rely on the fact that PTY numbers map directly to
                 * the minor number of the pty. */
                xsprintf(pty, "/dev/pts/%u", minor(devnr));

                if (stat(pty, &st) < 0) {
                        if (errno != ENOENT)
                                return -errno;

                } else if (S_ISCHR(st.st_mode) && devnr == st.st_rdev) /* Bingo! */
                        fn = pty;

                if (!fn) {
                        /* Doesn't exist, or not a PTY? Probably something similar to the PTYs which have no
                         * symlink in /dev/char/. Let's return something vaguely useful. */
                        r = device_path_make_major_minor(S_IFCHR, devnr, &buf);
                        if (r < 0)
                                return r;

                        fn = buf;
                }
        } else
                fn = buf;

        w = path_startswith(fn, "/dev/");
        if (!w)
                return -EINVAL;

        if (ret) {
                _cleanup_free_ char *b = NULL;

                b = strdup(w);
                if (!b)
                        return -ENOMEM;

                *ret = TAKE_PTR(b);
        }

        if (ret_devnr)
                *ret_devnr = devnr;

        return 0;
}

int ptsname_malloc(int fd, char **ret) {
        size_t l = 100;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                char *c;

                c = new(char, l);
                if (!c)
                        return -ENOMEM;

                if (ptsname_r(fd, c, l) == 0) {
                        *ret = c;
                        return 0;
                }
                if (errno != ERANGE) {
                        free(c);
                        return -errno;
                }

                free(c);

                if (l > SIZE_MAX / 2)
                        return -ENOMEM;

                l *= 2;
        }
}

int openpt_allocate(int flags, char **ret_slave) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *p = NULL;
        int r;

        fd = posix_openpt(flags|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        if (ret_slave) {
                r = ptsname_malloc(fd, &p);
                if (r < 0)
                        return r;

                if (!path_startswith(p, "/dev/pts/"))
                        return -EINVAL;
        }

        if (unlockpt(fd) < 0)
                return -errno;

        if (ret_slave)
                *ret_slave = TAKE_PTR(p);

        return TAKE_FD(fd);
}

static int ptsname_namespace(int pty, char **ret) {
        int no = -1, r;

        /* Like ptsname(), but doesn't assume that the path is
         * accessible in the local namespace. */

        r = ioctl(pty, TIOCGPTN, &no);
        if (r < 0)
                return -errno;

        if (no < 0)
                return -EIO;

        if (asprintf(ret, "/dev/pts/%i", no) < 0)
                return -ENOMEM;

        return 0;
}

int openpt_allocate_in_namespace(pid_t pid, int flags, char **ret_slave) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF, fd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        pid_t child;
        int r;

        assert(pid > 0);

        r = namespace_open(pid, &pidnsfd, &mntnsfd, NULL, &usernsfd, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
                return -errno;

        r = namespace_fork("(sd-openptns)", "(sd-openpt)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                           pidnsfd, mntnsfd, -1, usernsfd, rootfd, &child);
        if (r < 0)
                return r;
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                fd = openpt_allocate(flags, NULL);
                if (fd < 0)
                        _exit(EXIT_FAILURE);

                if (send_one_fd(pair[1], fd, 0) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = wait_for_terminate_and_check("(sd-openptns)", child, 0);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EIO;

        fd = receive_one_fd(pair[0], 0);
        if (fd < 0)
                return fd;

        if (ret_slave) {
                r = ptsname_namespace(fd, ret_slave);
                if (r < 0)
                        return r;
        }

        return TAKE_FD(fd);
}

int open_terminal_in_namespace(pid_t pid, const char *name, int mode) {
        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        pid_t child;
        int r;

        r = namespace_open(pid, &pidnsfd, &mntnsfd, NULL, &usernsfd, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM, 0, pair) < 0)
                return -errno;

        r = namespace_fork("(sd-terminalns)", "(sd-terminal)", NULL, 0, FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL,
                           pidnsfd, mntnsfd, -1, usernsfd, rootfd, &child);
        if (r < 0)
                return r;
        if (r == 0) {
                int master;

                pair[0] = safe_close(pair[0]);

                master = open_terminal(name, mode|O_NOCTTY|O_CLOEXEC);
                if (master < 0)
                        _exit(EXIT_FAILURE);

                if (send_one_fd(pair[1], master, 0) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        r = wait_for_terminate_and_check("(sd-terminalns)", child, 0);
        if (r < 0)
                return r;
        if (r != EXIT_SUCCESS)
                return -EIO;

        return receive_one_fd(pair[0], 0);
}

static bool on_dev_null(void) {
        struct stat dst, ost, est;

        if (cached_on_dev_null >= 0)
                return cached_on_dev_null;

        if (stat("/dev/null", &dst) < 0 || fstat(STDOUT_FILENO, &ost) < 0 || fstat(STDERR_FILENO, &est) < 0)
                cached_on_dev_null = false;
        else
                cached_on_dev_null = stat_inode_same(&dst, &ost) && stat_inode_same(&dst, &est);

        return cached_on_dev_null;
}

static bool getenv_terminal_is_dumb(void) {
        const char *e;

        e = getenv("TERM");
        if (!e)
                return true;

        return streq(e, "dumb");
}

bool terminal_is_dumb(void) {
        if (!on_tty() && !on_dev_null())
                return true;

        return getenv_terminal_is_dumb();
}

static ColorMode parse_systemd_colors(void) {
        const char *e;
        int r;

        e = getenv("SYSTEMD_COLORS");
        if (!e)
                return _COLOR_INVALID;
        if (streq(e, "16"))
                return COLOR_16;
        if (streq(e, "256"))
                return COLOR_256;
        r = parse_boolean(e);
        if (r >= 0)
                return r > 0 ? COLOR_ON : COLOR_OFF;
        return _COLOR_INVALID;
}

ColorMode get_color_mode(void) {

        /* Returns the mode used to choose output colors. The possible modes are COLOR_OFF for no colors,
         * COLOR_16 for only the base 16 ANSI colors, COLOR_256 for more colors and COLOR_ON for unrestricted
         * color output. For that we check $SYSTEMD_COLORS first (which is the explicit way to
         * change the mode). If that didn't work we turn colors off unless we are on a TTY. And if we are on a TTY
         * we turn it off if $TERM is set to "dumb". There's one special tweak though: if we are PID 1 then we do not
         * check whether we are connected to a TTY, because we don't keep /dev/console open continuously due to fear
         * of SAK, and hence things are a bit weird. */
        ColorMode m;

        if (cached_color_mode < 0) {
                m = parse_systemd_colors();
                if (m >= 0)
                        cached_color_mode = m;
                else if (getenv("NO_COLOR"))
                        /* We only check for the presence of the variable; value is ignored. */
                        cached_color_mode = COLOR_OFF;

                else if (getpid_cached() == 1) {
                        /* PID1 outputs to the console without holding it open all the time.
                         *
                         * Note that the Linux console can only display 16 colors. We still enable 256 color
                         * mode even for PID1 output though (which typically goes to the Linux console),
                         * since the Linux console is able to parse the 256 color sequences and automatically
                         * map them to the closest color in the 16 color palette (since kernel 3.16). Doing
                         * 256 colors is nice for people who invoke systemd in a container or via a serial
                         * link or such, and use a true 256 color terminal to do so. */
                        if (getenv_terminal_is_dumb())
                                cached_color_mode = COLOR_OFF;
                } else {
                        if (terminal_is_dumb())
                                cached_color_mode = COLOR_OFF;
                }

                if (cached_color_mode < 0) {
                        /* We failed to figure out any reason to *disable* colors.
                         * Let's see how many colors we shall use. */
                        if (STRPTR_IN_SET(getenv("COLORTERM"),
                                          "truecolor",
                                          "24bit"))
                                cached_color_mode = COLOR_24BIT;
                        else
                                cached_color_mode = COLOR_256;
                }
        }

        return cached_color_mode;
}

bool dev_console_colors_enabled(void) {
        _cleanup_free_ char *s = NULL;
        ColorMode m;

        /* Returns true if we assume that color is supported on /dev/console.
         *
         * For that we first check if we explicitly got told to use colors or not, by checking $SYSTEMD_COLORS. If that
         * isn't set we check whether PID 1 has $TERM set, and if not, whether TERM is set on the kernel command
         * line. If we find $TERM set we assume color if it's not set to "dumb", similarly to how regular
         * colors_enabled() operates. */

        m = parse_systemd_colors();
        if (m >= 0)
                return m;

        if (getenv("NO_COLOR"))
                return false;

        if (getenv_for_pid(1, "TERM", &s) <= 0)
                (void) proc_cmdline_get_key("TERM", 0, &s);

        return !streq_ptr(s, "dumb");
}

bool underline_enabled(void) {

        if (cached_underline_enabled < 0) {

                /* The Linux console doesn't support underlining, turn it off, but only there. */

                if (colors_enabled())
                        cached_underline_enabled = !streq_ptr(getenv("TERM"), "linux");
                else
                        cached_underline_enabled = false;
        }

        return cached_underline_enabled;
}

int vt_default_utf8(void) {
        _cleanup_free_ char *b = NULL;
        int r;

        /* Read the default VT UTF8 setting from the kernel */

        r = read_one_line_file("/sys/module/vt/parameters/default_utf8", &b);
        if (r < 0)
                return r;

        return parse_boolean(b);
}

int vt_reset_keyboard(int fd) {
        int kb;

        /* If we can't read the default, then default to unicode. It's 2017 after all. */
        kb = vt_default_utf8() != 0 ? K_UNICODE : K_XLATE;

        return RET_NERRNO(ioctl(fd, KDSKBMODE, kb));
}

int vt_restore(int fd) {
        static const struct vt_mode mode = {
                .mode = VT_AUTO,
        };
        int r, q = 0;

        if (isatty(fd) < 1)
                return log_debug_errno(errno, "Asked to restore the VT for an fd that does not refer to a terminal: %m");

        if (ioctl(fd, KDSETMODE, KD_TEXT) < 0)
                q = log_debug_errno(errno, "Failed to set VT in text mode, ignoring: %m");

        r = vt_reset_keyboard(fd);
        if (r < 0) {
                log_debug_errno(r, "Failed to reset keyboard mode, ignoring: %m");
                if (q >= 0)
                        q = r;
        }

        if (ioctl(fd, VT_SETMODE, &mode) < 0) {
                log_debug_errno(errno, "Failed to set VT_AUTO mode, ignoring: %m");
                if (q >= 0)
                        q = -errno;
        }

        r = fchmod_and_chown(fd, TTY_MODE, 0, GID_INVALID);
        if (r < 0) {
                log_debug_errno(r, "Failed to chmod()/chown() VT, ignoring: %m");
                if (q >= 0)
                        q = r;
        }

        return q;
}

int vt_release(int fd, bool restore) {
        assert(fd >= 0);

        /* This function releases the VT by acknowledging the VT-switch signal
         * sent by the kernel and optionally reset the VT in text and auto
         * VT-switching modes. */

        if (isatty(fd) < 1)
                return log_debug_errno(errno, "Asked to release the VT for an fd that does not refer to a terminal: %m");

        if (ioctl(fd, VT_RELDISP, 1) < 0)
                return -errno;

        if (restore)
                return vt_restore(fd);

        return 0;
}

void get_log_colors(int priority, const char **on, const char **off, const char **highlight) {
        /* Note that this will initialize output variables only when there's something to output.
         * The caller must pre-initialize to "" or NULL as appropriate. */

        if (priority <= LOG_ERR) {
                if (on)
                        *on = ansi_highlight_red();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight();

        } else if (priority <= LOG_WARNING) {
                if (on)
                        *on = ansi_highlight_yellow();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight();

        } else if (priority <= LOG_NOTICE) {
                if (on)
                        *on = ansi_highlight();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight_red();

        } else if (priority >= LOG_DEBUG) {
                if (on)
                        *on = ansi_grey();
                if (off)
                        *off = ansi_normal();
                if (highlight)
                        *highlight = ansi_highlight_red();
        }
}

int set_terminal_cursor_position(int fd, unsigned int row, unsigned int column) {
        int r;
        char cursor_position[STRLEN("\x1B[") + DECIMAL_STR_MAX(int) * 2 + STRLEN(";H") + 1];

        assert(fd >= 0);

        xsprintf(cursor_position, "\x1B[%u;%uH", row, column);

        r = loop_write(fd, cursor_position, SIZE_MAX);
        if (r < 0)
                return log_warning_errno(r, "Failed to set cursor position, ignoring: %m");

        return 0;
}

static const char* const tty_background_color_table[_TTY_COLOR_MAX_DEFINED] = {
        [TTY_BACKGROUND_BLACK]           = "\x1B[40m",
        [TTY_BACKGROUND_RED]             = "\x1B[41m",
        [TTY_BACKGROUND_GREEN]           = "\x1B[42m",
        [TTY_BACKGROUND_YELLOW]          = "\x1B[43m",
        [TTY_BACKGROUND_BLUE]            = "\x1B[44m",
        [TTY_BACKGROUND_MAGENTA]         = "\x1B[45m",
        [TTY_BACKGROUND_CYAN]            = "\x1B[46m",
        [TTY_BACKGROUND_GRAY]            = "\x1B[47m",
        [TTY_BACKGROUND_LIGHT_RED]       = "\x1B[41;97m",
        [TTY_BACKGROUND_LIGHT_GREEN]     = "\x1B[42;97m",
        [TTY_BACKGROUND_LIGHT_YELLOW]    = "\x1B[43;97m",
        [TTY_BACKGROUND_LIGHT_BLUE]      = "\x1B[44;97m",
        [TTY_BACKGROUND_LIGHT_MAGENTA]   = "\x1B[105m",
        [TTY_BACKGROUND_LIGHT_CYAN]      = "\x1B[106m",
        [TTY_BACKGROUND_TEAL]            = "\x1B[46m",
        [TTY_BACKGROUND_PURPLE]          = "\x1B[45m",
        [TTY_BACKGROUND_PINK]            = "\x1B[45;97m",
        [TTY_BACKGROUND_ORANGE]          = "\x1B[43;91m",
};

DEFINE_STRING_TABLE_LOOKUP_TO_STRING(tty_background_color, int);

static const char* const tty_color_index_table[_TTY_COLOR_MAX_DEFINED] = {
        [TTY_BACKGROUND_BLACK]           = "black",
        [TTY_BACKGROUND_RED]             = "red",
        [TTY_BACKGROUND_GREEN]           = "green",
        [TTY_BACKGROUND_YELLOW]          = "yellow",
        [TTY_BACKGROUND_BLUE]            = "blue",
        [TTY_BACKGROUND_MAGENTA]         = "magenta",
        [TTY_BACKGROUND_CYAN]            = "cyan",
        [TTY_BACKGROUND_GRAY]            = "gray",
        [TTY_BACKGROUND_LIGHT_RED]       = "light-red",
        [TTY_BACKGROUND_LIGHT_GREEN]     = "light-green",
        [TTY_BACKGROUND_LIGHT_YELLOW]    = "light-yellow",
        [TTY_BACKGROUND_LIGHT_BLUE]      = "light-blue",
        [TTY_BACKGROUND_LIGHT_MAGENTA]   = "light-magenta",
        [TTY_BACKGROUND_LIGHT_CYAN]      = "light-cyan",
        [TTY_BACKGROUND_TEAL]            = "teal",
        [TTY_BACKGROUND_PURPLE]          = "purple",
        [TTY_BACKGROUND_PINK]            = "pink",
        [TTY_BACKGROUND_ORANGE]          = "orange",
};

DEFINE_STRING_TABLE_LOOKUP_FROM_STRING(tty_color_index, int);
