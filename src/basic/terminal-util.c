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

#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <time.h>
#include <assert.h>
#include <poll.h>
#include <linux/vt.h>
#include <linux/tiocl.h>
#include <linux/kd.h>

#include "terminal-util.h"
#include "time-util.h"
#include "process-util.h"
#include "util.h"
#include "fileio.h"
#include "path-util.h"

static volatile unsigned cached_columns = 0;
static volatile unsigned cached_lines = 0;

int chvt(int vt) {
        _cleanup_close_ int fd;

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        if (vt < 0) {
                int tiocl[2] = {
                        TIOCL_GETKMSGREDIRECT,
                        0
                };

                if (ioctl(fd, TIOCLINUX, tiocl) < 0)
                        return -errno;

                vt = tiocl[0] <= 0 ? 1 : tiocl[0];
        }

        if (ioctl(fd, VT_ACTIVATE, vt) < 0)
                return -errno;

        return 0;
}

int read_one_char(FILE *f, char *ret, usec_t t, bool *need_nl) {
        struct termios old_termios, new_termios;
        char c, line[LINE_MAX];

        assert(f);
        assert(ret);

        if (tcgetattr(fileno(f), &old_termios) >= 0) {
                new_termios = old_termios;

                new_termios.c_lflag &= ~ICANON;
                new_termios.c_cc[VMIN] = 1;
                new_termios.c_cc[VTIME] = 0;

                if (tcsetattr(fileno(f), TCSADRAIN, &new_termios) >= 0) {
                        size_t k;

                        if (t != USEC_INFINITY) {
                                if (fd_wait_for_event(fileno(f), POLLIN, t) <= 0) {
                                        tcsetattr(fileno(f), TCSADRAIN, &old_termios);
                                        return -ETIMEDOUT;
                                }
                        }

                        k = fread(&c, 1, 1, f);

                        tcsetattr(fileno(f), TCSADRAIN, &old_termios);

                        if (k <= 0)
                                return -EIO;

                        if (need_nl)
                                *need_nl = c != '\n';

                        *ret = c;
                        return 0;
                }
        }

        if (t != USEC_INFINITY) {
                if (fd_wait_for_event(fileno(f), POLLIN, t) <= 0)
                        return -ETIMEDOUT;
        }

        errno = 0;
        if (!fgets(line, sizeof(line), f))
                return errno ? -errno : -EIO;

        truncate_nl(line);

        if (strlen(line) != 1)
                return -EBADMSG;

        if (need_nl)
                *need_nl = false;

        *ret = line[0];
        return 0;
}

int ask_char(char *ret, const char *replies, const char *text, ...) {
        int r;

        assert(ret);
        assert(replies);
        assert(text);

        for (;;) {
                va_list ap;
                char c;
                bool need_nl = true;

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_ON, stdout);

                va_start(ap, text);
                vprintf(text, ap);
                va_end(ap);

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_OFF, stdout);

                fflush(stdout);

                r = read_one_char(stdin, &c, USEC_INFINITY, &need_nl);
                if (r < 0) {

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
        assert(ret);
        assert(text);

        for (;;) {
                char line[LINE_MAX];
                va_list ap;

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_ON, stdout);

                va_start(ap, text);
                vprintf(text, ap);
                va_end(ap);

                if (on_tty())
                        fputs(ANSI_HIGHLIGHT_OFF, stdout);

                fflush(stdout);

                errno = 0;
                if (!fgets(line, sizeof(line), stdin))
                        return errno ? -errno : -EIO;

                if (!endswith(line, "\n"))
                        putchar('\n');
                else {
                        char *s;

                        if (isempty(line))
                                continue;

                        truncate_nl(line);
                        s = strdup(line);
                        if (!s)
                                return -ENOMEM;

                        *ret = s;
                        return 0;
                }
        }
}

int reset_terminal_fd(int fd, bool switch_to_text) {
        struct termios termios;
        int r = 0;

        /* Set terminal to some sane defaults */

        assert(fd >= 0);

        /* We leave locked terminal attributes untouched, so that
         * Plymouth may set whatever it wants to set, and we don't
         * interfere with that. */

        /* Disable exclusive mode, just in case */
        (void) ioctl(fd, TIOCNXCL);

        /* Switch to text mode */
        if (switch_to_text)
                (void) ioctl(fd, KDSETMODE, KD_TEXT);

        /* Enable console unicode mode */
        (void) ioctl(fd, KDSKBMODE, K_UNICODE);

        if (tcgetattr(fd, &termios) < 0) {
                r = -errno;
                goto finish;
        }

        /* We only reset the stuff that matters to the software. How
         * hardware is set up we don't touch assuming that somebody
         * else will do that for us */

        termios.c_iflag &= ~(IGNBRK | BRKINT | ISTRIP | INLCR | IGNCR | IUCLC);
        termios.c_iflag |= ICRNL | IMAXBEL | IUTF8;
        termios.c_oflag |= ONLCR;
        termios.c_cflag |= CREAD;
        termios.c_lflag = ISIG | ICANON | IEXTEN | ECHO | ECHOE | ECHOK | ECHOCTL | ECHOPRT | ECHOKE;

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

        if (tcsetattr(fd, TCSANOW, &termios) < 0)
                r = -errno;

finish:
        /* Just in case, flush all crap out */
        (void) tcflush(fd, TCIOFLUSH);

        return r;
}

int reset_terminal(const char *name) {
        _cleanup_close_ int fd = -1;

        /* We open the terminal with O_NONBLOCK here, to ensure we
         * don't block on carrier if this is a terminal with carrier
         * configured. */

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

        return reset_terminal_fd(fd, true);
}

int open_terminal(const char *name, int mode) {
        int fd, r;
        unsigned c = 0;

        /*
         * If a TTY is in the process of being closed opening it might
         * cause EIO. This is horribly awful, but unlikely to be
         * changed in the kernel. Hence we work around this problem by
         * retrying a couple of times.
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

                usleep(50 * USEC_PER_MSEC);
                c++;
        }

        r = isatty(fd);
        if (r < 0) {
                safe_close(fd);
                return -errno;
        }

        if (!r) {
                safe_close(fd);
                return -ENOTTY;
        }

        return fd;
}

int acquire_terminal(
                const char *name,
                bool fail,
                bool force,
                bool ignore_tiocstty_eperm,
                usec_t timeout) {

        int fd = -1, notify = -1, r = 0, wd = -1;
        usec_t ts = 0;

        assert(name);

        /* We use inotify to be notified when the tty is closed. We
         * create the watch before checking if we can actually acquire
         * it, so that we don't lose any event.
         *
         * Note: strictly speaking this actually watches for the
         * device being closed, it does *not* really watch whether a
         * tty loses its controlling process. However, unless some
         * rogue process uses TIOCNOTTY on /dev/tty *after* closing
         * its tty otherwise this will not become a problem. As long
         * as the administrator makes sure not configure any service
         * on the same tty as an untrusted user this should not be a
         * problem. (Which he probably should not do anyway.) */

        if (timeout != USEC_INFINITY)
                ts = now(CLOCK_MONOTONIC);

        if (!fail && !force) {
                notify = inotify_init1(IN_CLOEXEC | (timeout != USEC_INFINITY ? IN_NONBLOCK : 0));
                if (notify < 0) {
                        r = -errno;
                        goto fail;
                }

                wd = inotify_add_watch(notify, name, IN_CLOSE);
                if (wd < 0) {
                        r = -errno;
                        goto fail;
                }
        }

        for (;;) {
                struct sigaction sa_old, sa_new = {
                        .sa_handler = SIG_IGN,
                        .sa_flags = SA_RESTART,
                };

                if (notify >= 0) {
                        r = flush_fd(notify);
                        if (r < 0)
                                goto fail;
                }

                /* We pass here O_NOCTTY only so that we can check the return
                 * value TIOCSCTTY and have a reliable way to figure out if we
                 * successfully became the controlling process of the tty */
                fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
                 * if we already own the tty. */
                assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

                /* First, try to get the tty */
                if (ioctl(fd, TIOCSCTTY, force) < 0)
                        r = -errno;

                assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

                /* Sometimes it makes sense to ignore TIOCSCTTY
                 * returning EPERM, i.e. when very likely we already
                 * are have this controlling terminal. */
                if (r < 0 && r == -EPERM && ignore_tiocstty_eperm)
                        r = 0;

                if (r < 0 && (force || fail || r != -EPERM))
                        goto fail;

                if (r >= 0)
                        break;

                assert(!fail);
                assert(!force);
                assert(notify >= 0);

                for (;;) {
                        union inotify_event_buffer buffer;
                        struct inotify_event *e;
                        ssize_t l;

                        if (timeout != USEC_INFINITY) {
                                usec_t n;

                                n = now(CLOCK_MONOTONIC);
                                if (ts + timeout < n) {
                                        r = -ETIMEDOUT;
                                        goto fail;
                                }

                                r = fd_wait_for_event(fd, POLLIN, ts + timeout - n);
                                if (r < 0)
                                        goto fail;

                                if (r == 0) {
                                        r = -ETIMEDOUT;
                                        goto fail;
                                }
                        }

                        l = read(notify, &buffer, sizeof(buffer));
                        if (l < 0) {
                                if (errno == EINTR || errno == EAGAIN)
                                        continue;

                                r = -errno;
                                goto fail;
                        }

                        FOREACH_INOTIFY_EVENT(e, buffer, l) {
                                if (e->wd != wd || !(e->mask & IN_CLOSE)) {
                                        r = -EIO;
                                        goto fail;
                                }
                        }

                        break;
                }

                /* We close the tty fd here since if the old session
                 * ended our handle will be dead. It's important that
                 * we do this after sleeping, so that we don't enter
                 * an endless loop. */
                fd = safe_close(fd);
        }

        safe_close(notify);

        r = reset_terminal_fd(fd, true);
        if (r < 0)
                log_warning_errno(r, "Failed to reset terminal: %m");

        return fd;

fail:
        safe_close(fd);
        safe_close(notify);

        return r;
}

int release_terminal(void) {
        static const struct sigaction sa_new = {
                .sa_handler = SIG_IGN,
                .sa_flags = SA_RESTART,
        };

        _cleanup_close_ int fd = -1;
        struct sigaction sa_old;
        int r = 0;

        fd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
         * by our own TIOCNOTTY */
        assert_se(sigaction(SIGHUP, &sa_new, &sa_old) == 0);

        if (ioctl(fd, TIOCNOTTY) < 0)
                r = -errno;

        assert_se(sigaction(SIGHUP, &sa_old, NULL) == 0);

        return r;
}

int terminal_vhangup_fd(int fd) {
        assert(fd >= 0);

        if (ioctl(fd, TIOCVHANGUP) < 0)
                return -errno;

        return 0;
}

int terminal_vhangup(const char *name) {
        _cleanup_close_ int fd;

        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

        return terminal_vhangup_fd(fd);
}

int vt_disallocate(const char *name) {
        int fd, r;
        unsigned u;

        /* Deallocate the VT if possible. If not possible
         * (i.e. because it is the active one), at least clear it
         * entirely (including the scrollback buffer) */

        if (!startswith(name, "/dev/"))
                return -EINVAL;

        if (!tty_is_vc(name)) {
                /* So this is not a VT. I guess we cannot deallocate
                 * it then. But let's at least clear the screen */

                fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
                if (fd < 0)
                        return fd;

                loop_write(fd,
                           "\033[r"    /* clear scrolling region */
                           "\033[H"    /* move home */
                           "\033[2J",  /* clear screen */
                           10, false);
                safe_close(fd);

                return 0;
        }

        if (!startswith(name, "/dev/tty"))
                return -EINVAL;

        r = safe_atou(name+8, &u);
        if (r < 0)
                return r;

        if (u <= 0)
                return -EINVAL;

        /* Try to deallocate */
        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

        r = ioctl(fd, VT_DISALLOCATE, u);
        safe_close(fd);

        if (r >= 0)
                return 0;

        if (errno != EBUSY)
                return -errno;

        /* Couldn't deallocate, so let's clear it fully with
         * scrollback */
        fd = open_terminal(name, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        loop_write(fd,
                   "\033[r"   /* clear scrolling region */
                   "\033[H"   /* move home */
                   "\033[3J", /* clear screen including scrollback, requires Linux 2.6.40 */
                   10, false);
        safe_close(fd);

        return 0;
}

void warn_melody(void) {
        _cleanup_close_ int fd = -1;

        fd = open("/dev/console", O_WRONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return;

        /* Yeah, this is synchronous. Kinda sucks. But well... */

        (void) ioctl(fd, KIOCSOUND, (int)(1193180/440));
        usleep(125*USEC_PER_MSEC);

        (void) ioctl(fd, KIOCSOUND, (int)(1193180/220));
        usleep(125*USEC_PER_MSEC);

        (void) ioctl(fd, KIOCSOUND, (int)(1193180/220));
        usleep(125*USEC_PER_MSEC);

        (void) ioctl(fd, KIOCSOUND, 0);
}

int make_console_stdio(void) {
        int fd, r;

        /* Make /dev/console the controlling terminal and stdin/stdout/stderr */

        fd = acquire_terminal("/dev/console", false, true, true, USEC_INFINITY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to acquire terminal: %m");

        r = make_stdio(fd);
        if (r < 0)
                return log_error_errno(r, "Failed to duplicate terminal fd: %m");

        return 0;
}

int status_vprintf(const char *status, bool ellipse, bool ephemeral, const char *format, va_list ap) {
        static const char status_indent[] = "         "; /* "[" STATUS "] " */
        _cleanup_free_ char *s = NULL;
        _cleanup_close_ int fd = -1;
        struct iovec iovec[6] = {};
        int n = 0;
        static bool prev_ephemeral;

        assert(format);

        /* This is independent of logging, as status messages are
         * optional and go exclusively to the console. */

        if (vasprintf(&s, format, ap) < 0)
                return log_oom();

        fd = open_terminal("/dev/console", O_WRONLY|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        if (ellipse) {
                char *e;
                size_t emax, sl;
                int c;

                c = fd_columns(fd);
                if (c <= 0)
                        c = 80;

                sl = status ? sizeof(status_indent)-1 : 0;

                emax = c - sl - 1;
                if (emax < 3)
                        emax = 3;

                e = ellipsize(s, emax, 50);
                if (e) {
                        free(s);
                        s = e;
                }
        }

        if (prev_ephemeral)
                IOVEC_SET_STRING(iovec[n++], "\r" ANSI_ERASE_TO_END_OF_LINE);
        prev_ephemeral = ephemeral;

        if (status) {
                if (!isempty(status)) {
                        IOVEC_SET_STRING(iovec[n++], "[");
                        IOVEC_SET_STRING(iovec[n++], status);
                        IOVEC_SET_STRING(iovec[n++], "] ");
                } else
                        IOVEC_SET_STRING(iovec[n++], status_indent);
        }

        IOVEC_SET_STRING(iovec[n++], s);
        if (!ephemeral)
                IOVEC_SET_STRING(iovec[n++], "\n");

        if (writev(fd, iovec, n) < 0)
                return -errno;

        return 0;
}

int status_printf(const char *status, bool ellipse, bool ephemeral, const char *format, ...) {
        va_list ap;
        int r;

        assert(format);

        va_start(ap, format);
        r = status_vprintf(status, ellipse, ephemeral, format, ap);
        va_end(ap);

        return r;
}

bool tty_is_vc(const char *tty) {
        assert(tty);

        return vtnr_from_tty(tty) >= 0;
}

bool tty_is_console(const char *tty) {
        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        return streq(tty, "console");
}

int vtnr_from_tty(const char *tty) {
        int i, r;

        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        if (!startswith(tty, "tty") )
                return -EINVAL;

        if (tty[3] < '0' || tty[3] > '9')
                return -EINVAL;

        r = safe_atoi(tty+3, &i);
        if (r < 0)
                return r;

        if (i < 0 || i > 63)
                return -EINVAL;

        return i;
}

char *resolve_dev_console(char **active) {
        char *tty;

        /* Resolve where /dev/console is pointing to, if /sys is actually ours
         * (i.e. not read-only-mounted which is a sign for container setups) */

        if (path_is_read_only_fs("/sys") > 0)
                return NULL;

        if (read_one_line_file("/sys/class/tty/console/active", active) < 0)
                return NULL;

        /* If multiple log outputs are configured the last one is what
         * /dev/console points to */
        tty = strrchr(*active, ' ');
        if (tty)
                tty++;
        else
                tty = *active;

        if (streq(tty, "tty0")) {
                char *tmp;

                /* Get the active VC (e.g. tty1) */
                if (read_one_line_file("/sys/class/tty/tty0/active", &tmp) >= 0) {
                        free(*active);
                        tty = *active = tmp;
                }
        }

        return tty;
}

bool tty_is_vc_resolve(const char *tty) {
        _cleanup_free_ char *active = NULL;

        assert(tty);

        if (startswith(tty, "/dev/"))
                tty += 5;

        if (streq(tty, "console")) {
                tty = resolve_dev_console(&active);
                if (!tty)
                        return false;
        }

        return tty_is_vc(tty);
}

const char *default_term_for_tty(const char *tty) {
        assert(tty);

        return tty_is_vc_resolve(tty) ? "TERM=linux" : "TERM=vt220";
}

int fd_columns(int fd) {
        struct winsize ws = {};

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_col <= 0)
                return -EIO;

        return ws.ws_col;
}

unsigned columns(void) {
        const char *e;
        int c;

        if (_likely_(cached_columns > 0))
                return cached_columns;

        c = 0;
        e = getenv("COLUMNS");
        if (e)
                (void) safe_atoi(e, &c);

        if (c <= 0)
                c = fd_columns(STDOUT_FILENO);

        if (c <= 0)
                c = 80;

        cached_columns = c;
        return cached_columns;
}

int fd_lines(int fd) {
        struct winsize ws = {};

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_row <= 0)
                return -EIO;

        return ws.ws_row;
}

unsigned lines(void) {
        const char *e;
        int l;

        if (_likely_(cached_lines > 0))
                return cached_lines;

        l = 0;
        e = getenv("LINES");
        if (e)
                (void) safe_atoi(e, &l);

        if (l <= 0)
                l = fd_lines(STDOUT_FILENO);

        if (l <= 0)
                l = 24;

        cached_lines = l;
        return cached_lines;
}

/* intended to be used as a SIGWINCH sighandler */
void columns_lines_cache_reset(int signum) {
        cached_columns = 0;
        cached_lines = 0;
}

bool on_tty(void) {
        static int cached_on_tty = -1;

        if (_unlikely_(cached_on_tty < 0))
                cached_on_tty = isatty(STDOUT_FILENO) > 0;

        return cached_on_tty;
}

int make_stdio(int fd) {
        int r, s, t;

        assert(fd >= 0);

        r = dup2(fd, STDIN_FILENO);
        s = dup2(fd, STDOUT_FILENO);
        t = dup2(fd, STDERR_FILENO);

        if (fd >= 3)
                safe_close(fd);

        if (r < 0 || s < 0 || t < 0)
                return -errno;

        /* Explicitly unset O_CLOEXEC, since if fd was < 3, then
         * dup2() was a NOP and the bit hence possibly set. */
        fd_cloexec(STDIN_FILENO, false);
        fd_cloexec(STDOUT_FILENO, false);
        fd_cloexec(STDERR_FILENO, false);

        return 0;
}

int make_null_stdio(void) {
        int null_fd;

        null_fd = open("/dev/null", O_RDWR|O_NOCTTY);
        if (null_fd < 0)
                return -errno;

        return make_stdio(null_fd);
}

int getttyname_malloc(int fd, char **ret) {
        size_t l = 100;
        int r;

        assert(fd >= 0);
        assert(ret);

        for (;;) {
                char path[l];

                r = ttyname_r(fd, path, sizeof(path));
                if (r == 0) {
                        const char *p;
                        char *c;

                        p = startswith(path, "/dev/");
                        c = strdup(p ?: path);
                        if (!c)
                                return -ENOMEM;

                        *ret = c;
                        return 0;
                }

                if (r != ERANGE)
                        return -r;

                l *= 2;
        }

        return 0;
}

int getttyname_harder(int fd, char **r) {
        int k;
        char *s = NULL;

        k = getttyname_malloc(fd, &s);
        if (k < 0)
                return k;

        if (streq(s, "tty")) {
                free(s);
                return get_ctty(0, NULL, r);
        }

        *r = s;
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

        if (major(ttynr) == 0 && minor(ttynr) == 0)
                return -ENXIO;

        if (d)
                *d = (dev_t) ttynr;

        return 0;
}

int get_ctty(pid_t pid, dev_t *_devnr, char **r) {
        char fn[sizeof("/dev/char/")-1 + 2*DECIMAL_STR_MAX(unsigned) + 1 + 1], *b = NULL;
        _cleanup_free_ char *s = NULL;
        const char *p;
        dev_t devnr;
        int k;

        assert(r);

        k = get_ctty_devnr(pid, &devnr);
        if (k < 0)
                return k;

        sprintf(fn, "/dev/char/%u:%u", major(devnr), minor(devnr));

        k = readlink_malloc(fn, &s);
        if (k < 0) {

                if (k != -ENOENT)
                        return k;

                /* This is an ugly hack */
                if (major(devnr) == 136) {
                        if (asprintf(&b, "pts/%u", minor(devnr)) < 0)
                                return -ENOMEM;
                } else {
                        /* Probably something like the ptys which have no
                         * symlink in /dev/char. Let's return something
                         * vaguely useful. */

                        b = strdup(fn + 5);
                        if (!b)
                                return -ENOMEM;
                }
        } else {
                if (startswith(s, "/dev/"))
                        p = s + 5;
                else if (startswith(s, "../"))
                        p = s + 3;
                else
                        p = s;

                b = strdup(p);
                if (!b)
                        return -ENOMEM;
        }

        *r = b;
        if (_devnr)
                *_devnr = devnr;

        return 0;
}
