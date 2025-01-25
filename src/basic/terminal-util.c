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
#include "ansi-color.h"
#include "chase.h"
#include "constants.h"
#include "devnum-util.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "glyph-util.h"
#include "hexdecoct.h"
#include "inotify-util.h"
#include "io-util.h"
#include "log.h"
#include "macro.h"
#include "missing_magic.h"
#include "namespace-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "signal-util.h"
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
static volatile int cached_color_mode = _COLOR_MODE_INVALID;
static volatile int cached_underline_enabled = -1;

bool isatty_safe(int fd) {
        assert(fd >= 0);

        if (isatty(fd))
                return true;

        /* Linux/glibc returns EIO for hung up TTY on isatty(). Which is wrong, the thing doesn't stop being
         * a TTY after all, just because it is temporarily hung up. Let's work around this here, until this
         * is fixed in glibc. See: https://sourceware.org/bugzilla/show_bug.cgi?id=32103 */
        if (errno == EIO)
                return true;

        /* Be resilient if we're working on stdio, since they're set up by parent process. */
        assert(errno != EBADF || IN_SET(fd, STDIN_FILENO, STDOUT_FILENO, STDERR_FILENO));

        return false;
}

int chvt(int vt) {
        _cleanup_close_ int fd = -EBADF;

        /* Switch to the specified vt number. If the VT is specified <= 0 switch to the VT the kernel log messages go,
         * if that's configured. */

        fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return fd;

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

        if (t != USEC_INFINITY && fd >= 0) {
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

bool any_key_to_proceed(void) {
        char key = 0;
        bool need_nl = true;

        /*
         * Insert a new line here as well as to when the user inputs, as this is also used during the
         * boot up sequence when status messages may be interleaved with the current program output.
         * This ensures that the status messages aren't appended on the same line as this message.
         */
        puts("-- Press any key to proceed --");

        (void) read_one_char(stdin, &key, USEC_INFINITY, &need_nl);

        if (need_nl)
                putchar('\n');

        return key != 'q';
}

int show_menu(char **x, unsigned n_columns, unsigned width, unsigned percentage) {
        unsigned break_lines, break_modulo;
        size_t n, per_column, i, j;

        assert(n_columns > 0);

        n = strv_length(x);
        per_column = DIV_ROUND_UP(n, n_columns);

        break_lines = lines();
        if (break_lines > 2)
                break_lines--;

        /* The first page gets two extra lines, since we want to show
         * a title */
        break_modulo = break_lines;
        if (break_modulo > 3)
                break_modulo -= 3;

        for (i = 0; i < per_column; i++) {

                for (j = 0; j < n_columns; j++) {
                        _cleanup_free_ char *e = NULL;

                        if (j * per_column + i >= n)
                                break;

                        e = ellipsize(x[j * per_column + i], width, percentage);
                        if (!e)
                                return log_oom();

                        printf("%4zu) %-*s", j * per_column + i + 1, (int) width, e);
                }

                putchar('\n');

                /* on the first screen we reserve 2 extra lines for the title */
                if (i % break_lines == break_modulo) {
                        if (!any_key_to_proceed())
                                return 0;
                }
        }

        return 0;
}

int open_terminal(const char *name, int mode) {
        _cleanup_close_ int fd = -EBADF;

        /*
         * If a TTY is in the process of being closed opening it might cause EIO. This is horribly awful, but
         * unlikely to be changed in the kernel. Hence we work around this problem by retrying a couple of
         * times.
         *
         * https://bugs.launchpad.net/ubuntu/+source/linux/+bug/554172/comments/245
         */

        assert((mode & (O_CREAT|O_PATH|O_DIRECTORY|O_TMPFILE)) == 0);

        for (unsigned c = 0;; c++) {
                fd = open(name, mode, 0);
                if (fd >= 0)
                        break;

                if (errno != EIO)
                        return -errno;

                /* Max 1s in total */
                if (c >= 20)
                        return -EIO;

                (void) usleep_safe(50 * USEC_PER_MSEC);
        }

        if (!isatty_safe(fd))
                return -ENOTTY;

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
                struct sigaction sa_old;
                assert_se(sigaction(SIGHUP, &sigaction_ignore, &sa_old) >= 0);

                /* First, try to get the tty */
                r = RET_NERRNO(ioctl(fd, TIOCSCTTY, (flags & ~ACQUIRE_TERMINAL_PERMISSIVE) == ACQUIRE_TERMINAL_FORCE));

                /* Reset signal handler to old value */
                assert_se(sigaction(SIGHUP, &sa_old, NULL) >= 0);

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
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = open("/dev/tty", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd < 0)
                return -errno;

        /* Temporarily ignore SIGHUP, so that we don't get SIGHUP'ed
         * by our own TIOCNOTTY */
        struct sigaction sa_old;
        assert_se(sigaction(SIGHUP, &sigaction_ignore, &sa_old) >= 0);

        r = RET_NERRNO(ioctl(fd, TIOCNOTTY));

        assert_se(sigaction(SIGHUP, &sa_old, NULL) >= 0);

        return r;
}

int terminal_new_session(void) {

        /* Make us the new session leader, and set stdin tty to be our controlling terminal.
         *
         * Why stdin? Well, the ctty logic is relevant for signal delivery mostly, i.e. if people hit C-c
         * or the line is hung up. Such events are basically just a form of input, via a side channel
         * (that side channel being signal delivery, i.e. SIGINT, SIGHUP et al). Hence we focus on input,
         * not output here. */

        if (!isatty_safe(STDIN_FILENO))
                return -ENXIO;

        (void) setsid();
        return RET_NERRNO(ioctl(STDIN_FILENO, TIOCSCTTY, 0));
}

int terminal_vhangup_fd(int fd) {
        assert(fd >= 0);
        return RET_NERRNO(ioctl(fd, TIOCVHANGUP));
}

int terminal_vhangup(const char *tty) {
        _cleanup_close_ int fd = -EBADF;

        assert(tty);

        fd = open_terminal(tty, O_RDWR|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return fd;

        return terminal_vhangup_fd(fd);
}

int vt_disallocate(const char *tty_path) {
        assert(tty_path);

        /* Deallocate the VT if possible. If not possible (i.e. because it is the active one), at least clear
         * it entirely (including the scrollback buffer). */

        int ttynr = vtnr_from_tty(tty_path);
        if (ttynr > 0) {
                _cleanup_close_ int fd = open_terminal("/dev/tty0", O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0)
                        return fd;

                /* Try to deallocate */
                if (ioctl(fd, VT_DISALLOCATE, ttynr) >= 0)
                        return 0;
                if (errno != EBUSY)
                        return -errno;
        }

        /* So this is not a VT (in which case we cannot deallocate it), or we failed to deallocate. Let's at
         * least clear the screen. */

        _cleanup_close_ int fd2 = open_terminal(tty_path, O_WRONLY|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
        if (fd2 < 0)
                return fd2;

        return loop_write_full(fd2,
                               "\033[r"   /* clear scrolling region */
                               "\033[H"   /* move home */
                               "\033[3J"  /* clear screen including scrollback, requires Linux 2.6.40 */
                               "\033c",   /* reset to initial state */
                               SIZE_MAX,
                               100 * USEC_PER_MSEC);
}

static int vt_default_utf8(void) {
        _cleanup_free_ char *b = NULL;
        int r;

        /* Read the default VT UTF8 setting from the kernel */

        r = read_one_line_file("/sys/module/vt/parameters/default_utf8", &b);
        if (r < 0)
                return r;

        return parse_boolean(b);
}

static int vt_reset_keyboard(int fd) {
        int r, kb;

        assert(fd >= 0);

        /* If we can't read the default, then default to Unicode. It's 2024 after all. */
        r = vt_default_utf8();
        if (r < 0)
                log_debug_errno(r, "Failed to determine kernel VT UTF-8 mode, assuming enabled: %m");

        kb = vt_default_utf8() != 0 ? K_UNICODE : K_XLATE;
        return RET_NERRNO(ioctl(fd, KDSKBMODE, kb));
}

static int terminal_reset_ioctl(int fd, bool switch_to_text) {
        struct termios termios;
        int r;

        /* Set terminal to some sane defaults */

        assert(fd >= 0);

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
        if (r < 0)
                log_debug_errno(r, "Failed to set terminal parameters: %m");

finish:
        /* Just in case, flush all crap out */
        (void) tcflush(fd, TCIOFLUSH);

        return r;
}

static int terminal_reset_ansi_seq(int fd) {
        int r, k;

        assert(fd >= 0);

        if (getenv_terminal_is_dumb())
                return 0;

        r = fd_nonblock(fd, true);
        if (r < 0)
                return log_debug_errno(r, "Failed to set terminal to non-blocking mode: %m");

        k = loop_write_full(fd,
                            "\033[!p"      /* soft terminal reset */
                            "\033]104\007" /* reset colors */
                            "\033[?7h",    /* enable line-wrapping */
                            SIZE_MAX,
                            100 * USEC_PER_MSEC);
        if (k < 0)
                log_debug_errno(k, "Failed to reset terminal through ANSI sequences: %m");

        if (r > 0) {
                r = fd_nonblock(fd, false);
                if (r < 0)
                        log_debug_errno(r, "Failed to set terminal back to blocking mode: %m");
        }

        return k < 0 ? k : r;
}

void reset_dev_console_fd(int fd, bool switch_to_text) {
        int r;

        assert(fd >= 0);

        _cleanup_close_ int lock_fd = lock_dev_console();
        if (lock_fd < 0)
                log_debug_errno(lock_fd, "Failed to lock /dev/console, ignoring: %m");

        r = terminal_reset_ioctl(fd, switch_to_text);
        if (r < 0)
                log_warning_errno(r, "Failed to reset /dev/console, ignoring: %m");

        unsigned rows, cols;
        r = proc_cmdline_tty_size("/dev/console", &rows, &cols);
        if (r < 0)
                log_warning_errno(r, "Failed to get /dev/console size, ignoring: %m");
        else if (r > 0) {
                r = terminal_set_size_fd(fd, NULL, rows, cols);
                if (r < 0)
                        log_warning_errno(r, "Failed to set configured terminal size on /dev/console, ignoring: %m");
        } else
                (void) terminal_fix_size(fd, fd);

        r = terminal_reset_ansi_seq(fd);
        if (r < 0)
                log_warning_errno(r, "Failed to reset /dev/console using ANSI sequences, ignoring: %m");
}

int lock_dev_console(void) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        /* NB: We do not use O_NOFOLLOW here, because some container managers might place a symlink to some
         * pty in /dev/console, in which case it should be fine to lock the target TTY. */
        fd = open_terminal("/dev/console", O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return fd;

        r = lock_generic(fd, LOCK_BSD, LOCK_EX);
        if (r < 0)
                return r;

        return TAKE_FD(fd);
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
                reset_dev_console_fd(fd, /* switch_to_text= */ true);

                r = rearrange_stdio(fd, fd, fd); /* This invalidates 'fd' both on success and on failure. */
                if (r < 0)
                        return log_error_errno(r, "Failed to make terminal stdin/stdout/stderr: %m");
        }

        reset_terminal_feature_caches();
        return 0;
}

static int vtnr_from_tty_raw(const char *tty, unsigned *ret) {
        assert(tty);

        tty = skip_dev_prefix(tty);

        const char *e = startswith(tty, "tty");
        if (!e)
                return -EINVAL;

        return safe_atou(e, ret);
}

int vtnr_from_tty(const char *tty) {
        unsigned u;
        int r;

        assert(tty);

        r = vtnr_from_tty_raw(tty, &u);
        if (r < 0)
                return r;
        if (!vtnr_is_valid(u))
                return -ERANGE;

        return (int) u;
}

bool tty_is_vc(const char *tty) {
        assert(tty);

        /* NB: for >= 0 values no range check is conducted here, on the assumption that the caller will
         * either extract vtnr through vtnr_from_tty() later where ERANGE would be reported, or doesn't care
         * about whether it's strictly valid, but only asking "does this fall into the vt catogory?", for which
         * "yes" seems to be a better answer. */

        return vtnr_from_tty_raw(tty, /* ret = */ NULL) >= 0;
}

bool tty_is_console(const char *tty) {
        assert(tty);

        return streq(skip_dev_prefix(tty), "console");
}

int resolve_dev_console(char **ret) {
        int r;

        assert(ret);

        /* Resolve where /dev/console is pointing to. If /dev/console is a symlink (like in container
         * managers), we'll just resolve the symlink. If it's a real device node, we'll use if
         * /sys/class/tty/tty0/active, but only if /sys/ is actually ours (i.e. not read-only-mounted which
         * is a sign for container setups). */

        _cleanup_free_ char *chased = NULL;
        r = chase("/dev/console", /* root= */ NULL, /* chase_flags= */ 0,  &chased, /* ret_fd= */ NULL);
        if (r < 0)
                return r;
        if (!path_equal(chased, "/dev/console")) {
                *ret = TAKE_PTR(chased);
                return 0;
        }

        r = path_is_read_only_fs("/sys");
        if (r < 0)
                return r;
        if (r > 0)
                return -ENOMEDIUM;

        _cleanup_free_ char *active = NULL;
        r = read_one_line_file("/sys/class/tty/console/active", &active);
        if (r < 0)
                return r;

        /* If multiple log outputs are configured the last one is what /dev/console points to */
        const char *tty = strrchr(active, ' ');
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

        if (tty != active)
                return strdup_to(ret, tty);

        *ret = TAKE_PTR(active);
        return 0;
}

int get_kernel_consoles(char ***ret) {
        _cleanup_strv_free_ char **l = NULL;
        _cleanup_free_ char *line = NULL;
        int r;

        assert(ret);

        /* If /sys/ is mounted read-only this means we are running in some kind of container environment.
         * In that case /sys/ would reflect the host system, not us, hence ignore the data we can read from it. */
        if (path_is_read_only_fs("/sys") > 0)
                goto fallback;

        r = read_one_line_file("/sys/class/tty/console/active", &line);
        if (r < 0)
                return r;

        for (const char *p = line;;) {
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
        return strv_length(*ret);

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

const char* default_term_for_tty(const char *tty) {
        return tty && tty_is_vc_resolve(tty) ? "linux" : "vt220";
}

int fd_columns(int fd) {
        struct winsize ws = {};

        if (fd < 0)
                return -EBADF;

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return -errno;

        if (ws.ws_col <= 0)
                return -ENODATA; /* some tty types come up with invalid row/column initially, return a recognizable error for that */

        return ws.ws_col;
}

int getenv_columns(void) {
        int r;

        const char *e = getenv("COLUMNS");
        if (!e)
                return -ENXIO;

        unsigned c;
        r = safe_atou_bounded(e, 1, USHRT_MAX, &c);
        if (r < 0)
                return r;

        return (int) c;
}

unsigned columns(void) {

        if (cached_columns > 0)
                return cached_columns;

        int c = getenv_columns();
        if (c < 0) {
                c = fd_columns(STDOUT_FILENO);
                if (c < 0)
                        c = 80;
        }

        assert(c > 0);

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
                return -ENODATA; /* some tty types come up with invalid row/column initially, return a recognizable error for that */

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

        assert(fd >= 0);

        if (!ident)
                ident = "TTY";

        if (rows == UINT_MAX && cols == UINT_MAX)
                return 0;

        if (ioctl(fd, TIOCGWINSZ, &ws) < 0)
                return log_debug_errno(errno,
                                       "TIOCGWINSZ ioctl for getting %s size failed, not setting terminal size: %m",
                                       ident);

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
                return log_debug_errno(errno, "TIOCSWINSZ ioctl for setting %s size failed: %m", ident);

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
        if (path_startswith(tty, "pts/"))
                return -EMEDIUMTYPE;
        if (!in_charset(tty, ALPHANUMERICAL))
                return log_debug_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "TTY name '%s' contains non-alphanumeric characters, not searching kernel cmdline for size.", tty);

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

        return rows != UINT_MAX || cols != UINT_MAX;
}

/* intended to be used as a SIGWINCH sighandler */
void columns_lines_cache_reset(int signum) {
        cached_columns = 0;
        cached_lines = 0;
}

void reset_terminal_feature_caches(void) {
        cached_columns = 0;
        cached_lines = 0;

        cached_color_mode = _COLOR_MODE_INVALID;
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
                        isatty_safe(STDOUT_FILENO) &&
                        isatty_safe(STDERR_FILENO);

        return cached_on_tty;
}

int getttyname_malloc(int fd, char **ret) {
        char path[PATH_MAX]; /* PATH_MAX is counted *with* the trailing NUL byte */
        int r;

        assert(fd >= 0);
        assert(ret);

        r = ttyname_r(fd, path, sizeof path); /* positive error */
        assert(r >= 0);
        if (r == ERANGE)
                return -ENAMETOOLONG;
        if (r > 0)
                return -r;

        return strdup_to(ret, skip_dev_prefix(path));
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

int get_ctty_devnr(pid_t pid, dev_t *ret) {
        _cleanup_free_ char *line = NULL;
        unsigned long ttynr;
        const char *p;
        int r;

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

        if (ret)
                *ret = (dev_t) ttynr;

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
                r = strdup_to(ret, w);
                if (r < 0)
                        return r;
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

int openpt_allocate(int flags, char **ret_peer_path) {
        _cleanup_close_ int fd = -EBADF;
        int r;

        fd = posix_openpt(flags|O_NOCTTY|O_CLOEXEC);
        if (fd < 0)
                return -errno;

        _cleanup_free_ char *p = NULL;
        if (ret_peer_path) {
                r = ptsname_malloc(fd, &p);
                if (r < 0)
                        return r;

                if (!path_startswith(p, "/dev/pts/"))
                        return -EINVAL;
        }

        if (unlockpt(fd) < 0)
                return -errno;

        if (ret_peer_path)
                *ret_peer_path = TAKE_PTR(p);

        return TAKE_FD(fd);
}

static int ptsname_namespace(int pty, char **ret) {
        int no = -1;

        assert(pty >= 0);
        assert(ret);

        /* Like ptsname(), but doesn't assume that the path is
         * accessible in the local namespace. */

        if (ioctl(pty, TIOCGPTN, &no) < 0)
                return -errno;

        if (no < 0)
                return -EIO;

        if (asprintf(ret, "/dev/pts/%i", no) < 0)
                return -ENOMEM;

        return 0;
}

int openpt_allocate_in_namespace(
                const PidRef *pidref,
                int flags,
                char **ret_peer_path) {

        _cleanup_close_ int pidnsfd = -EBADF, mntnsfd = -EBADF, usernsfd = -EBADF, rootfd = -EBADF, fd = -EBADF;
        _cleanup_close_pair_ int pair[2] = EBADF_PAIR;
        int r;

        r = pidref_namespace_open(pidref, &pidnsfd, &mntnsfd, /* ret_netns_fd = */ NULL, &usernsfd, &rootfd);
        if (r < 0)
                return r;

        if (socketpair(AF_UNIX, SOCK_DGRAM|SOCK_CLOEXEC, 0, pair) < 0)
                return -errno;

        r = namespace_fork(
                        "(sd-openptns)",
                        "(sd-openpt)",
                        /* except_fds= */ NULL,
                        /* n_except_fds= */ 0,
                        FORK_RESET_SIGNALS|FORK_DEATHSIG_SIGKILL|FORK_WAIT,
                        pidnsfd,
                        mntnsfd,
                        /* netns_fd= */ -EBADF,
                        usernsfd,
                        rootfd,
                        /* ret_pid= */ NULL);
        if (r < 0)
                return r;
        if (r == 0) {
                pair[0] = safe_close(pair[0]);

                fd = openpt_allocate(flags, /* ret_peer_path= */ NULL);
                if (fd < 0)
                        _exit(EXIT_FAILURE);

                if (send_one_fd(pair[1], fd, 0) < 0)
                        _exit(EXIT_FAILURE);

                _exit(EXIT_SUCCESS);
        }

        pair[1] = safe_close(pair[1]);

        fd = receive_one_fd(pair[0], 0);
        if (fd < 0)
                return fd;

        if (ret_peer_path) {
                r = ptsname_namespace(fd, ret_peer_path);
                if (r < 0)
                        return r;
        }

        return TAKE_FD(fd);
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

bool getenv_terminal_is_dumb(void) {
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

static const char* const color_mode_table[_COLOR_MODE_MAX] = {
        [COLOR_OFF]   = "off",
        [COLOR_16]    = "16",
        [COLOR_256]   = "256",
        [COLOR_24BIT] = "24bit",
};

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(color_mode, ColorMode, COLOR_24BIT);

static ColorMode parse_systemd_colors(void) {
        const char *e;

        e = getenv("SYSTEMD_COLORS");
        if (!e)
                return _COLOR_MODE_INVALID;

        ColorMode m = color_mode_from_string(e);
        if (m < 0)
                return log_debug_errno(m, "Failed to parse $SYSTEMD_COLORS value '%s', ignoring: %m", e);

        return m;
}

static ColorMode get_color_mode_impl(void) {
        /* Returns the mode used to choose output colors. The possible modes are COLOR_OFF for no colors,
         * COLOR_16 for only the base 16 ANSI colors, COLOR_256 for more colors, and COLOR_24BIT for
         * unrestricted color output. */

        /* First, we check $SYSTEMD_COLORS, which is the explicit way to change the mode. */
        ColorMode m = parse_systemd_colors();
        if (m >= 0)
                return m;

        /* Next, check for the presence of $NO_COLOR; value is ignored. */
        if (getenv("NO_COLOR"))
                return COLOR_OFF;

        /* If the above didn't work, we turn colors off unless we are on a TTY. And if we are on a TTY we
         * turn it off if $TERM is set to "dumb". There's one special tweak though: if we are PID 1 then we
         * do not check whether we are connected to a TTY, because we don't keep /dev/console open
         * continuously due to fear of SAK, and hence things are a bit weird. */
        if (getpid_cached() == 1 ? getenv_terminal_is_dumb() : terminal_is_dumb())
                return COLOR_OFF;

        /* We failed to figure out any reason to *disable* colors. Let's see how many colors we shall use. */
        if (STRPTR_IN_SET(getenv("COLORTERM"),
                          "truecolor",
                          "24bit"))
                return COLOR_24BIT;

        /* Note that the Linux console can only display 16 colors. We still enable 256 color mode
         * even for PID1 output though (which typically goes to the Linux console), since the Linux
         * console is able to parse the 256 color sequences and automatically map them to the closest
         * color in the 16 color palette (since kernel 3.16). Doing 256 colors is nice for people who
         * invoke systemd in a container or via a serial link or such, and use a true 256 color
         * terminal to do so. */
        return COLOR_256;
}

ColorMode get_color_mode(void) {
        if (cached_color_mode < 0)
                cached_color_mode = get_color_mode_impl();

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

int vt_restore(int fd) {

        static const struct vt_mode mode = {
                .mode = VT_AUTO,
        };

        int r, ret = 0;

        assert(fd >= 0);

        if (!isatty_safe(fd))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTTY), "Asked to restore the VT for an fd that does not refer to a terminal: %m");

        if (ioctl(fd, KDSETMODE, KD_TEXT) < 0)
                RET_GATHER(ret, log_debug_errno(errno, "Failed to set VT to text mode, ignoring: %m"));

        r = vt_reset_keyboard(fd);
        if (r < 0)
                RET_GATHER(ret, log_debug_errno(r, "Failed to reset keyboard mode, ignoring: %m"));

        if (ioctl(fd, VT_SETMODE, &mode) < 0)
                RET_GATHER(ret, log_debug_errno(errno, "Failed to set VT_AUTO mode, ignoring: %m"));

        r = fchmod_and_chown(fd, TTY_MODE, 0, GID_INVALID);
        if (r < 0)
                RET_GATHER(ret, log_debug_errno(r, "Failed to chmod()/chown() VT, ignoring: %m"));

        return ret;
}

int vt_release(int fd, bool restore) {
        assert(fd >= 0);

        /* This function releases the VT by acknowledging the VT-switch signal
         * sent by the kernel and optionally reset the VT in text and auto
         * VT-switching modes. */

        if (!isatty_safe(fd))
                return log_debug_errno(SYNTHETIC_ERRNO(ENOTTY), "Asked to release the VT for an fd that does not refer to a terminal: %m");

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

int terminal_set_cursor_position(int fd, unsigned row, unsigned column) {
        assert(fd >= 0);

        char cursor_position[STRLEN("\x1B[" ";" "H") + DECIMAL_STR_MAX(unsigned) * 2 + 1];
        xsprintf(cursor_position, "\x1B[%u;%uH", row, column);

        return loop_write(fd, cursor_position, SIZE_MAX);
}

int terminal_reset_defensive(int fd, bool switch_to_text) {
        int r = 0;

        assert(fd >= 0);

        /* Resets the terminal comprehensively, but defensively. i.e. both resets the tty via ioctl()s and
         * via ANSI sequences, but avoids the latter in case we are talking to a pty. That's a safety measure
         * because ptys might be connected to shell pipelines where we cannot expect such ansi sequences to
         * work. Given that ptys are generally short-lived (and not recycled) this restriction shouldn't hurt
         * much.
         *
         * The specified fd should be open for *writing*! */

        if (!isatty_safe(fd))
                return -ENOTTY;

        RET_GATHER(r, terminal_reset_ioctl(fd, switch_to_text));

        if (terminal_is_pty_fd(fd) == 0)
                RET_GATHER(r, terminal_reset_ansi_seq(fd));

        return r;
}

int terminal_reset_defensive_locked(int fd, bool switch_to_text) {
        assert(fd >= 0);

        _cleanup_close_ int lock_fd = lock_dev_console();
        if (lock_fd < 0)
                log_debug_errno(lock_fd, "Failed to acquire lock for /dev/console, ignoring: %m");

        return terminal_reset_defensive(fd, switch_to_text);
}

void termios_disable_echo(struct termios *termios) {
        assert(termios);

        termios->c_lflag &= ~(ICANON|ECHO);
        termios->c_cc[VMIN] = 1;
        termios->c_cc[VTIME] = 0;
}

static int terminal_verify_same(int input_fd, int output_fd) {
        assert(input_fd >= 0);
        assert(output_fd >= 0);

        /* Validates that the specified fds reference the same TTY */

        if (input_fd != output_fd) {
                struct stat sti;
                if (fstat(input_fd, &sti) < 0)
                        return -errno;

                if (!S_ISCHR(sti.st_mode)) /* TTYs are character devices */
                        return -ENOTTY;

                struct stat sto;
                if (fstat(output_fd, &sto) < 0)
                        return -errno;

                if (!S_ISCHR(sto.st_mode))
                        return -ENOTTY;

                if (sti.st_rdev != sto.st_rdev)
                        return -ENOLINK;
        }

        if (!isatty_safe(input_fd)) /* The check above was just for char device, but now let's ensure it's actually a tty */
                return -ENOTTY;

        return 0;
}

typedef enum BackgroundColorState {
        BACKGROUND_TEXT,
        BACKGROUND_ESCAPE,
        BACKGROUND_BRACKET,
        BACKGROUND_FIRST_ONE,
        BACKGROUND_SECOND_ONE,
        BACKGROUND_SEMICOLON,
        BACKGROUND_R,
        BACKGROUND_G,
        BACKGROUND_B,
        BACKGROUND_RED,
        BACKGROUND_GREEN,
        BACKGROUND_BLUE,
        BACKGROUND_STRING_TERMINATOR,
} BackgroundColorState;

typedef struct BackgroundColorContext {
        BackgroundColorState state;
        uint32_t red, green, blue;
        unsigned red_bits, green_bits, blue_bits;
} BackgroundColorContext;

static int scan_background_color_response(
                BackgroundColorContext *context,
                const char *buf,
                size_t size,
                size_t *ret_processed) {

        assert(context);
        assert(buf || size == 0);

        for (size_t i = 0; i < size; i++) {
                char c = buf[i];

                switch (context->state) {

                case BACKGROUND_TEXT:
                        context->state = c == '\x1B' ? BACKGROUND_ESCAPE : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_ESCAPE:
                        context->state = c == ']' ? BACKGROUND_BRACKET : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_BRACKET:
                        context->state = c == '1' ? BACKGROUND_FIRST_ONE : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_FIRST_ONE:
                        context->state = c == '1' ? BACKGROUND_SECOND_ONE : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_SECOND_ONE:
                        context->state = c == ';' ? BACKGROUND_SEMICOLON : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_SEMICOLON:
                        context->state = c == 'r' ? BACKGROUND_R : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_R:
                        context->state = c == 'g' ? BACKGROUND_G : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_G:
                        context->state = c == 'b' ? BACKGROUND_B : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_B:
                        context->state = c == ':' ? BACKGROUND_RED : BACKGROUND_TEXT;
                        break;

                case BACKGROUND_RED:
                        if (c == '/')
                                context->state = context->red_bits > 0 ? BACKGROUND_GREEN : BACKGROUND_TEXT;
                        else {
                                int d = unhexchar(c);
                                if (d < 0 || context->red_bits >= sizeof(context->red)*8)
                                        context->state = BACKGROUND_TEXT;
                                else {
                                        context->red = (context->red << 4) | d;
                                        context->red_bits += 4;
                                }
                        }
                        break;

                case BACKGROUND_GREEN:
                        if (c == '/')
                                context->state = context->green_bits > 0 ? BACKGROUND_BLUE : BACKGROUND_TEXT;
                        else {
                                int d = unhexchar(c);
                                if (d < 0 || context->green_bits >= sizeof(context->green)*8)
                                        context->state = BACKGROUND_TEXT;
                                else {
                                        context->green = (context->green << 4) | d;
                                        context->green_bits += 4;
                                }
                        }
                        break;

                case BACKGROUND_BLUE:
                        if (c == '\x07') {
                                if (context->blue_bits > 0) {
                                        if (ret_processed)
                                                *ret_processed = i + 1;

                                        return 1; /* success! */
                                }

                                context->state = BACKGROUND_TEXT;
                        } else if (c == '\x1b')
                                context->state = context->blue_bits > 0 ? BACKGROUND_STRING_TERMINATOR : BACKGROUND_TEXT;
                        else {
                                int d = unhexchar(c);
                                if (d < 0 || context->blue_bits >= sizeof(context->blue)*8)
                                        context->state = BACKGROUND_TEXT;
                                else {
                                        context->blue = (context->blue << 4) | d;
                                        context->blue_bits += 4;
                                }
                        }
                        break;

                case BACKGROUND_STRING_TERMINATOR:
                        if (c == '\\') {
                                if (ret_processed)
                                        *ret_processed = i + 1;

                                return 1; /* success! */
                        }

                        context->state = c == ']' ? BACKGROUND_ESCAPE : BACKGROUND_TEXT;
                        break;

                }

                /* Reset any colors we might have picked up */
                if (IN_SET(context->state, BACKGROUND_TEXT, BACKGROUND_ESCAPE)) {
                        /* reset color */
                        context->red = context->green = context->blue = 0;
                        context->red_bits = context->green_bits = context->blue_bits = 0;
                }
        }

        if (ret_processed)
                *ret_processed = size;

        return 0; /* all good, but not enough data yet */
}

int get_default_background_color(double *ret_red, double *ret_green, double *ret_blue) {
        _cleanup_close_ int nonblock_input_fd = -EBADF;
        int r;

        assert(ret_red);
        assert(ret_green);
        assert(ret_blue);

        if (!colors_enabled())
                return -EOPNOTSUPP;

        r = terminal_verify_same(STDIN_FILENO, STDOUT_FILENO);
        if (r < 0)
                return r;

        if (streq_ptr(getenv("TERM"), "linux")) {
                /* Linux console is black */
                *ret_red = *ret_green = *ret_blue = 0.0;
                return 0;
        }

        struct termios old_termios;
        if (tcgetattr(STDIN_FILENO, &old_termios) < 0)
                return -errno;

        struct termios new_termios = old_termios;
        termios_disable_echo(&new_termios);

        if (tcsetattr(STDIN_FILENO, TCSADRAIN, &new_termios) < 0)
                return -errno;

        r = loop_write(STDOUT_FILENO, ANSI_OSC "11;?" ANSI_ST, SIZE_MAX);
        if (r < 0)
                goto finish;

        /* Open a 2nd input fd, in non-blocking mode, so that we won't ever hang in read() should someone
         * else process the POLLIN. */

        nonblock_input_fd = fd_reopen(STDIN_FILENO, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (nonblock_input_fd < 0)
                return nonblock_input_fd;

        usec_t end = usec_add(now(CLOCK_MONOTONIC), 333 * USEC_PER_MSEC);
        char buf[STRLEN(ANSI_OSC "11;rgb:0/0/0" ANSI_ST)]; /* shortest possible reply */
        size_t buf_full = 0;
        BackgroundColorContext context = {};

        for (bool first = true;; first = false) {
                if (buf_full == 0) {
                        usec_t n = now(CLOCK_MONOTONIC);
                        if (n >= end) {
                                r = -EOPNOTSUPP;
                                goto finish;
                        }

                        r = fd_wait_for_event(nonblock_input_fd, POLLIN, usec_sub_unsigned(end, n));
                        if (r < 0)
                                goto finish;
                        if (r == 0) {
                                r = -EOPNOTSUPP;
                                goto finish;
                        }

                        /* On the first try, read multiple characters, i.e. the shortest valid
                         * reply. Afterwards read byte-wise, since we don't want to read too much, and
                         * unnecessarily drop too many characters from the input queue. */
                        ssize_t l = read(nonblock_input_fd, buf, first ? sizeof(buf) : 1);
                        if (l < 0) {
                                if (errno == EAGAIN)
                                        continue;
                                r = -errno;
                                goto finish;
                        }

                        assert((size_t) l <= sizeof(buf));
                        buf_full = l;
                }

                size_t processed;
                r = scan_background_color_response(&context, buf, buf_full, &processed);
                if (r < 0)
                        goto finish;

                assert(processed <= buf_full);
                buf_full -= processed;
                memmove(buf, buf + processed, buf_full);

                if (r > 0) {
                        assert(context.red_bits > 0);
                        *ret_red = (double) context.red / ((UINT64_C(1) << context.red_bits) - 1);
                        assert(context.green_bits > 0);
                        *ret_green = (double) context.green / ((UINT64_C(1) << context.green_bits) - 1);
                        assert(context.blue_bits > 0);
                        *ret_blue = (double) context.blue / ((UINT64_C(1) << context.blue_bits) - 1);
                        r = 0;
                        goto finish;
                }
        }

finish:
        RET_GATHER(r, RET_NERRNO(tcsetattr(STDIN_FILENO, TCSADRAIN, &old_termios)));
        return r;
}

typedef enum CursorPositionState {
        CURSOR_TEXT,
        CURSOR_ESCAPE,
        CURSOR_ROW,
        CURSOR_COLUMN,
} CursorPositionState;

typedef struct CursorPositionContext {
        CursorPositionState state;
        unsigned row, column;
} CursorPositionContext;

static int scan_cursor_position_response(
                CursorPositionContext *context,
                const char *buf,
                size_t size,
                size_t *ret_processed) {

        assert(context);
        assert(buf || size == 0);

        for (size_t i = 0; i < size; i++) {
                char c = buf[i];

                switch (context->state) {

                case CURSOR_TEXT:
                        context->state = c == '\x1B' ? CURSOR_ESCAPE : CURSOR_TEXT;
                        break;

                case CURSOR_ESCAPE:
                        context->state = c == '[' ? CURSOR_ROW : CURSOR_TEXT;
                        break;

                case CURSOR_ROW:
                        if (c == ';')
                                context->state = context->row > 0 ? CURSOR_COLUMN : CURSOR_TEXT;
                        else {
                                int d = undecchar(c);

                                /* We read a decimal character, let's suffix it to the number we so far read,
                                 * but let's do an overflow check first. */
                                if (d < 0 || context->row > (UINT_MAX-d)/10)
                                        context->state = CURSOR_TEXT;
                                else
                                        context->row = context->row * 10 + d;
                        }
                        break;

                case CURSOR_COLUMN:
                        if (c == 'R') {
                                if (context->column > 0) {
                                        if (ret_processed)
                                                *ret_processed = i + 1;

                                        return 1; /* success! */
                                }

                                context->state = CURSOR_TEXT;
                        } else {
                                int d = undecchar(c);

                                /* As above, add the decimal charatcer to our column number */
                                if (d < 0 || context->column > (UINT_MAX-d)/10)
                                        context->state = CURSOR_TEXT;
                                else
                                        context->column = context->column * 10 + d;
                        }

                        break;
                }

                /* Reset any positions we might have picked up */
                if (IN_SET(context->state, CURSOR_TEXT, CURSOR_ESCAPE))
                        context->row = context->column = 0;
        }

        if (ret_processed)
                *ret_processed = size;

        return 0; /* all good, but not enough data yet */
}

int terminal_get_size_by_dsr(
                int input_fd,
                int output_fd,
                unsigned *ret_rows,
                unsigned *ret_columns) {

        _cleanup_close_ int nonblock_input_fd = -EBADF;

        assert(input_fd >= 0);
        assert(output_fd >= 0);

        int r;

        /* Tries to determine the terminal dimension by means of ANSI sequences rather than TIOCGWINSZ
         * ioctl(). Why bother with this? The ioctl() information is often incorrect on serial terminals
         * (since there's no handshake or protocol to determine the right dimensions in RS232), but since the
         * ANSI sequences are interpreted by the final terminal instead of an intermediary tty driver they
         * should be more accurate.
         *
         * Unfortunately there's no direct ANSI sequence to query terminal dimensions. But we can hack around
         * it: we position the cursor briefly at an absolute location very far down and very far to the
         * right, and then read back where we actually ended up. Because cursor locations are capped at the
         * terminal width/height we should then see the right values. In order to not risk integer overflows
         * in terminal applications we'll use INT16_MAX-1 as location to jump to — hopefully a value that is
         * large enough for any real-life terminals, but small enough to not overflow anything or be
         * recognized as a "niche" value. (Note that the dimension fields in "struct winsize" are 16bit only,
         * too). */

        if (terminal_is_dumb())
                return -EOPNOTSUPP;

        r = terminal_verify_same(input_fd, output_fd);
        if (r < 0)
                return log_debug_errno(r, "Called with distinct input/output fds: %m");

        struct termios old_termios;
        if (tcgetattr(input_fd, &old_termios) < 0)
                return log_debug_errno(errno, "Failed to to get terminal settings: %m");

        struct termios new_termios = old_termios;
        termios_disable_echo(&new_termios);

        if (tcsetattr(input_fd, TCSADRAIN, &new_termios) < 0)
                return log_debug_errno(errno, "Failed to to set new terminal settings: %m");

        unsigned saved_row = 0, saved_column = 0;

        r = loop_write(output_fd,
                       "\x1B[6n"           /* Request cursor position (DSR/CPR) */
                       "\x1B[32766;32766H" /* Position cursor really far to the right and to the bottom, but let's stay within the 16bit signed range */
                       "\x1B[6n",          /* Request cursor position again */
                       SIZE_MAX);
        if (r < 0)
                goto finish;

        /* Open a 2nd input fd, in non-blocking mode, so that we won't ever hang in read() should someone
         * else process the POLLIN. */

        nonblock_input_fd = fd_reopen(input_fd, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (nonblock_input_fd < 0)
                return nonblock_input_fd;

        usec_t end = usec_add(now(CLOCK_MONOTONIC), 333 * USEC_PER_MSEC);
        char buf[STRLEN("\x1B[1;1R")]; /* The shortest valid reply possible */
        size_t buf_full = 0;
        CursorPositionContext context = {};

        for (bool first = true;; first = false) {
                if (buf_full == 0) {
                        usec_t n = now(CLOCK_MONOTONIC);
                        if (n >= end) {
                                r = -EOPNOTSUPP;
                                goto finish;
                        }

                        r = fd_wait_for_event(nonblock_input_fd, POLLIN, usec_sub_unsigned(end, n));
                        if (r < 0)
                                goto finish;
                        if (r == 0) {
                                r = -EOPNOTSUPP;
                                goto finish;
                        }

                        /* On the first try, read multiple characters, i.e. the shortest valid
                         * reply. Afterwards read byte-wise, since we don't want to read too much, and
                         * unnecessarily drop too many characters from the input queue. */
                        ssize_t l = read(nonblock_input_fd, buf, first ? sizeof(buf) : 1);
                        if (l < 0) {
                                if (errno == EAGAIN)
                                        continue;

                                r = -errno;
                                goto finish;
                        }

                        assert((size_t) l <= sizeof(buf));
                        buf_full = l;
                }

                size_t processed;
                r = scan_cursor_position_response(&context, buf, buf_full, &processed);
                if (r < 0)
                        goto finish;

                assert(processed <= buf_full);
                buf_full -= processed;
                memmove(buf, buf + processed, buf_full);

                if (r > 0) {
                        if (saved_row == 0) {
                                assert(saved_column == 0);

                                /* First sequence, this is the cursor position before we set it somewhere
                                 * into the void at the bottom right. Let's save where we are so that we can
                                 * return later. */

                                /* Superficial validity checks */
                                if (context.row <= 0 || context.column <= 0 || context.row >= 32766 || context.column >= 32766) {
                                        r = -ENODATA;
                                        goto finish;
                                }

                                saved_row = context.row;
                                saved_column = context.column;

                                /* Reset state */
                                context = (CursorPositionContext) {};
                        } else {
                                /* Second sequence, this is the cursor position after we set it somewhere
                                 * into the void at the bottom right. */

                                /* Superficial validity checks (no particular reason to check for < 4, it's
                                 * just a way to look for unreasonably small values) */
                                if (context.row < 4 || context.column < 4 || context.row >= 32766 || context.column >= 32766) {
                                        r = -ENODATA;
                                        goto finish;
                                }

                                if (ret_rows)
                                        *ret_rows = context.row;
                                if (ret_columns)
                                        *ret_columns = context.column;

                                r = 0;
                                goto finish;
                        }
                }
        }

finish:
        /* Restore cursor position */
        if (saved_row > 0 && saved_column > 0)
                RET_GATHER(r, terminal_set_cursor_position(output_fd, saved_row, saved_column));

        RET_GATHER(r, RET_NERRNO(tcsetattr(input_fd, TCSADRAIN, &old_termios)));
        return r;
}

int terminal_fix_size(int input_fd, int output_fd) {
        unsigned rows, columns;
        int r;

        /* Tries to update the current terminal dimensions to the ones reported via ANSI sequences */

        r = terminal_verify_same(input_fd, output_fd);
        if (r < 0)
                return r;

        struct winsize ws = {};
        if (ioctl(output_fd, TIOCGWINSZ, &ws) < 0)
                return log_debug_errno(errno, "Failed to query terminal dimensions, ignoring: %m");

        r = terminal_get_size_by_dsr(input_fd, output_fd, &rows, &columns);
        if (r < 0)
                return log_debug_errno(r, "Failed to acquire terminal dimensions via ANSI sequences, not adjusting terminal dimensions: %m");

        if (ws.ws_row == rows && ws.ws_col == columns) {
                log_debug("Terminal dimensions reported via ANSI sequences match currently set terminal dimensions, not changing.");
                return 0;
        }

        ws.ws_col = columns;
        ws.ws_row = rows;

        if (ioctl(output_fd, TIOCSWINSZ, &ws) < 0)
                return log_debug_errno(errno, "Failed to update terminal dimensions, ignoring: %m");

        log_debug("Fixed terminal dimensions to %ux%u based on ANSI sequence information.", columns, rows);
        return 1;
}

int terminal_is_pty_fd(int fd) {
        int r;

        assert(fd >= 0);

        /* Returns true if we are looking at a pty, i.e. if it's backed by the /dev/pts/ file system */

        if (!isatty_safe(fd))
                return false;

        r = is_fs_type_at(fd, NULL, DEVPTS_SUPER_MAGIC);
        if (r != 0)
                return r;

        /* The ptmx device is weird, it exists twice, once inside and once outside devpts. To detect the
         * latter case, let's fire off an ioctl() that only works on ptmx devices. */

        int v;
        if (ioctl(fd, TIOCGPKT, &v) < 0) {
                if (ERRNO_IS_NOT_SUPPORTED(errno))
                        return false;

                return -errno;
        }

        return true;
}

int pty_open_peer(int fd, int mode) {
        assert(fd >= 0);

        /* Opens the peer PTY using the new race-free TIOCGPTPEER ioctl() (kernel 4.13).
         *
         * This is safe to be called on TTYs from other namespaces. */

        assert((mode & (O_CREAT|O_PATH|O_DIRECTORY|O_TMPFILE)) == 0);

        /* This replicates the EIO retry logic of open_terminal() in a modified way. */
        for (unsigned c = 0;; c++) {
                int peer_fd = ioctl(fd, TIOCGPTPEER, mode);
                if (peer_fd >= 0)
                        return peer_fd;

                if (errno != EIO)
                        return -errno;

                /* Max 1s in total */
                if (c >= 20)
                        return -EIO;

                (void) usleep_safe(50 * USEC_PER_MSEC);
        }
}
