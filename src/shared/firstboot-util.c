/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <sys/signalfd.h>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "firstboot-util.h"
#include "io-util.h"
#include "log.h"
#include "proc-cmdline.h"
#include "signal-util.h"
#include "string-table.h"
#include "strv.h"
#include "terminal-util.h"

static const char* const firstboot_mode_table[_FIRSTBOOT_MODE_MAX] = {
        [FIRSTBOOT_NO]          = "no",
        [FIRSTBOOT_INTERACTIVE] = "interactive",
        [FIRSTBOOT_HEADLESS]    = "headless",
};

assert_cc(FIRSTBOOT_NO == 0);

DEFINE_STRING_TABLE_LOOKUP_WITH_BOOLEAN(firstboot_mode, FirstBootMode, FIRSTBOOT_INTERACTIVE);

int firstboot_mode_from_cmdline(FirstBootMode *ret, char **reterr_value) {
        _cleanup_free_ char *value = NULL;
        int r;

        assert(ret);

        r = proc_cmdline_get_key("systemd.firstboot", PROC_CMDLINE_VALUE_OPTIONAL, &value);
        if (r < 0)
                return r;
        if (r == 0) { /* not specified at all */
                *ret = FIRSTBOOT_INTERACTIVE;
                return 0;
        }
        if (!value) { /* key without parameter, i.e. bare "systemd.firstboot" */
                *ret = FIRSTBOOT_INTERACTIVE;
                return 1;
        }

        FirstBootMode m = firstboot_mode_from_string(value);
        if (m < 0) {
                if (reterr_value)
                        *reterr_value = TAKE_PTR(value);
                return m;
        }

        *ret = m;
        return 1;
}

typedef struct FirstBootConsole {
        int fd;
        dev_t device;
        size_t tty_index;
        struct termios saved_termios;
        bool configured;
} FirstBootConsole;

static void firstboot_console_done(FirstBootConsole *c) {
        assert(c);

        if (c->fd >= 0 && c->configured) {
                (void) tcflush(c->fd, TCIFLUSH);
                (void) tcsetattr(c->fd, TCSANOW, &c->saved_termios);
        }
        c->fd = safe_close(c->fd);
}

static DEFINE_ARRAY_FREE_FUNC(firstboot_console_array_free, FirstBootConsole, firstboot_console_done);

static int firstboot_console_prepare(FirstBootConsole *c) {
        struct termios termios;

        assert(c);
        assert(c->fd >= 0);

        if (tcgetattr(c->fd, &termios) < 0)
                return -errno;
        c->saved_termios = termios;

        /* Read individual keys without echo or line editing. Do not generate signals for control keys on a
         * terminal that may belong to another session. Map carriage return to newline for serial consoles. */
        termios.c_iflag &= ~(IGNCR|INLCR);
        termios.c_iflag |= ICRNL;
        termios.c_lflag &= ~(ICANON|ECHO|ECHONL|ISIG);
        termios.c_cc[VMIN] = 1;
        termios.c_cc[VTIME] = 0;
        if (tcsetattr(c->fd, TCSANOW, &termios) < 0)
                return -errno;
        c->configured = true;

        (void) tcflush(c->fd, TCIFLUSH);
        return loop_write(c->fd, "\r\nPress Enter to begin initial setup on this console.\r\n", SIZE_MAX);
}

int firstboot_select_console(char **ttys) {
        /* Keep the original indices so that the caller can identify the selected console. Ignore unavailable
         * consoles and aliases of devices we already opened. With only one usable console, no input is needed. */

        BLOCK_SIGNALS(SIGINT, SIGTERM, SIGHUP);
        FirstBootConsole *consoles = NULL;
        size_t n_ttys = strv_length(ttys), n_consoles = 0, n_active = 0;
        CLEANUP_ARRAY(consoles, n_consoles, firstboot_console_array_free);
        int r;

        consoles = new(FirstBootConsole, n_ttys);
        if (!consoles)
                return -ENOMEM;

        _cleanup_free_ struct pollfd *pollfds = new(struct pollfd, n_ttys + 1);
        if (!pollfds)
                return -ENOMEM;

        for (size_t i = 0; i < n_ttys; i++) {
                _cleanup_close_ int fd = open_terminal(ttys[i], O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0) {
                        log_debug_errno(fd, "Cannot open console %s, ignoring: %m", ttys[i]);
                        continue;
                }

                struct stat st;
                struct termios termios;
                if (fstat(fd, &st) < 0) {
                        log_debug_errno(errno, "Cannot inspect console %s, ignoring: %m", ttys[i]);
                        continue;
                }
                if (!S_ISCHR(st.st_mode)) {
                        log_debug("Console %s is not a character device, ignoring.", ttys[i]);
                        continue;
                }
                if (tcgetattr(fd, &termios) < 0) {
                        log_debug_errno(errno, "Cannot inspect console %s, ignoring: %m", ttys[i]);
                        continue;
                }

                bool duplicate = false;
                FOREACH_ARRAY(c, consoles, n_consoles)
                        if (c->device == st.st_rdev) {
                                duplicate = true;
                                break;
                        }
                if (duplicate)
                        continue;

                consoles[n_consoles] = (FirstBootConsole) {
                        .fd = TAKE_FD(fd),
                        .device = st.st_rdev,
                        .tty_index = i,
                };
                pollfds[n_consoles] = (struct pollfd) {
                        .fd = consoles[n_consoles].fd,
                        .events = POLLIN,
                };
                n_consoles++;
                n_active++;
        }

        if (n_active == 0)
                return -ENXIO;
        if (n_active == 1)
                return (int) consoles[0].tty_index;

        sigset_t mask;
        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM, SIGHUP) >= 0);

        _cleanup_close_ int signal_fd = signalfd(-1, &mask, SFD_CLOEXEC|SFD_NONBLOCK);
        if (signal_fd < 0)
                return -errno;
        pollfds[n_consoles] = (struct pollfd) {
                .fd = signal_fd,
                .events = POLLIN,
        };

        for (size_t i = 0; i < n_consoles; i++) {
                FirstBootConsole *c = &consoles[i];
                r = firstboot_console_prepare(c);
                if (r < 0) {
                        log_debug_errno(r, "Cannot prompt on console %s, ignoring: %m", ttys[c->tty_index]);
                        firstboot_console_done(c);
                        pollfds[i].fd = -EBADF;
                        n_active--;
                }
        }

        /* Once the prompt has been shown, consume Enter even if only one console remains. */
        while (n_active > 0) {
                r = ppoll_usec(pollfds, n_consoles + 1, USEC_INFINITY);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (pollfds[n_consoles].revents != 0)
                        return -EINTR; /* Restore all terminals before unblocking the pending signal. */

                for (size_t i = 0; i < n_consoles; i++) {
                        if (pollfds[i].revents == 0)
                                continue;

                        if (pollfds[i].revents & POLLIN) {
                                char ch;
                                ssize_t n = read(pollfds[i].fd, &ch, 1);
                                if (n < 0 && ERRNO_IS_TRANSIENT(errno))
                                        continue;
                                if (n > 0) {
                                        if (!IN_SET(ch, '\r', '\n'))
                                                continue;

                                        for (size_t j = 0; j < n_consoles; j++)
                                                if (j != i && consoles[j].fd >= 0)
                                                        (void) dprintf(consoles[j].fd,
                                                                       "\r\nInitial setup is running on %s.\r\n", ttys[consoles[i].tty_index]);
                                        return (int) consoles[i].tty_index;
                                }
                                if (n == 0 && !(pollfds[i].revents & (POLLHUP|POLLERR|POLLNVAL)))
                                        continue;
                        }

                        firstboot_console_done(&consoles[i]);
                        pollfds[i].fd = -EBADF;
                        n_active--;
                }
        }

        return -ENXIO;
}
