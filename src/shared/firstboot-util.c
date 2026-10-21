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
        struct termios saved_termios;
        bool configured;
} FirstBootConsole;

typedef struct FirstBootConsoles {
        FirstBootConsole *items;
        size_t n_items;
} FirstBootConsoles;

static void firstboot_console_done(FirstBootConsole *c) {
        assert(c);

        if (c->fd >= 0 && c->configured) {
                (void) tcflush(c->fd, TCIFLUSH);
                (void) tcsetattr(c->fd, TCSANOW, &c->saved_termios);
        }
        c->fd = safe_close(c->fd);
}

static void firstboot_consoles_done(FirstBootConsoles *c) {
        assert(c);

        FOREACH_ARRAY(i, c->items, c->n_items)
                firstboot_console_done(i);

        free(c->items);
}

static int firstboot_console_prepare(FirstBootConsole *c) {
        struct termios termios;

        assert(c);
        assert(c->fd >= 0);

        if (tcgetattr(c->fd, &termios) < 0)
                return -errno;
        c->saved_termios = termios;
        termios.c_iflag &= ~(IGNCR|INLCR);
        termios.c_iflag |= ICRNL;
        termios.c_lflag &= ~(ECHO|ECHONL|ISIG);
        termios.c_lflag |= ICANON;
        if (tcsetattr(c->fd, TCSANOW, &termios) < 0)
                return -errno;
        c->configured = true;

        (void) tcflush(c->fd, TCIFLUSH);
        return loop_write(c->fd, "\r\nPress Enter to begin initial setup on this console.\r\n", SIZE_MAX);
}

int firstboot_select_console(char **ttys, bool require_vc) {
        /* Keep the original indices so that the caller can identify the selected console. Ignore unavailable
         * consoles and aliases of devices we already opened. With only one usable console, no input is needed.
         * require_vc is used for --prompt-keymap-auto: don't ask for input if no local console can be selected. */

        BLOCK_SIGNALS(SIGINT, SIGTERM, SIGHUP);
        _cleanup_(firstboot_consoles_done) FirstBootConsoles consoles = {};
        size_t n_ttys = strv_length(ttys), n_active = 0;
        bool have_vc = false;
        int selected = -ENXIO, r;

        consoles.items = new(FirstBootConsole, n_ttys);
        if (!consoles.items)
                return -ENOMEM;

        consoles.n_items = n_ttys;
        FOREACH_ARRAY(c, consoles.items, n_ttys)
                *c = (FirstBootConsole) { .fd = -EBADF };

        _cleanup_free_ struct pollfd *pollfds = new(struct pollfd, n_ttys + 1);
        if (!pollfds)
                return -ENOMEM;

        FOREACH_ARRAY(p, pollfds, n_ttys + 1)
                *p = (struct pollfd) { .fd = -EBADF, .events = POLLIN };

        for (size_t i = 0; i < n_ttys; i++) {
                _cleanup_close_ int fd = open_terminal(ttys[i], O_RDWR|O_NOCTTY|O_CLOEXEC|O_NONBLOCK);
                if (fd < 0) {
                        log_debug_errno(fd, "Cannot open console %s, ignoring: %m", ttys[i]);
                        continue;
                }

                struct stat st;
                struct termios termios;
                if (fstat(fd, &st) < 0 || tcgetattr(fd, &termios) < 0) {
                        log_debug_errno(errno, "Cannot inspect console %s, ignoring: %m", ttys[i]);
                        continue;
                }

                bool duplicate = false;
                FOREACH_ARRAY(c, consoles.items, i)
                        if (c->fd >= 0 && c->device == st.st_rdev) {
                                duplicate = true;
                                break;
                        }
                if (duplicate)
                        continue;

                consoles.items[i].fd = TAKE_FD(fd);
                consoles.items[i].device = st.st_rdev;
                pollfds[i].fd = consoles.items[i].fd;
                selected = (int) i;
                n_active++;
                have_vc = have_vc || tty_is_vc_resolve(ttys[i]);
        }

        if (n_active == 0)
                return -ENXIO;
        if (require_vc && !have_vc)
                return -ENOTTY;
        if (n_active == 1)
                return selected;

        sigset_t mask;
        assert_se(sigemptyset(&mask) >= 0);
        assert_se(sigset_add_many(&mask, SIGINT, SIGTERM, SIGHUP) >= 0);

        _cleanup_close_ int signal_fd = signalfd(-1, &mask, SFD_CLOEXEC|SFD_NONBLOCK);
        if (signal_fd < 0)
                return -errno;
        pollfds[n_ttys].fd = signal_fd;

        for (size_t i = 0; i < n_ttys; i++) {
                FirstBootConsole *c = &consoles.items[i];
                if (c->fd < 0)
                        continue;

                r = firstboot_console_prepare(c);
                if (r < 0) {
                        log_debug_errno(r, "Cannot prompt on console %s, ignoring: %m", ttys[i]);
                        firstboot_console_done(c);
                        pollfds[i].fd = -EBADF;
                        n_active--;
                }
        }

        /* Once the prompt has been shown, consume Enter even if only one console remains. */
        while (n_active > 0) {
                r = ppoll_usec(pollfds, n_ttys + 1, USEC_INFINITY);
                if (r == -EINTR)
                        continue;
                if (r < 0)
                        return r;
                if (pollfds[n_ttys].revents != 0)
                        return -EINTR; /* Restore all terminals before unblocking the pending signal. */

                for (size_t i = 0; i < n_ttys; i++) {
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

                                        for (size_t j = 0; j < n_ttys; j++)
                                                if (j != i && consoles.items[j].fd >= 0)
                                                        (void) dprintf(consoles.items[j].fd,
                                                                       "\r\nInitial setup is running on %s.\r\n", ttys[i]);
                                        return (int) i;
                                }
                                if (n == 0 && !(pollfds[i].revents & (POLLHUP|POLLERR|POLLNVAL)))
                                        continue; /* An empty line terminated by EOF isn't a selection. */
                        }

                        firstboot_console_done(&consoles.items[i]);
                        pollfds[i].fd = -EBADF;
                        n_active--;
                }
        }

        return -ENXIO;
}
