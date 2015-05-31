/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Kay Sievers

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

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <limits.h>
#include <sys/ioctl.h>
#include <linux/tiocl.h>
#include <linux/kd.h>
#include <linux/vt.h>

#include "util.h"
#include "log.h"
#include "virt.h"
#include "fileio.h"
#include "process-util.h"
#include "terminal-util.h"
#include "signal-util.h"

static bool is_vconsole(int fd) {
        unsigned char data[1];

        data[0] = TIOCL_GETFGCONSOLE;
        return ioctl(fd, TIOCLINUX, data) >= 0;
}

static int disable_utf8(int fd) {
        int r = 0, k;

        if (ioctl(fd, KDSKBMODE, K_XLATE) < 0)
                r = -errno;

        k = loop_write(fd, "\033%@", 3, false);
        if (k < 0)
                r = k;

        k = write_string_file("/sys/module/vt/parameters/default_utf8", "0");
        if (k < 0)
                r = k;

        if (r < 0)
                log_warning_errno(r, "Failed to disable UTF-8: %m");

        return r;
}

static int enable_utf8(int fd) {
        int r = 0, k;
        long current = 0;

        if (ioctl(fd, KDGKBMODE, &current) < 0 || current == K_XLATE) {
                /*
                 * Change the current keyboard to unicode, unless it
                 * is currently in raw or off mode anyway. We
                 * shouldn't interfere with X11's processing of the
                 * key events.
                 *
                 * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
                 *
                 */

                if (ioctl(fd, KDSKBMODE, K_UNICODE) < 0)
                        r = -errno;
        }

        k = loop_write(fd, "\033%G", 3, false);
        if (k < 0)
                r = k;

        k = write_string_file("/sys/module/vt/parameters/default_utf8", "1");
        if (k < 0)
                r = k;

        if (r < 0)
                log_warning_errno(r, "Failed to enable UTF-8: %m");

        return r;
}

static int keyboard_load_and_wait(const char *vc, const char *map, const char *map_toggle, bool utf8) {
        const char *args[8];
        int i = 0, r;
        pid_t pid;

        /* An empty map means kernel map */
        if (isempty(map))
                return 1;

        args[i++] = KBD_LOADKEYS;
        args[i++] = "-q";
        args[i++] = "-C";
        args[i++] = vc;
        if (utf8)
                args[i++] = "-u";
        args[i++] = map;
        if (map_toggle)
                args[i++] = map_toggle;
        args[i++] = NULL;

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");
        else if (pid == 0) {

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate_and_warn(KBD_LOADKEYS, pid, true);
        if (r < 0)
                return r;

        return r == 0;
}

static int font_load_and_wait(const char *vc, const char *font, const char *map, const char *unimap) {
        const char *args[9];
        int i = 0, r;
        pid_t pid;

        /* An empty font means kernel font */
        if (isempty(font))
                return 1;

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        args[i++] = font;
        if (map) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (unimap) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        args[i++] = NULL;

        pid = fork();
        if (pid < 0)
                return log_error_errno(errno, "Failed to fork: %m");
        else if (pid == 0) {

                (void) reset_all_signal_handlers();
                (void) reset_signal_mask();

                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        r = wait_for_terminate_and_warn(KBD_SETFONT, pid, true);
        if (r < 0)
                return r;

        return r == 0;
}

/*
 * A newly allocated VT uses the font from the active VT. Here
 * we update all possibly already allocated VTs with the configured
 * font. It also allows to restart systemd-vconsole-setup.service,
 * to apply a new font to all VTs.
 */
static void font_copy_to_all_vcs(int fd) {
        struct vt_stat vcs = {};
        unsigned char map8[E_TABSZ];
        unsigned short map16[E_TABSZ];
        struct unimapdesc unimapd;
        struct unipair unipairs[USHRT_MAX];
        int i, r;

        /* get active, and 16 bit mask of used VT numbers */
        r = ioctl(fd, VT_GETSTATE, &vcs);
        if (r < 0) {
                log_debug_errno(errno, "VT_GETSTATE failed, ignoring: %m");
                return;
        }

        for (i = 1; i <= 15; i++) {
                char vcname[strlen("/dev/vcs") + DECIMAL_STR_MAX(int)];
                _cleanup_close_ int vcfd = -1;
                struct console_font_op cfo = {};

                if (i == vcs.v_active)
                        continue;

                /* skip non-allocated ttys */
                snprintf(vcname, sizeof(vcname), "/dev/vcs%i", i);
                if (access(vcname, F_OK) < 0)
                        continue;

                snprintf(vcname, sizeof(vcname), "/dev/tty%i", i);
                vcfd = open_terminal(vcname, O_RDWR|O_CLOEXEC);
                if (vcfd < 0)
                        continue;

                /* copy font from active VT, where the font was uploaded to */
                cfo.op = KD_FONT_OP_COPY;
                cfo.height = vcs.v_active-1; /* tty1 == index 0 */
                (void) ioctl(vcfd, KDFONTOP, &cfo);

                /* copy map of 8bit chars */
                if (ioctl(fd, GIO_SCRNMAP, map8) >= 0)
                        (void) ioctl(vcfd, PIO_SCRNMAP, map8);

                /* copy map of 8bit chars -> 16bit Unicode values */
                if (ioctl(fd, GIO_UNISCRNMAP, map16) >= 0)
                        (void) ioctl(vcfd, PIO_UNISCRNMAP, map16);

                /* copy unicode translation table */
                /* unimapd is a ushort count and a pointer to an
                   array of struct unipair { ushort, ushort } */
                unimapd.entries  = unipairs;
                unimapd.entry_ct = USHRT_MAX;
                if (ioctl(fd, GIO_UNIMAP, &unimapd) >= 0) {
                        struct unimapinit adv = { 0, 0, 0 };

                        (void) ioctl(vcfd, PIO_UNIMAPCLR, &adv);
                        (void) ioctl(vcfd, PIO_UNIMAP, &unimapd);
                }
        }
}

int main(int argc, char **argv) {
        const char *vc;
        _cleanup_free_ char
                *vc_keymap = NULL, *vc_keymap_toggle = NULL,
                *vc_font = NULL, *vc_font_map = NULL, *vc_font_unimap = NULL;
        _cleanup_close_ int fd = -1;
        bool utf8, font_copy = false, font_ok, keyboard_ok;
        int r = EXIT_FAILURE;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argv[1])
                vc = argv[1];
        else {
                vc = "/dev/tty0";
                font_copy = true;
        }

        fd = open_terminal(vc, O_RDWR|O_CLOEXEC);
        if (fd < 0) {
                log_error_errno(errno, "Failed to open %s: %m", vc);
                return EXIT_FAILURE;
        }

        if (!is_vconsole(fd)) {
                log_error("Device %s is not a virtual console.", vc);
                return EXIT_FAILURE;
        }

        utf8 = is_locale_utf8();

        r = parse_env_file("/etc/vconsole.conf", NEWLINE,
                           "KEYMAP", &vc_keymap,
                           "KEYMAP_TOGGLE", &vc_keymap_toggle,
                           "FONT", &vc_font,
                           "FONT_MAP", &vc_font_map,
                           "FONT_UNIMAP", &vc_font_unimap,
                           NULL);

        if (r < 0 && r != -ENOENT)
                log_warning_errno(r, "Failed to read /etc/vconsole.conf: %m");

        /* Let the kernel command line override /etc/vconsole.conf */
        if (detect_container(NULL) <= 0) {
                r = parse_env_file("/proc/cmdline", WHITESPACE,
                                   "vconsole.keymap", &vc_keymap,
                                   "vconsole.keymap.toggle", &vc_keymap_toggle,
                                   "vconsole.font", &vc_font,
                                   "vconsole.font.map", &vc_font_map,
                                   "vconsole.font.unimap", &vc_font_unimap,
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline: %m");
        }

        if (utf8)
                (void) enable_utf8(fd);
        else
                (void) disable_utf8(fd);

        font_ok = font_load_and_wait(vc, vc_font, vc_font_map, vc_font_unimap) > 0;
        keyboard_ok = keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) > 0;

        /* Only copy the font when we executed setfont successfully */
        if (font_copy && font_ok)
                (void) font_copy_to_all_vcs(fd);

        return font_ok && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
