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

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <termios.h>
#include <unistd.h>

#include "alloc-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "terminal-util.h"
#include "util.h"
#include "virt.h"

static bool is_vconsole(int fd) {
        unsigned char data[1];

        data[0] = TIOCL_GETFGCONSOLE;
        return ioctl(fd, TIOCLINUX, data) >= 0;
}

static int toggle_utf8(int fd, bool utf8) {
        int r;
        struct termios tc = {};

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode: %m", utf8 ? "enable" : "disable");

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", 3, false);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s UTF-8 term processing: %m", utf8 ? "enable" : "disable");

        r = tcgetattr(fd, &tc);
        if (r >= 0) {
                if (utf8)
                        tc.c_iflag |= IUTF8;
                else
                        tc.c_iflag &= ~IUTF8;
                r = tcsetattr(fd, TCSANOW, &tc);
        }
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s iutf8 flag: %m", utf8 ? "enable" : "disable");

        return 0;
}

static int toggle_utf8_sysfs(bool utf8) {
        int r;

        r = write_string_file("/sys/module/vt/parameters/default_utf8", one_zero(utf8), 0);
        if (r < 0)
                log_warning_errno(r, "Failed to %s sysfs UTF-8 flag: %m", utf8 ? "enable" : "disable");
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
        struct unimapdesc unimapd;
        _cleanup_free_ struct unipair* unipairs = NULL;
        int i, r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs) {
                log_oom();
                return;
        }

        /* get active, and 16 bit mask of used VT numbers */
        r = ioctl(fd, VT_GETSTATE, &vcs);
        if (r < 0) {
                log_debug_errno(errno, "VT_GETSTATE failed, ignoring: %m");
                return;
        }

        for (i = 1; i <= 63; i++) {
                char vcname[strlen("/dev/vcs") + DECIMAL_STR_MAX(int)];
                _cleanup_close_ int vcfd = -1;
                struct console_font_op cfo = {};

                if (i == vcs.v_active)
                        continue;

                /* skip non-allocated ttys */
                xsprintf(vcname, "/dev/vcs%i", i);
                if (access(vcname, F_OK) < 0)
                        continue;

                xsprintf(vcname, "/dev/tty%i", i);
                vcfd = open_terminal(vcname, O_RDWR|O_CLOEXEC);
                if (vcfd < 0)
                        continue;

                /* copy font from active VT, where the font was uploaded to */
                cfo.op = KD_FONT_OP_COPY;
                cfo.height = vcs.v_active-1; /* tty1 == index 0 */
                (void) ioctl(vcfd, KDFONTOP, &cfo);

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
                log_error_errno(fd, "Failed to open %s: %m", vc);
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
        if (detect_container() <= 0) {
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

        toggle_utf8_sysfs(utf8);
        toggle_utf8(fd, utf8);

        font_ok = font_load_and_wait(vc, vc_font, vc_font_map, vc_font_unimap) > 0;
        keyboard_ok = keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) > 0;

        /* Only copy the font when we executed setfont successfully */
        if (font_copy && font_ok)
                (void) font_copy_to_all_vcs(fd);

        return font_ok && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
