/***
  This file is part of systemd.

  Copyright 2010 Kay Sievers
  Copyright 2016 Michal Soltys <soltys@ziu.info>

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

static bool is_allocated(unsigned int idx) {
        char vcname[strlen("/dev/vcs") + DECIMAL_STR_MAX(int)];

        xsprintf(vcname, "/dev/vcs%i", idx);
        return access(vcname, F_OK) == 0;
}

static bool is_allocated_byfd(int fd) {
        struct vt_stat vcs = {};

        if (ioctl(fd, VT_GETSTATE, &vcs) < 0) {
                log_warning_errno(errno, "VT_GETSTATE failed: %m");
                return false;
        }
        return is_allocated(vcs.v_active);
}

static bool is_settable(int fd) {
        int r, curr_mode;

        r = ioctl(fd, KDGKBMODE, &curr_mode);
        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */
        return r == 0 && IN_SET(curr_mode, K_XLATE, K_UNICODE);
}

static int toggle_utf8(const char *name, int fd, bool utf8) {
        int r;
        struct termios tc = {};

        assert(name);

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode on %s: %m", enable_disable(utf8), name);

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", 3, false);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s UTF-8 term processing on %s: %m", enable_disable(utf8), name);

        r = tcgetattr(fd, &tc);
        if (r >= 0) {
                if (utf8)
                        tc.c_iflag |= IUTF8;
                else
                        tc.c_iflag &= ~IUTF8;
                r = tcsetattr(fd, TCSANOW, &tc);
        }
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s iutf8 flag on %s: %m", enable_disable(utf8), name);

        log_debug("UTF-8 kbdmode %sd on %s", enable_disable(utf8), name);
        return 0;
}

static int toggle_utf8_sysfs(bool utf8) {
        int r;

        r = write_string_file("/sys/module/vt/parameters/default_utf8", one_zero(utf8), 0);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s sysfs UTF-8 flag: %m", enable_disable(utf8));

        log_debug("Sysfs UTF-8 flag %sd", enable_disable(utf8));
        return 0;
}

static int keyboard_load_and_wait(const char *vc, const char *map, const char *map_toggle, bool utf8) {
        const char *args[8];
        int i = 0;
        pid_t pid;

        /* An empty map means kernel map */
        if (isempty(map))
                return 0;

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

        return wait_for_terminate_and_warn(KBD_LOADKEYS, pid, true);
}

static int font_load_and_wait(const char *vc, const char *font, const char *map, const char *unimap) {
        const char *args[9];
        int i = 0;
        pid_t pid;

        /* Any part can be set independently */
        if (isempty(font) && isempty(map) && isempty(unimap))
                return 0;

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        if (!isempty(map)) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (!isempty(unimap)) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        if (!isempty(font))
                args[i++] = font;
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

        return wait_for_terminate_and_warn(KBD_SETFONT, pid, true);
}

/*
 * A newly allocated VT uses the font from the active VT. Here
 * we update all possibly already allocated VTs with the configured
 * font. It also allows to restart systemd-vconsole-setup.service,
 * to apply a new font to all VTs.
 *
 * We also setup per-console utf8 related stuff: kbdmode, term
 * processing, stty iutf8.
 */
static void setup_remaining_vcs(int fd, bool utf8) {
        struct console_font_op cfo = {
                .op = KD_FONT_OP_GET, .flags = 0,
                .width = 32, .height = 32,
                .charcount = 512,
        };
        struct vt_stat vcs = {};
        struct unimapinit adv = {};
        struct unimapdesc unimapd;
        _cleanup_free_ struct unipair* unipairs = NULL;
        _cleanup_free_ void *fontbuf = NULL;
        int i, r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs) {
                log_oom();
                return;
        }

        fontbuf = malloc(cfo.width * cfo.height * cfo.charcount / 8);
        if (!fontbuf) {
                log_oom();
                return;
        }

        /* get active, and 16 bit mask of used VT numbers */
        r = ioctl(fd, VT_GETSTATE, &vcs);
        if (r < 0) {
                log_warning_errno(errno, "VT_GETSTATE failed, ignoring remaining consoles: %m");
                return;
        }

        /* get fonts from source console */
        cfo.data = fontbuf;
        r = ioctl(fd, KDFONTOP, &cfo);
        if (r < 0)
                log_warning_errno(errno, "KD_FONT_OP_GET failed, fonts will not be copied: %m");
        else {
                unimapd.entries  = unipairs;
                unimapd.entry_ct = USHRT_MAX;
                r = ioctl(fd, GIO_UNIMAP, &unimapd);
                if (r < 0)
                        log_warning_errno(errno, "GIO_UNIMAP failed, fonts will not be copied: %m");
                else
                        cfo.op = KD_FONT_OP_SET;
        }

        for (i = 1; i <= 63; i++) {
                char ttyname[strlen("/dev/tty") + DECIMAL_STR_MAX(int)];
                _cleanup_close_ int fd_d = -1;

                if (i == vcs.v_active || !is_allocated(i))
                        continue;

                /* try to open terminal */
                xsprintf(ttyname, "/dev/tty%i", i);
                fd_d = open_terminal(ttyname, O_RDWR|O_CLOEXEC);
                if (fd_d < 0) {
                        log_warning_errno(fd_d, "Unable to open tty%i, fonts will not be copied: %m", i);
                        continue;
                }

                if (!is_settable(fd_d))
                        continue;

                toggle_utf8(ttyname, fd_d, utf8);

                if (cfo.op != KD_FONT_OP_SET)
                        continue;

                r = ioctl(fd_d, KDFONTOP, &cfo);
                if (r < 0) {
                        log_warning_errno(errno, "KD_FONT_OP_SET failed, fonts will not be copied to tty%i: %m", i);
                        continue;
                }

                /* copy unicode translation table */
                /* unimapd is a ushort count and a pointer to an
                   array of struct unipair { ushort, ushort } */
                r = ioctl(fd_d, PIO_UNIMAPCLR, &adv);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAPCLR failed, unimaps might be incorrect for tty%i: %m", i);
                        continue;
                }

                r = ioctl(fd_d, PIO_UNIMAP, &unimapd);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAP failed, unimaps might be incorrect for tty%i: %m", i);
                        continue;
                }

                log_debug("Font and unimap successfully copied to %s", ttyname);
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

        if (!is_allocated_byfd(fd)) {
                log_error("Virtual console %s is not allocated.", vc);
                return EXIT_FAILURE;
        }

        if (!is_settable(fd)) {
                log_error("Virtual console %s is not in K_XLATE or K_UNICODE.", vc);
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
                                   "vconsole.keymap_toggle", &vc_keymap_toggle,
                                   "vconsole.font", &vc_font,
                                   "vconsole.font_map", &vc_font_map,
                                   "vconsole.font_unimap", &vc_font_unimap,
                                   /* compatibility with obsolete multiple-dot scheme */
                                   "vconsole.keymap.toggle", &vc_keymap_toggle,
                                   "vconsole.font.map", &vc_font_map,
                                   "vconsole.font.unimap", &vc_font_unimap,
                                   NULL);

                if (r < 0 && r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline: %m");
        }

        toggle_utf8_sysfs(utf8);
        toggle_utf8(vc, fd, utf8);
        font_ok = font_load_and_wait(vc, vc_font, vc_font_map, vc_font_unimap) == 0;
        keyboard_ok = keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) == 0;

        if (font_copy) {
                if (font_ok)
                        setup_remaining_vcs(fd, utf8);
                else
                        log_warning("Setting source virtual console failed, ignoring remaining ones");
        }

        return font_ok && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
