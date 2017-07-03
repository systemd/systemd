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
#include <sysexits.h>
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
#include "strv.h"
#include "terminal-util.h"
#include "util.h"
#include "virt.h"

static int verify_vc_device(int fd) {
        unsigned char data[1];
        int r;

        data[0] = TIOCL_GETFGCONSOLE;
        r = ioctl(fd, TIOCLINUX, data);
        return r < 0 ? -errno : r;
}

static int verify_vc_allocation(unsigned idx) {
        char vcname[sizeof("/dev/vcs") + DECIMAL_STR_MAX(unsigned) - 2];
        int r;

        xsprintf(vcname, "/dev/vcs%u", idx);
        r = access(vcname, F_OK);
        return r < 0 ? -errno : r;
}

static int verify_vc_allocation_byfd(int fd) {
        struct vt_stat vcs = {};
        int r;

        r = ioctl(fd, VT_GETSTATE, &vcs);
        return r < 0 ? -errno : verify_vc_allocation(vcs.v_active);
}

static int verify_vc_kbmode(int fd) {
        int r, curr_mode;

        r = ioctl(fd, KDGKBMODE, &curr_mode);
        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * http://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */
        if (r < 0)
                return -errno;

        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
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
                SET_FLAG(tc.c_iflag, IUTF8, utf8);
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
        _cleanup_free_ char *cmd = NULL;
        const char *args[8];
        unsigned i = 0;
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

        log_debug("Executing \"%s\"...",
                  strnull((cmd = strv_join((char**) args, " "))));

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
        _cleanup_free_ char *cmd = NULL;
        const char *args[9];
        unsigned i = 0;
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

        log_debug("Executing \"%s\"...",
                  strnull((cmd = strv_join((char**) args, " "))));

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
 * A newly allocated VT uses the font from the source VT. Here
 * we update all possibly already allocated VTs with the configured
 * font. It also allows to restart systemd-vconsole-setup.service,
 * to apply a new font to all VTs.
 *
 * We also setup per-console utf8 related stuff: kbdmode, term
 * processing, stty iutf8.
 */
static void setup_remaining_vcs(int src_fd, unsigned src_idx, bool utf8) {
        struct console_font_op cfo = {
                .op = KD_FONT_OP_GET,
                .width = UINT_MAX, .height = UINT_MAX,
                .charcount = UINT_MAX,
        };
        struct unimapinit adv = {};
        struct unimapdesc unimapd;
        _cleanup_free_ struct unipair* unipairs = NULL;
        _cleanup_free_ void *fontbuf = NULL;
        unsigned i;
        int r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs) {
                log_oom();
                return;
        }

        /* get metadata of the current font (width, height, count) */
        r = ioctl(src_fd, KDFONTOP, &cfo);
        if (r < 0)
                log_warning_errno(errno, "KD_FONT_OP_GET failed while trying to get the font metadata: %m");
        else {
                /* verify parameter sanity first */
                if (cfo.width > 32 || cfo.height > 32 || cfo.charcount > 512)
                        log_warning("Invalid font metadata - width: %u (max 32), height: %u (max 32), count: %u (max 512)",
                                    cfo.width, cfo.height, cfo.charcount);
                else {
                        /*
                         * Console fonts supported by the kernel are limited in size to 32 x 32 and maximum 512
                         * characters. Thus with 1 bit per pixel it requires up to 65536 bytes. The height always
                         * requries 32 per glyph, regardless of the actual height - see the comment above #define
                         * max_font_size 65536 in drivers/tty/vt/vt.c for more details.
                         */
                        fontbuf = malloc((cfo.width + 7) / 8 * 32 * cfo.charcount);
                        if (!fontbuf) {
                                log_oom();
                                return;
                        }
                        /* get fonts from the source console */
                        cfo.data = fontbuf;
                        r = ioctl(src_fd, KDFONTOP, &cfo);
                        if (r < 0)
                                log_warning_errno(errno, "KD_FONT_OP_GET failed while trying to read the font data: %m");
                        else {
                                unimapd.entries  = unipairs;
                                unimapd.entry_ct = USHRT_MAX;
                                r = ioctl(src_fd, GIO_UNIMAP, &unimapd);
                                if (r < 0)
                                        log_warning_errno(errno, "GIO_UNIMAP failed while trying to read unicode mappings: %m");
                                else
                                        cfo.op = KD_FONT_OP_SET;
                        }
                }
        }

        if (cfo.op != KD_FONT_OP_SET)
                log_warning("Fonts will not be copied to remaining consoles");

        for (i = 1; i <= 63; i++) {
                char ttyname[sizeof("/dev/tty63")];
                _cleanup_close_ int fd_d = -1;

                if (i == src_idx || verify_vc_allocation(i) < 0)
                        continue;

                /* try to open terminal */
                xsprintf(ttyname, "/dev/tty%u", i);
                fd_d = open_terminal(ttyname, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd_d < 0) {
                        log_warning_errno(fd_d, "Unable to open tty%u, fonts will not be copied: %m", i);
                        continue;
                }

                if (verify_vc_kbmode(fd_d) < 0)
                        continue;

                toggle_utf8(ttyname, fd_d, utf8);

                if (cfo.op != KD_FONT_OP_SET)
                        continue;

                r = ioctl(fd_d, KDFONTOP, &cfo);
                if (r < 0) {
                        log_warning_errno(errno, "KD_FONT_OP_SET failed, fonts will not be copied to tty%u: %m", i);
                        continue;
                }

                /*
                 * copy unicode translation table
                 * unimapd is a ushort count and a pointer to an
                 * array of struct unipair { ushort, ushort }
                 */
                r = ioctl(fd_d, PIO_UNIMAPCLR, &adv);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAPCLR failed, unimaps might be incorrect for tty%u: %m", i);
                        continue;
                }

                r = ioctl(fd_d, PIO_UNIMAP, &unimapd);
                if (r < 0) {
                        log_warning_errno(errno, "PIO_UNIMAP failed, unimaps might be incorrect for tty%u: %m", i);
                        continue;
                }

                log_debug("Font and unimap successfully copied to %s", ttyname);
        }
}

static int find_source_vc(char **ret_path, unsigned *ret_idx) {
        _cleanup_free_ char *path = NULL;
        unsigned i;
        int ret_fd, r, err = 0;

        path = new(char, sizeof("/dev/tty63"));
        if (path == NULL)
                return log_oom();

        for (i = 1; i <= 63; i++) {
                _cleanup_close_ int fd = -1;

                r = verify_vc_allocation(i);
                if (r < 0) {
                        if (!err)
                                err = -r;
                        continue;
                }

                sprintf(path, "/dev/tty%u", i);
                fd = open_terminal(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        if (!err)
                                err = -fd;
                        continue;
                }
                r = verify_vc_kbmode(fd);
                if (r < 0) {
                        if (!err)
                                err = -r;
                        continue;
                }

                /* all checks passed, return this one as a source console */
                *ret_idx = i;
                *ret_path = path;
                path = NULL;
                ret_fd = fd;
                fd = -1;
                return ret_fd;
        }

        return log_error_errno(err, "No usable source console found: %m");
}

static int verify_source_vc(char **ret_path, const char *src_vc) {
        char *path;
        _cleanup_close_ int fd = -1;
        int ret_fd, r;

        fd = open_terminal(src_vc, O_RDWR|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open %s: %m", src_vc);

        r = verify_vc_device(fd);
        if (r < 0)
                return log_error_errno(r, "Device %s is not a virtual console: %m", src_vc);

        r = verify_vc_allocation_byfd(fd);
        if (r < 0)
                return log_error_errno(r, "Virtual console %s is not allocated: %m", src_vc);

        r = verify_vc_kbmode(fd);
        if (r < 0)
                return log_error_errno(r, "Virtual console %s is not in K_XLATE or K_UNICODE: %m", src_vc);

        path = strdup(src_vc);
        if (path == NULL)
                return log_oom();

        *ret_path = path;
        ret_fd = fd;
        fd = -1;
        return ret_fd;
}

int main(int argc, char **argv) {
        _cleanup_free_ char
                *vc = NULL,
                *vc_keymap = NULL, *vc_keymap_toggle = NULL,
                *vc_font = NULL, *vc_font_map = NULL, *vc_font_unimap = NULL;
        _cleanup_close_ int fd = -1;
        bool utf8, keyboard_ok;
        unsigned idx = 0;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);

        if (argv[1])
                fd = verify_source_vc(&vc, argv[1]);
        else
                fd = find_source_vc(&vc, &idx);

        if (fd < 0)
                return EXIT_FAILURE;

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

        r = font_load_and_wait(vc, vc_font, vc_font_map, vc_font_unimap);
        keyboard_ok = keyboard_load_and_wait(vc, vc_keymap, vc_keymap_toggle, utf8) == 0;

        if (idx > 0) {
                if (r == 0)
                        setup_remaining_vcs(fd, idx, utf8);
                else if (r == EX_OSERR)
                        /* setfont returns EX_OSERR when ioctl(KDFONTOP/PIO_FONTX/PIO_FONTX) fails.
                         * This might mean various things, but in particular lack of a graphical
                         * console. Let's be generous and not treat this as an error. */
                        log_notice("Setting fonts failed with a \"system error\", ignoring.");
                else
                        log_warning("Setting source virtual console failed, ignoring remaining ones");
        }

        return IN_SET(r, 0, EX_OSERR) && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}
