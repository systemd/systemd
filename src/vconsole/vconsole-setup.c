/* SPDX-License-Identifier: LGPL-2.1-or-later */
/***
  Copyright © 2016 Michal Soltys <soltys@ziu.info>
***/

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <linux/kd.h>
#include <linux/tiocl.h>
#include <linux/vt.h>
#include <stdbool.h>
#include <stdlib.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sysexits.h>
#include <termios.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "alloc-util.h"
#include "creds-util.h"
#include "dev-setup.h"
#include "env-file.h"
#include "errno-util.h"
#include "fd-util.h"
#include "fileio.h"
#include "io-util.h"
#include "locale-util.h"
#include "log.h"
#include "main-func.h"
#include "proc-cmdline.h"
#include "process-util.h"
#include "signal-util.h"
#include "stdio-util.h"
#include "string-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "virt.h"

typedef enum VCMeta {
        VC_KEYMAP,
        VC_KEYMAP_TOGGLE,
        VC_FONT,
        VC_FONT_MAP,
        VC_FONT_UNIMAP,
        _VC_META_MAX,
        _VC_META_INVALID = -EINVAL,
} VCMeta;

typedef struct Context {
        char *config[_VC_META_MAX];
} Context;

static const char * const vc_meta_names[_VC_META_MAX] = {
        [VC_KEYMAP]        = "vconsole.keymap",
        [VC_KEYMAP_TOGGLE] = "vconsole.keymap_toggle",
        [VC_FONT]          = "vconsole.font",
        [VC_FONT_MAP]      = "vconsole.font_map",
        [VC_FONT_UNIMAP]   = "vconsole.font_unimap",
};

/* compatibility with obsolete multiple-dot scheme */
static const char * const vc_meta_compat_names[_VC_META_MAX] = {
        [VC_KEYMAP_TOGGLE] = "vconsole.keymap.toggle",
        [VC_FONT_MAP]      = "vconsole.font.map",
        [VC_FONT_UNIMAP]   = "vconsole.font.unimap",
};

static const char * const vc_env_names[_VC_META_MAX] = {
        [VC_KEYMAP]        = "KEYMAP",
        [VC_KEYMAP_TOGGLE] = "KEYMAP_TOGGLE",
        [VC_FONT]          = "FONT",
        [VC_FONT_MAP]      = "FONT_MAP",
        [VC_FONT_UNIMAP]   = "FONT_UNIMAP",
};

static void context_done(Context *c) {
        assert(c);

        FOREACH_ARRAY(cc, c->config, _VC_META_MAX)
                free(*cc);
}

static void context_merge_config(
                Context *dst,
                Context *src,
                Context *src_compat) {

        assert(dst);
        assert(src);

        for (VCMeta i = 0; i < _VC_META_MAX; i++)
                if (src->config[i])
                        free_and_replace(dst->config[i], src->config[i]);
                else if (src_compat && src_compat->config[i])
                        free_and_replace(dst->config[i], src_compat->config[i]);
}

static const char* context_get_config(Context *c, VCMeta meta) {
        assert(c);
        assert(meta >= 0 && meta < _VC_META_MAX);

        if (meta == VC_KEYMAP)
                return isempty(c->config[VC_KEYMAP]) ? SYSTEMD_DEFAULT_KEYMAP : c->config[VC_KEYMAP];

        return empty_to_null(c->config[meta]);
}

static int context_read_creds(Context *c) {
        _cleanup_(context_done) Context v = {};
        int r;

        assert(c);

        r = read_credential_strings_many(
                        vc_meta_names[VC_KEYMAP],        &v.config[VC_KEYMAP],
                        vc_meta_names[VC_KEYMAP_TOGGLE], &v.config[VC_KEYMAP_TOGGLE],
                        vc_meta_names[VC_FONT],          &v.config[VC_FONT],
                        vc_meta_names[VC_FONT_MAP],      &v.config[VC_FONT_MAP],
                        vc_meta_names[VC_FONT_UNIMAP],   &v.config[VC_FONT_UNIMAP]);
        if (r < 0)
                log_warning_errno(r, "Failed to import credentials, ignoring: %m");

        context_merge_config(c, &v, NULL);
        return 0;
}

static int context_read_env(Context *c) {
        _cleanup_(context_done) Context v = {};
        int r;

        assert(c);

        r = parse_env_file(
                        NULL, "/etc/vconsole.conf",
                        vc_env_names[VC_KEYMAP],        &v.config[VC_KEYMAP],
                        vc_env_names[VC_KEYMAP_TOGGLE], &v.config[VC_KEYMAP_TOGGLE],
                        vc_env_names[VC_FONT],          &v.config[VC_FONT],
                        vc_env_names[VC_FONT_MAP],      &v.config[VC_FONT_MAP],
                        vc_env_names[VC_FONT_UNIMAP],   &v.config[VC_FONT_UNIMAP]);
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to read /etc/vconsole.conf, ignoring: %m");
                return r;
        }

        context_merge_config(c, &v, NULL);
        return 0;
}

static int context_read_proc_cmdline(Context *c) {
        _cleanup_(context_done) Context v = {}, w = {};
        int r;

        assert(c);

        r = proc_cmdline_get_key_many(
                        PROC_CMDLINE_STRIP_RD_PREFIX,
                        vc_meta_names[VC_KEYMAP],               &v.config[VC_KEYMAP],
                        vc_meta_names[VC_KEYMAP_TOGGLE],        &v.config[VC_KEYMAP_TOGGLE],
                        vc_meta_names[VC_FONT],                 &v.config[VC_FONT],
                        vc_meta_names[VC_FONT_MAP],             &v.config[VC_FONT_MAP],
                        vc_meta_names[VC_FONT_UNIMAP],          &v.config[VC_FONT_UNIMAP],
                        vc_meta_compat_names[VC_KEYMAP_TOGGLE], &w.config[VC_KEYMAP_TOGGLE],
                        vc_meta_compat_names[VC_FONT_MAP],      &w.config[VC_FONT_MAP],
                        vc_meta_compat_names[VC_FONT_UNIMAP],   &w.config[VC_FONT_UNIMAP]);
        if (r < 0) {
                if (r != -ENOENT)
                        log_warning_errno(r, "Failed to read /proc/cmdline, ignoring: %m");
                return r;
        }

        context_merge_config(c, &v, &w);
        return 0;
}

static void context_load_config(Context *c) {
        assert(c);

        /* Load data from credentials (lowest priority) */
        (void) context_read_creds(c);

        /* Load data from configuration file (middle priority) */
        (void) context_read_env(c);

        /* Let the kernel command line override /etc/vconsole.conf (highest priority) */
        (void) context_read_proc_cmdline(c);
}

static int verify_vc_device(int fd) {
        unsigned char data[] = {
                TIOCL_GETFGCONSOLE,
        };

        return RET_NERRNO(ioctl(fd, TIOCLINUX, data));
}

static int verify_vc_allocation(unsigned idx) {
        char vcname[sizeof("/dev/vcs") + DECIMAL_STR_MAX(unsigned) - 2];

        xsprintf(vcname, "/dev/vcs%u", idx);

        return RET_NERRNO(access(vcname, F_OK));
}

static int verify_vc_allocation_byfd(int fd) {
        struct vt_stat vcs = {};

        if (ioctl(fd, VT_GETSTATE, &vcs) < 0)
                return -errno;

        return verify_vc_allocation(vcs.v_active);
}

static int verify_vc_kbmode(int fd) {
        int curr_mode;

        /*
         * Make sure we only adjust consoles in K_XLATE or K_UNICODE mode.
         * Otherwise we would (likely) interfere with X11's processing of the
         * key events.
         *
         * https://lists.freedesktop.org/archives/systemd-devel/2013-February/008573.html
         */

        if (ioctl(fd, KDGKBMODE, &curr_mode) < 0)
                return -errno;

        return IN_SET(curr_mode, K_XLATE, K_UNICODE) ? 0 : -EBUSY;
}

static int verify_vc_display_mode(int fd) {
        int mode;

        /* Similarly the vc is likely busy if it is in KD_GRAPHICS mode. If it's not the case and it's been
         * left in graphics mode, the kernel will refuse to operate on the font settings anyway. */

        if (ioctl(fd, KDGETMODE, &mode) < 0)
                return -errno;

        return mode != KD_TEXT ? -EBUSY : 0;
}

static int toggle_utf8_vc(const char *name, int fd, bool utf8) {
        int r;
        struct termios tc = {};

        assert(name);
        assert(fd >= 0);

        r = ioctl(fd, KDSKBMODE, utf8 ? K_UNICODE : K_XLATE);
        if (r < 0)
                return log_warning_errno(errno, "Failed to %s UTF-8 kbdmode on %s: %m", enable_disable(utf8), name);

        r = loop_write(fd, utf8 ? "\033%G" : "\033%@", SIZE_MAX);
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

        r = write_string_file("/sys/module/vt/parameters/default_utf8", one_zero(utf8), WRITE_STRING_FILE_DISABLE_BUFFER);
        if (r < 0)
                return log_warning_errno(r, "Failed to %s sysfs UTF-8 flag: %m", enable_disable(utf8));

        log_debug("Sysfs UTF-8 flag %sd", enable_disable(utf8));
        return 0;
}

static int keyboard_load_and_wait(const char *vc, Context *c, bool utf8) {
        const char *map, *map_toggle, *args[8];
        unsigned i = 0;
        pid_t pid;
        int r;

        assert(vc);
        assert(c);

        map = context_get_config(c, VC_KEYMAP);
        map_toggle = context_get_config(c, VC_KEYMAP_TOGGLE);

        /* An empty map means kernel map */
        if (isempty(map) || streq(map, "@kernel"))
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

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd = NULL;

                cmd = strv_join((char**) args, " ");
                log_debug("Executing \"%s\"...", strnull(cmd));
        }

        r = safe_fork("(loadkeys)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        return wait_for_terminate_and_check(KBD_LOADKEYS, pid, WAIT_LOG);
}

static int font_load_and_wait(const char *vc, Context *c) {
        const char *font, *map, *unimap, *args[9];
        unsigned i = 0;
        pid_t pid;
        int r;

        assert(vc);
        assert(c);

        font = context_get_config(c, VC_FONT);
        map = context_get_config(c, VC_FONT_MAP);
        unimap = context_get_config(c, VC_FONT_UNIMAP);

        /* Any part can be set independently */
        if (!font && !map && !unimap)
                return 0;

        args[i++] = KBD_SETFONT;
        args[i++] = "-C";
        args[i++] = vc;
        if (map) {
                args[i++] = "-m";
                args[i++] = map;
        }
        if (unimap) {
                args[i++] = "-u";
                args[i++] = unimap;
        }
        if (font)
                args[i++] = font;
        args[i++] = NULL;

        if (DEBUG_LOGGING) {
                _cleanup_free_ char *cmd = NULL;

                cmd = strv_join((char**) args, " ");
                log_debug("Executing \"%s\"...", strnull(cmd));
        }

        r = safe_fork("(setfont)", FORK_RESET_SIGNALS|FORK_CLOSE_ALL_FDS|FORK_RLIMIT_NOFILE_SAFE|FORK_LOG, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execv(args[0], (char **) args);
                _exit(EXIT_FAILURE);
        }

        /* setfont returns EX_OSERR when ioctl(KDFONTOP/PIO_FONTX/PIO_FONTX) fails.  This might mean various
         * things, but in particular lack of a graphical console. Let's be generous and not treat this as an
         * error. */
        r = wait_for_terminate_and_check(KBD_SETFONT, pid, WAIT_LOG_ABNORMAL);
        if (r == EX_OSERR)
                log_notice(KBD_SETFONT " failed with a \"system error\" (EX_OSERR), ignoring.");
        else if (r >= 0 && r != EXIT_SUCCESS)
                log_error(KBD_SETFONT " failed with exit status %i.", r);

        return r;
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
        int log_level = LOG_WARNING;
        int r;

        unipairs = new(struct unipair, USHRT_MAX);
        if (!unipairs)
                return (void) log_oom();

        /* get metadata of the current font (width, height, count) */
        r = ioctl(src_fd, KDFONTOP, &cfo);
        if (r < 0) {
                /* We might be called to operate on the dummy console (to setup keymap
                 * mainly) when fbcon deferred takeover is used for example. In such case,
                 * setting font is not supported and is expected to fail. */
                if (errno == ENOSYS)
                        log_level = LOG_DEBUG;

                log_full_errno(log_level, errno,
                               "KD_FONT_OP_GET failed while trying to get the font metadata: %m");
        } else {
                /* verify parameter sanity first */
                if (cfo.width > 32 || cfo.height > 32 || cfo.charcount > 512)
                        log_warning("Invalid font metadata - width: %u (max 32), height: %u (max 32), count: %u (max 512)",
                                    cfo.width, cfo.height, cfo.charcount);
                else {
                        /*
                         * Console fonts supported by the kernel are limited in size to 32 x 32 and maximum 512
                         * characters. Thus with 1 bit per pixel it requires up to 65536 bytes. The height always
                         * requires 32 per glyph, regardless of the actual height - see the comment above #define
                         * max_font_size 65536 in drivers/tty/vt/vt.c for more details.
                         */
                        fontbuf = malloc_multiply((cfo.width + 7) / 8 * 32, cfo.charcount);
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
                log_full(log_level, "Fonts will not be copied to remaining consoles");

        for (unsigned i = 1; i <= 63; i++) {
                char ttyname[sizeof("/dev/tty63")];
                _cleanup_close_ int fd_d = -EBADF;

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

                (void) toggle_utf8_vc(ttyname, fd_d, utf8);

                if (cfo.op != KD_FONT_OP_SET)
                        continue;

                r = verify_vc_display_mode(fd_d);
                if (r < 0) {
                        log_debug_errno(r, "KD_FONT_OP_SET skipped: tty%u is not in text mode", i);
                        continue;
                }

                r = ioctl(fd_d, KDFONTOP, &cfo);
                if (r < 0) {
                        log_warning_errno(errno, "KD_FONT_OP_SET failed, fonts will not be copied to tty%u: %m", i);
                        continue;
                }

                /* Copy unicode translation table unimapd is a ushort count and a pointer
                 * to an array of struct unipair { ushort, ushort }. */
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
        int r, err = 0;

        assert(ret_path);
        assert(ret_idx);

        for (unsigned i = 1; i <= 63; i++) {
                _cleanup_close_ int fd = -EBADF;
                _cleanup_free_ char *path = NULL;

                r = verify_vc_allocation(i);
                if (r < 0) {
                        log_debug_errno(r, "VC %u existence check failed, skipping: %m", i);
                        RET_GATHER(err, r);
                        continue;
                }

                if (asprintf(&path, "/dev/tty%u", i) < 0)
                        return log_oom();

                fd = open_terminal(path, O_RDWR|O_CLOEXEC|O_NOCTTY);
                if (fd < 0) {
                        log_debug_errno(fd, "Failed to open terminal %s, ignoring: %m", path);
                        RET_GATHER(err, r);
                        continue;
                }

                r = verify_vc_kbmode(fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to check VC %s keyboard mode: %m", path);
                        RET_GATHER(err, r);
                        continue;
                }

                r = verify_vc_display_mode(fd);
                if (r < 0) {
                        log_debug_errno(r, "Failed to check VC %s display mode: %m", path);
                        RET_GATHER(err, r);
                        continue;
                }

                /* all checks passed, return this one as a source console */
                *ret_idx = i;
                *ret_path = TAKE_PTR(path);
                return TAKE_FD(fd);
        }

        return log_error_errno(err, "No usable source console found: %m");
}

static int verify_source_vc(char **ret_path, const char *src_vc) {
        _cleanup_close_ int fd = -EBADF;
        char *path;
        int r;

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

        /* setfont(8) silently ignores when the font can't be applied due to the vc being in
         * KD_GRAPHICS. Hence we continue to accept this case however we now let the user know that the vc
         * will be initialized only partially.*/
        r = verify_vc_display_mode(fd);
        if (r < 0)
                log_notice_errno(r, "Virtual console %s is not in KD_TEXT, font settings likely won't be applied.", src_vc);

        path = strdup(src_vc);
        if (!path)
                return log_oom();

        *ret_path = path;
        return TAKE_FD(fd);
}

static int run(int argc, char **argv) {
        _cleanup_(context_done) Context c = {};
        _cleanup_free_ char *vc = NULL;
        _cleanup_close_ int fd = -EBADF, lock_fd = -EBADF;
        bool utf8, keyboard_ok;
        unsigned idx = 0;
        int r;

        log_setup();

        umask(0022);

        if (argv[1])
                fd = verify_source_vc(&vc, argv[1]);
        else
                fd = find_source_vc(&vc, &idx);
        if (fd < 0)
                return fd;

        utf8 = is_locale_utf8();

        context_load_config(&c);

        /* Take lock around the remaining operation to avoid being interrupted by a tty reset operation
         * performed for services with TTYVHangup=yes. */
        lock_fd = lock_dev_console();
        if (lock_fd < 0) {
                log_full_errno(lock_fd == -ENOENT ? LOG_DEBUG : LOG_ERR,
                               lock_fd,
                               "Failed to lock /dev/console%s: %m",
                               lock_fd == -ENOENT ? ", ignoring" : "");
                if (lock_fd != -ENOENT)
                        return lock_fd;
        }

        (void) toggle_utf8_sysfs(utf8);
        (void) toggle_utf8_vc(vc, fd, utf8);

        r = font_load_and_wait(vc, &c);
        keyboard_ok = keyboard_load_and_wait(vc, &c, utf8) == 0;

        if (idx > 0) {
                if (r == 0)
                        setup_remaining_vcs(fd, idx, utf8);
                else
                        log_full(r == EX_OSERR ? LOG_NOTICE : LOG_WARNING,
                                 "Setting source virtual console failed, ignoring remaining ones.");
        }

        return IN_SET(r, 0, EX_OSERR) && keyboard_ok ? EXIT_SUCCESS : EXIT_FAILURE;
}

DEFINE_MAIN_FUNCTION_WITH_POSITIVE_FAILURE(run);
