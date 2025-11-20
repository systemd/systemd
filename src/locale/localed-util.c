/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>
#include <unistd.h>

#include "sd-bus.h"

#include "alloc-util.h"
#include "copy.h"
#include "env-file.h"
#include "errno-util.h"
#include "escape.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "fs-util.h"
#include "hashmap.h"
#include "kbd-util.h"
#include "localed-util.h"
#include "log.h"
#include "mkdir-label.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "xkbcommon-util.h"

int x11_context_verify_and_warn(const X11Context *xc, int log_level, sd_bus_error *error) {
        int r;

        assert(xc);

        if (!x11_context_is_safe(xc)) {
                if (error)
                        sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid X11 keyboard layout.");
                return log_full_errno(log_level, SYNTHETIC_ERRNO(EINVAL), "Invalid X11 keyboard layout.");
        }

        r = verify_xkb_rmlvo(xc->model, xc->layout, xc->variant, xc->options);
        if (r == -EOPNOTSUPP) {
                log_full_errno(MAX(log_level, LOG_NOTICE), r,
                               "Cannot verify if new keymap is correct, libxkbcommon.so unavailable.");
                return 0;
        }
        if (r < 0) {
                if (error)
                        sd_bus_error_set_errnof(error, r, "Specified keymap cannot be compiled, refusing as invalid.");
                return log_full_errno(log_level, r,
                                      "Cannot compile XKB keymap for x11 keyboard layout "
                                      "(model='%s' / layout='%s' / variant='%s' / options='%s'): %m",
                                      strempty(xc->model), strempty(xc->layout), strempty(xc->variant), strempty(xc->options));
        }

        return 0;
}

static int verify_keymap(const char *keymap, int log_level, sd_bus_error *error) {
        int r;

        assert(keymap);

        r = keymap_exists(keymap); /* This also verifies that the keymap name is kosher. */
        if (r <= 0) {
                _cleanup_free_ char *escaped = cescape(keymap);
                if (r < 0) {
                        if (error)
                                sd_bus_error_set_errnof(error, r, "Failed to check keymap %s: %m", strna(escaped));
                        return log_full_errno(log_level, r, "Failed to check keymap %s: %m", strna(escaped));
                }
                if (error)
                        sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Keymap %s is not installed.", strna(escaped));
                return log_full_errno(log_level, SYNTHETIC_ERRNO(ENOENT), "Keymap %s is not installed.", strna(escaped));
        }

        return 0;
}

int vc_context_verify_and_warn(const VCContext *vc, int log_level, sd_bus_error *error) {
        int r;

        assert(vc);

        if (vc->keymap) {
                r = verify_keymap(vc->keymap, log_level, error);
                if (r < 0)
                        return r;
        }

        if (vc->toggle) {
                r = verify_keymap(vc->toggle, log_level, error);
                if (r < 0)
                        return r;
        }

        return 0;
}

void context_clear(Context *c) {
        assert(c);

        locale_context_clear(&c->locale_context);
        x11_context_clear(&c->x11_from_xorg);
        x11_context_clear(&c->x11_from_vc);
        vc_context_clear(&c->vc);

        c->locale_cache = sd_bus_message_unref(c->locale_cache);
        c->x11_cache = sd_bus_message_unref(c->x11_cache);
        c->vc_cache = sd_bus_message_unref(c->vc_cache);

        c->polkit_registry = hashmap_free(c->polkit_registry);
};

X11Context *context_get_x11_context(Context *c) {
        assert(c);

        if (!x11_context_isempty(&c->x11_from_vc))
                return &c->x11_from_vc;

        if (!x11_context_isempty(&c->x11_from_xorg))
                return &c->x11_from_xorg;

        return &c->x11_from_vc;
}

int locale_read_data(Context *c, sd_bus_message *m) {
        assert(c);

        /* Do not try to re-read the file within single bus operation. */
        if (m) {
                if (m == c->locale_cache)
                        return 0;

                sd_bus_message_unref(c->locale_cache);
                c->locale_cache = sd_bus_message_ref(m);
        }

        return locale_context_load(&c->locale_context, LOCALE_LOAD_LOCALE_CONF | LOCALE_LOAD_ENVIRONMENT | LOCALE_LOAD_SIMPLIFY);
}

int vconsole_read_data(Context *c, sd_bus_message *m) {
        _cleanup_close_ int fd = -EBADF;
        struct stat st;
        int r;

        assert(c);

        /* Do not try to re-read the file within single bus operation. */
        if (m) {
                if (m == c->vc_cache)
                        return 0;

                sd_bus_message_unref(c->vc_cache);
                c->vc_cache = sd_bus_message_ref(m);
        }

        fd = RET_NERRNO(open(etc_vconsole_conf(), O_CLOEXEC | O_PATH));
        if (fd == -ENOENT) {
                c->vc_stat = (struct stat) {};
                vc_context_clear(&c->vc);
                x11_context_clear(&c->x11_from_vc);
                return 0;
        }
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* If the file is not changed, then we do not need to re-read */
        if (stat_inode_unmodified(&c->vc_stat, &st))
                return 0;

        c->vc_stat = st;
        vc_context_clear(&c->vc);
        x11_context_clear(&c->x11_from_vc);

        r = parse_env_file_fd(
                        fd, etc_vconsole_conf(),
                        "KEYMAP",        &c->vc.keymap,
                        "KEYMAP_TOGGLE", &c->vc.toggle,
                        "XKBLAYOUT",     &c->x11_from_vc.layout,
                        "XKBMODEL",      &c->x11_from_vc.model,
                        "XKBVARIANT",    &c->x11_from_vc.variant,
                        "XKBOPTIONS",    &c->x11_from_vc.options);
        if (r < 0)
                return r;

        if (vc_context_verify(&c->vc) < 0)
                vc_context_clear(&c->vc);

        if (x11_context_verify(&c->x11_from_vc) < 0)
                x11_context_clear(&c->x11_from_vc);

        return 0;
}

int x11_read_data(Context *c, sd_bus_message *m) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_fclose_ FILE *f = NULL;
        bool in_section = false;
        struct stat st;
        int r;

        assert(c);

        /* Do not try to re-read the file within single bus operation. */
        if (m) {
                if (m == c->x11_cache)
                        return 0;

                sd_bus_message_unref(c->x11_cache);
                c->x11_cache = sd_bus_message_ref(m);
        }

        fd = RET_NERRNO(open("/etc/X11/xorg.conf.d/00-keyboard.conf", O_CLOEXEC | O_PATH));
        if (fd == -ENOENT) {
                c->x11_stat = (struct stat) {};
                x11_context_clear(&c->x11_from_xorg);
                return 0;
        }
        if (fd < 0)
                return fd;

        if (fstat(fd, &st) < 0)
                return -errno;

        /* If the file is not changed, then we do not need to re-read */
        if (stat_inode_unmodified(&c->x11_stat, &st))
                return 0;

        c->x11_stat = st;
        x11_context_clear(&c->x11_from_xorg);

        r = fdopen_independent(fd, "re", &f);
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                if (in_section && first_word(line, "Option")) {
                        _cleanup_strv_free_ char **a = NULL;

                        r = strv_split_full(&a, line, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return r;

                        if (strv_length(a) == 3) {
                                char **p = NULL;

                                if (streq(a[1], "XkbLayout"))
                                        p = &c->x11_from_xorg.layout;
                                else if (streq(a[1], "XkbModel"))
                                        p = &c->x11_from_xorg.model;
                                else if (streq(a[1], "XkbVariant"))
                                        p = &c->x11_from_xorg.variant;
                                else if (streq(a[1], "XkbOptions"))
                                        p = &c->x11_from_xorg.options;

                                if (p)
                                        free_and_replace(*p, a[2]);
                        }

                } else if (!in_section && first_word(line, "Section")) {
                        _cleanup_strv_free_ char **a = NULL;

                        r = strv_split_full(&a, line, WHITESPACE, EXTRACT_UNQUOTE);
                        if (r < 0)
                                return -ENOMEM;

                        if (strv_length(a) == 2 && streq(a[1], "InputClass"))
                                in_section = true;

                } else if (in_section && first_word(line, "EndSection"))
                        in_section = false;
        }

        if (x11_context_verify(&c->x11_from_xorg) < 0)
                x11_context_clear(&c->x11_from_xorg);

        return 0;
}

int vconsole_write_data(Context *c) {
        _cleanup_strv_free_ char **l = NULL;
        const X11Context *xc;
        int r;

        assert(c);

        xc = context_get_x11_context(c);

        r = load_env_file(NULL, etc_vconsole_conf(), &l);
        if (r < 0 && r != -ENOENT)
                return r;

        r = vconsole_serialize(&c->vc, xc, &l);
        if (r < 0)
                return r;

        if (strv_isempty(l)) {
                if (unlink(etc_vconsole_conf()) < 0)
                        return errno == ENOENT ? 0 : -errno;

                c->vc_stat = (struct stat) {};
                return 0;
        }

        r = write_vconsole_conf(AT_FDCWD, "/etc/vconsole.conf", l);
        if (r < 0)
                return r;

        if (stat(etc_vconsole_conf(), &c->vc_stat) < 0)
                return -errno;

        return 0;
}

int x11_write_data(Context *c) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        const X11Context *xc;
        int r;

        assert(c);

        xc = context_get_x11_context(c);
        if (x11_context_isempty(xc)) {
                if (unlink("/etc/X11/xorg.conf.d/00-keyboard.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                c->x11_stat = (struct stat) {};
                return 0;
        }

        (void) mkdir_p_label("/etc/X11/xorg.conf.d", 0755);
        r = fopen_temporary("/etc/X11/xorg.conf.d/00-keyboard.conf", &f, &temp_path);
        if (r < 0)
                return r;

        (void) fchmod(fileno(f), 0644);

        fputs("# Written by systemd-localed(8), read by systemd-localed and Xorg. It's\n"
              "# probably wise not to edit this file manually. Use localectl(1) to\n"
              "# update this file.\n"
              "Section \"InputClass\"\n"
              "        Identifier \"system-keyboard\"\n"
              "        MatchIsKeyboard \"on\"\n", f);

        if (!isempty(xc->layout))
                fprintf(f, "        Option \"XkbLayout\" \"%s\"\n", xc->layout);

        if (!isempty(xc->model))
                fprintf(f, "        Option \"XkbModel\" \"%s\"\n", xc->model);

        if (!isempty(xc->variant))
                fprintf(f, "        Option \"XkbVariant\" \"%s\"\n", xc->variant);

        if (!isempty(xc->options))
                fprintf(f, "        Option \"XkbOptions\" \"%s\"\n", xc->options);

        fputs("EndSection\n", f);

        r = fflush_sync_and_check(f);
        if (r < 0)
                return r;

        if (rename(temp_path, "/etc/X11/xorg.conf.d/00-keyboard.conf") < 0)
                return -errno;

        if (stat("/etc/X11/xorg.conf.d/00-keyboard.conf", &c->x11_stat) < 0)
                return -errno;

        return 0;
}

bool locale_gen_check_available(void) {
#if HAVE_LOCALEGEN
        if (access(LOCALEGEN_PATH, X_OK) < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Unable to determine whether " LOCALEGEN_PATH " exists and is executable, assuming it is not: %m");
                return false;
        }
        if (access("/etc/locale.gen", F_OK) < 0) {
                if (errno != ENOENT)
                        log_warning_errno(errno, "Unable to determine whether /etc/locale.gen exists, assuming it does not: %m");
                return false;
        }
        return true;
#else
        return false;
#endif
}

#if HAVE_LOCALEGEN
static bool locale_encoding_is_utf8_or_unspecified(const char *locale) {
        const char *c = strchr(locale, '.');
        return !c || strcaseeq(c, ".UTF-8") || strcasestr(locale, ".UTF-8@");
}

static int locale_gen_locale_supported(const char *locale_entry) {
        /* Returns an error valus <= 0 if the locale-gen entry is invalid or unsupported,
         * 1 in case the locale entry is valid, and -EOPNOTSUPP specifically in case
         * the distributor has not provided us with a SUPPORTED file to check
         * locale for validity. */

        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(locale_entry);

        /* Locale templates without country code are never supported */
        if (!strstr(locale_entry, "_"))
                return -EINVAL;

        f = fopen("/usr/share/i18n/SUPPORTED", "re");
        if (!f) {
                if (errno == ENOENT)
                        return log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                               "Unable to check validity of locale entry %s: /usr/share/i18n/SUPPORTED does not exist",
                                               locale_entry);
                return -errno;
        }

        for (;;) {
                _cleanup_free_ char *line = NULL;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return log_debug_errno(r, "Failed to read /usr/share/i18n/SUPPORTED: %m");
                if (r == 0)
                        return 0;

                if (strcaseeq_ptr(line, locale_entry))
                        return 1;
        }
}
#endif

int locale_gen_enable_locale(const char *locale) {
#if HAVE_LOCALEGEN
        _cleanup_fclose_ FILE *fr = NULL, *fw = NULL;
        _cleanup_(unlink_and_freep) char *temp_path = NULL;
        _cleanup_free_ char *locale_entry = NULL;
        bool locale_enabled = false, first_line = false;
        bool write_new = false;
        int r;

        if (isempty(locale))
                return 0;

        if (locale_encoding_is_utf8_or_unspecified(locale)) {
                locale_entry = strjoin(locale, " UTF-8");
                if (!locale_entry)
                        return -ENOMEM;
        } else
                return -ENOEXEC; /* We do not process non-UTF-8 locale */

        r = locale_gen_locale_supported(locale_entry);
        if (r == 0)
                return -EINVAL;
        if (r < 0 && r != -EOPNOTSUPP)
                return r;

        fr = fopen("/etc/locale.gen", "re");
        if (!fr) {
                if (errno != ENOENT)
                        return -errno;
                write_new = true;
        }

        r = fopen_temporary("/etc/locale.gen", &fw, &temp_path);
        if (r < 0)
                return r;

        if (write_new)
                (void) fchmod(fileno(fw), 0644);
        else {
                /* apply mode & xattrs of the original file to new file */
                r = copy_access(fileno(fr), fileno(fw));
                if (r < 0)
                        return r;
                r = copy_xattr(fileno(fr), NULL, fileno(fw), NULL, COPY_ALL_XATTRS);
                if (r < 0)
                        log_debug_errno(r, "Failed to copy all xattrs from old to new /etc/locale.gen file, ignoring: %m");
        }

        if (!write_new) {
                /* The config file ends with a line break, which we do not want to include before potentially appending a new locale
                * instead of uncommenting an existing line. By prepending linebreaks, we can avoid buffering this file but can still write
                * a nice config file without empty lines */
                first_line = true;
                for (;;) {
                        _cleanup_free_ char *line = NULL;
                        char *line_locale;

                        r = read_line(fr, LONG_LINE_MAX, &line);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        if (locale_enabled) {
                                /* Just complete writing the file if the new locale was already enabled */
                                if (!first_line)
                                        fputc('\n', fw);
                                fputs(line, fw);
                                first_line = false;
                                continue;
                        }

                        line_locale = strstrip(line);
                        if (isempty(line_locale)) {
                                fputc('\n', fw);
                                first_line = false;
                                continue;
                        }

                        if (line_locale[0] == '#')
                                line_locale = strstrip(line_locale + 1);
                        else if (strcaseeq_ptr(line_locale, locale_entry))
                                return 0; /* the file already had our locale activated, so skip updating it */

                        if (strcaseeq_ptr(line_locale, locale_entry)) {
                                /* Uncomment existing line for new locale */
                                if (!first_line)
                                        fputc('\n', fw);
                                fputs(locale_entry, fw);
                                locale_enabled = true;
                                first_line = false;
                                continue;
                        }

                        /* The line was not for the locale we want to enable, just copy it */
                        if (!first_line)
                                fputc('\n', fw);
                        fputs(line, fw);
                        first_line = false;
                }
        }

        /* Add locale to enable to the end of the file if it was not found as commented line */
        if (!locale_enabled) {
                if (!write_new)
                        fputc('\n', fw);
                fputs(locale_entry, fw);
        }
        fputc('\n', fw);

        r = fflush_sync_and_check(fw);
        if (r < 0)
                return r;

        if (rename(temp_path, "/etc/locale.gen") < 0)
                return -errno;
        temp_path = mfree(temp_path);

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}

int locale_gen_run(void) {
#if HAVE_LOCALEGEN
        pid_t pid;
        int r;

        r = safe_fork("(sd-localegen)", FORK_RESET_SIGNALS|FORK_RLIMIT_NOFILE_SAFE|FORK_CLOSE_ALL_FDS|FORK_LOG|FORK_WAIT, &pid);
        if (r < 0)
                return r;
        if (r == 0) {
                execl(LOCALEGEN_PATH, LOCALEGEN_PATH, NULL);
                _exit(EXIT_FAILURE);
        }

        return 0;
#else
        return -EOPNOTSUPP;
#endif
}
