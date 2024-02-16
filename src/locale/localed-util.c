/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include "bus-polkit.h"
#include "copy.h"
#include "env-file-label.h"
#include "env-file.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "fileio.h"
#include "fs-util.h"
#include "kbd-util.h"
#include "localed-util.h"
#include "macro.h"
#include "mkdir-label.h"
#include "nulstr-util.h"
#include "process-util.h"
#include "stat-util.h"
#include "string-util.h"
#include "strv.h"
#include "tmpfile-util.h"
#include "xkbcommon-util.h"

static bool startswith_comma(const char *s, const char *prefix) {
        assert(s);
        assert(prefix);

        s = startswith(s, prefix);
        if (!s)
                return false;

        return IN_SET(*s, ',', '\0');
}

static const char* systemd_kbd_model_map(void) {
        const char* s;

        s = getenv("SYSTEMD_KBD_MODEL_MAP");
        if (s)
                return s;

        return SYSTEMD_KBD_MODEL_MAP;
}

static const char* systemd_language_fallback_map(void) {
        const char* s;

        s = getenv("SYSTEMD_LANGUAGE_FALLBACK_MAP");
        if (s)
                return s;

        return SYSTEMD_LANGUAGE_FALLBACK_MAP;
}

void x11_context_clear(X11Context *xc) {
        assert(xc);

        xc->layout  = mfree(xc->layout);
        xc->options = mfree(xc->options);
        xc->model   = mfree(xc->model);
        xc->variant = mfree(xc->variant);
}

void x11_context_replace(X11Context *dest, X11Context *src) {
        assert(dest);
        assert(src);

        x11_context_clear(dest);
        *dest = TAKE_STRUCT(*src);
}

bool x11_context_isempty(const X11Context *xc) {
        assert(xc);

        return
                isempty(xc->layout)  &&
                isempty(xc->model)   &&
                isempty(xc->variant) &&
                isempty(xc->options);
}

void x11_context_empty_to_null(X11Context *xc) {
        assert(xc);

        /* Do not call x11_context_clear() for the passed object. */

        xc->layout  = empty_to_null(xc->layout);
        xc->model   = empty_to_null(xc->model);
        xc->variant = empty_to_null(xc->variant);
        xc->options = empty_to_null(xc->options);
}

bool x11_context_is_safe(const X11Context *xc) {
        assert(xc);

        return
                (!xc->layout  || string_is_safe(xc->layout))  &&
                (!xc->model   || string_is_safe(xc->model))   &&
                (!xc->variant || string_is_safe(xc->variant)) &&
                (!xc->options || string_is_safe(xc->options));
}

bool x11_context_equal(const X11Context *a, const X11Context *b) {
        assert(a);
        assert(b);

        return
                streq_ptr(a->layout,  b->layout)  &&
                streq_ptr(a->model,   b->model)   &&
                streq_ptr(a->variant, b->variant) &&
                streq_ptr(a->options, b->options);
}

int x11_context_copy(X11Context *dest, const X11Context *src) {
        bool modified;
        int r;

        assert(dest);

        if (dest == src)
                return 0;

        if (!src) {
                modified = !x11_context_isempty(dest);
                x11_context_clear(dest);
                return modified;
        }

        r = free_and_strdup(&dest->layout, src->layout);
        if (r < 0)
                return r;
        modified = r > 0;

        r = free_and_strdup(&dest->model, src->model);
        if (r < 0)
                return r;
        modified = modified || r > 0;

        r = free_and_strdup(&dest->variant, src->variant);
        if (r < 0)
                return r;
        modified = modified || r > 0;

        r = free_and_strdup(&dest->options, src->options);
        if (r < 0)
                return r;
        modified = modified || r > 0;

        return modified;
}

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

void vc_context_clear(VCContext *vc) {
        assert(vc);

        vc->keymap = mfree(vc->keymap);
        vc->toggle = mfree(vc->toggle);
}

void vc_context_replace(VCContext *dest, VCContext *src) {
        assert(dest);
        assert(src);

        vc_context_clear(dest);
        *dest = TAKE_STRUCT(*src);
}

bool vc_context_isempty(const VCContext *vc) {
        assert(vc);

        return
                isempty(vc->keymap) &&
                isempty(vc->toggle);
}

void vc_context_empty_to_null(VCContext *vc) {
        assert(vc);

        /* Do not call vc_context_clear() for the passed object. */

        vc->keymap = empty_to_null(vc->keymap);
        vc->toggle = empty_to_null(vc->toggle);
}

bool vc_context_equal(const VCContext *a, const VCContext *b) {
        assert(a);
        assert(b);

        return
                streq_ptr(a->keymap, b->keymap) &&
                streq_ptr(a->toggle, b->toggle);
}

int vc_context_copy(VCContext *dest, const VCContext *src) {
        bool modified;
        int r;

        assert(dest);

        if (dest == src)
                return 0;

        if (!src) {
                modified = !vc_context_isempty(dest);
                vc_context_clear(dest);
                return modified;
        }

        r = free_and_strdup(&dest->keymap, src->keymap);
        if (r < 0)
                return r;
        modified = r > 0;

        r = free_and_strdup(&dest->toggle, src->toggle);
        if (r < 0)
                return r;
        modified = modified || r > 0;

        return modified;
}

static int verify_keymap(const char *keymap, int log_level, sd_bus_error *error) {
        int r;

        assert(keymap);

        r = keymap_exists(keymap); /* This also verifies that the keymap name is kosher. */
        if (r < 0) {
                if (error)
                        sd_bus_error_set_errnof(error, r, "Failed to check keymap %s: %m", keymap);
                return log_full_errno(log_level, r, "Failed to check keymap %s: %m", keymap);
        }
        if (r == 0) {
                if (error)
                        sd_bus_error_setf(error, SD_BUS_ERROR_FAILED, "Keymap %s is not installed.", keymap);
                return log_full_errno(log_level, SYNTHETIC_ERRNO(ENOENT), "Keymap %s is not installed.", keymap);
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

        fd = RET_NERRNO(open("/etc/vconsole.conf", O_CLOEXEC | O_PATH));
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
                        fd, "/etc/vconsole.conf",
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

        r = load_env_file(NULL, "/etc/vconsole.conf", &l);
        if (r < 0 && r != -ENOENT)
                return r;

        r = strv_env_assign(&l, "KEYMAP", empty_to_null(c->vc.keymap));
        if (r < 0)
                return r;

        r = strv_env_assign(&l, "KEYMAP_TOGGLE", empty_to_null(c->vc.toggle));
        if (r < 0)
                return r;

        r = strv_env_assign(&l, "XKBLAYOUT", empty_to_null(xc->layout));
        if (r < 0)
                return r;

        r = strv_env_assign(&l, "XKBMODEL", empty_to_null(xc->model));
        if (r < 0)
                return r;

        r = strv_env_assign(&l, "XKBVARIANT", empty_to_null(xc->variant));
        if (r < 0)
                return r;

        r = strv_env_assign(&l, "XKBOPTIONS", empty_to_null(xc->options));
        if (r < 0)
                return r;

        if (strv_isempty(l)) {
                if (unlink("/etc/vconsole.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                c->vc_stat = (struct stat) {};
                return 0;
        }

        r = write_vconsole_conf_label(l);
        if (r < 0)
                return r;

        if (stat("/etc/vconsole.conf", &c->vc_stat) < 0)
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

static int read_next_mapping(
                const char *filename,
                unsigned min_fields,
                unsigned max_fields,
                FILE *f,
                unsigned *n,
                char ***ret) {

        assert(f);
        assert(n);
        assert(ret);

        for (;;) {
                _cleanup_strv_free_ char **b = NULL;
                _cleanup_free_ char *line = NULL;
                size_t length;
                int r;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                (*n)++;

                if (IN_SET(line[0], 0, '#'))
                        continue;

                r = strv_split_full(&b, line, WHITESPACE, EXTRACT_UNQUOTE);
                if (r < 0)
                        return r;

                length = strv_length(b);
                if (length < min_fields || length > max_fields) {
                        log_debug("Invalid line %s:%u, ignoring.", strna(filename), *n);
                        continue;

                }

                *ret = TAKE_PTR(b);
                return 1;
        }

        *ret = NULL;
        return 0;
}

int vconsole_convert_to_x11(const VCContext *vc, X11Context *ret) {
        _cleanup_fclose_ FILE *f = NULL;
        const char *map;
        X11Context xc;
        int r;

        assert(vc);
        assert(ret);

        if (isempty(vc->keymap)) {
                *ret = (X11Context) {};
                return 0;
        }

        map = systemd_kbd_model_map();
        f = fopen(map, "re");
        if (!f)
                return -errno;

        for (unsigned n = 0;;) {
                _cleanup_strv_free_ char **a = NULL;

                r = read_next_mapping(map, 5, UINT_MAX, f, &n, &a);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                if (!streq(vc->keymap, a[0]))
                        continue;

                xc = (X11Context) {
                        .layout  = empty_or_dash_to_null(a[1]),
                        .model   = empty_or_dash_to_null(a[2]),
                        .variant = empty_or_dash_to_null(a[3]),
                        .options = empty_or_dash_to_null(a[4]),
                };

                if (x11_context_verify(&xc) < 0)
                        continue;

                return x11_context_copy(ret, &xc);
        }

        /* No custom mapping has been found, see if the keymap is a converted one. In such case deducing the
         * corresponding x11 layout is easy. */
        _cleanup_free_ char *xlayout = NULL, *converted = NULL;
        char *xvariant;

        xlayout = strdup(vc->keymap);
        if (!xlayout)
                return -ENOMEM;
        xvariant = strchr(xlayout, '-');
        if (xvariant) {
                xvariant[0] = '\0';
                xvariant++;
        }

        /* Note: by default we use keyboard model "microsoftpro" which should be equivalent to "pc105" but
         * with the internet/media key mapping added. */
        xc = (X11Context) {
                .layout  = xlayout,
                .model   = (char*) "microsoftpro",
                .variant = xvariant,
                .options = (char*) "terminate:ctrl_alt_bksp",
        };

        /* This sanity check seems redundant with the verification of the X11 layout done on the next
         * step. However xkbcommon is an optional dependency hence the verification might be a NOP.  */
        r = find_converted_keymap(&xc, &converted);
        if (r == 0 && xc.variant) {
                /* If we still haven't find a match, try with no variant, it's still better than nothing.  */
                xc.variant = NULL;
                r = find_converted_keymap(&xc, &converted);
        }
        if (r < 0)
                return r;

        if (r == 0 || x11_context_verify(&xc) < 0) {
                *ret = (X11Context) {};
                return 0;
        }

        return x11_context_copy(ret, &xc);
}

int find_converted_keymap(const X11Context *xc, char **ret) {
        _cleanup_free_ char *n = NULL;

        assert(xc);
        assert(!isempty(xc->layout));
        assert(ret);

        if (xc->variant)
                n = strjoin(xc->layout, "-", xc->variant);
        else
                n = strdup(xc->layout);
        if (!n)
                return -ENOMEM;

        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                _cleanup_free_ char *p = NULL, *pz = NULL;
                bool uncompressed;

                p = strjoin(dir, "xkb/", n, ".map");
                pz = strjoin(dir, "xkb/", n, ".map.gz");
                if (!p || !pz)
                        return -ENOMEM;

                uncompressed = access(p, F_OK) == 0;
                if (uncompressed || access(pz, F_OK) == 0) {
                        log_debug("Found converted keymap %s at %s", n, uncompressed ? p : pz);
                        *ret = TAKE_PTR(n);
                        return 1;
                }
        }

        *ret = NULL;
        return 0;
}

int find_legacy_keymap(const X11Context *xc, char **ret) {
        const char *map;
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *new_keymap = NULL;
        unsigned best_matching = 0;
        int r;

        assert(xc);
        assert(!isempty(xc->layout));

        map = systemd_kbd_model_map();
        f = fopen(map, "re");
        if (!f)
                return -errno;

        for (unsigned n = 0;;) {
                _cleanup_strv_free_ char **a = NULL;
                unsigned matching = 0;

                r = read_next_mapping(map, 5, UINT_MAX, f, &n, &a);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Determine how well matching this entry is */
                if (streq(xc->layout, a[1]))
                        /* If we got an exact match, this is the best */
                        matching = 10;
                else {
                        /* see if we get an exact match with the order reversed */
                        _cleanup_strv_free_ char **b = NULL;
                        _cleanup_free_ char *c = NULL;
                        r = strv_split_full(&b, a[1], ",", 0);
                        if (r < 0)
                                return r;
                        strv_reverse(b);
                        c = strv_join(b, ",");
                        if (!c)
                                return log_oom();
                        if (streq(xc->layout, c))
                                matching = 9;
                        else {
                                /* We have multiple X layouts, look for an
                                 * entry that matches our key with everything
                                 * but the first layout stripped off. */
                                if (startswith_comma(xc->layout, a[1]))
                                        matching = 5;
                                else {
                                        _cleanup_free_ char *x = NULL;

                                        /* If that didn't work, strip off the
                                         * other layouts from the entry, too */
                                        x = strdupcspn(a[1], ",");
                                        if (!x)
                                                return -ENOMEM;
                                        if (startswith_comma(xc->layout, x))
                                                matching = 1;
                                }
                        }
                }

                if (matching > 0) {
                        if (isempty(xc->model) || streq_ptr(xc->model, a[2])) {
                                matching++;

                                if (streq_ptr(xc->variant, a[3]) || ((isempty(xc->variant) || streq_skip_trailing_chars(xc->variant, "", ",")) && streq(a[3], "-"))) {
                                        matching++;

                                        if (streq_ptr(xc->options, a[4]))
                                                matching++;
                                }
                        }
                }

                /* The best matching entry so far, then let's save that */
                if (matching >= MAX(best_matching, 1u)) {
                        log_debug("Found legacy keymap %s with score %u", a[0], matching);

                        if (matching > best_matching) {
                                best_matching = matching;

                                r = free_and_strdup(&new_keymap, a[0]);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (best_matching < 9 && !isempty(xc->layout)) {
                _cleanup_free_ char *l = NULL, *v = NULL, *converted = NULL;

                /* The best match is only the first part of the X11
                 * keymap. Check if we have a converted map which
                 * matches just the first layout.
                 */

                l = strdupcspn(xc->layout, ",");
                if (!l)
                        return -ENOMEM;

                if (!isempty(xc->variant)) {
                        v = strdupcspn(xc->variant, ",");
                        if (!v)
                                return -ENOMEM;
                }

                r = find_converted_keymap(
                                &(X11Context) {
                                        .layout = l,
                                        .variant = v,
                                },
                                &converted);
                if (r < 0)
                        return r;
                if (r > 0)
                        free_and_replace(new_keymap, converted);
        }

        *ret = TAKE_PTR(new_keymap);
        return !!*ret;
}

int x11_convert_to_vconsole(const X11Context *xc, VCContext *ret) {
        _cleanup_free_ char *keymap = NULL;
        int r;

        assert(xc);
        assert(ret);

        if (isempty(xc->layout)) {
                *ret = (VCContext) {};
                return 0;
        }

        r = find_converted_keymap(xc, &keymap);
        if (r == 0) {
                r = find_legacy_keymap(xc, &keymap);
                if (r == 0 && xc->variant)
                        /* If we still haven't find a match, try with no variant, it's still better than
                         * nothing.  */
                        r = find_converted_keymap(
                                        &(X11Context) {
                                                .layout = xc->layout,
                                        },
                                        &keymap);
        }
        if (r < 0)
                return r;

        *ret = (VCContext) {
                .keymap = TAKE_PTR(keymap),
        };
        return 0;
}

int find_language_fallback(const char *lang, char **ret) {
        const char *map;
        _cleanup_fclose_ FILE *f = NULL;
        unsigned n = 0;
        int r;

        assert(lang);
        assert(ret);

        map = systemd_language_fallback_map();
        f = fopen(map, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_strv_free_ char **a = NULL;

                r = read_next_mapping(map, 2, 2, f, &n, &a);
                if (r <= 0)
                        return r;

                if (streq(lang, a[0])) {
                        assert(strv_length(a) == 2);
                        *ret = TAKE_PTR(a[1]);
                        return 1;
                }
        }
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
