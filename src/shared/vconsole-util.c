/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdlib.h>
#include <unistd.h>

#include "alloc-util.h"
#include "env-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "kbd-util.h"
#include "log.h"
#include "string-util.h"
#include "strv.h"
#include "vconsole-util.h"

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

int vconsole_convert_to_x11(const VCContext *vc, X11VerifyCallback verify, X11Context *ret) {
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

                if (verify && verify(&xc) < 0)
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

        if (r == 0 || (verify && verify(&xc) < 0)) {
                *ret = (X11Context) {};
                return 0;
        }

        return x11_context_copy(ret, &xc);
}

int find_converted_keymap(const X11Context *xc, char **ret) {
        _cleanup_free_ char *n = NULL, *p = NULL, *pz = NULL;
        _cleanup_strv_free_ char **keymap_dirs = NULL;
        int r;

        assert(xc);
        assert(!isempty(xc->layout));
        assert(ret);

        if (xc->variant)
                n = strjoin(xc->layout, "-", xc->variant);
        else
                n = strdup(xc->layout);
        if (!n)
                return -ENOMEM;

        p = strjoin("xkb/", n, ".map");
        pz = strjoin("xkb/", n, ".map.gz");
        if (!p || !pz)
                return -ENOMEM;

        r = keymap_directories(&keymap_dirs);
        if (r < 0)
                return r;

        STRV_FOREACH(dir, keymap_dirs) {
                _cleanup_close_ int dir_fd = -EBADF;
                bool uncompressed;

                dir_fd = open(*dir, O_CLOEXEC | O_DIRECTORY | O_PATH);
                if (dir_fd < 0) {
                        if (errno != ENOENT)
                                log_debug_errno(errno, "Failed to open %s, ignoring: %m", *dir);
                        continue;
                }

                uncompressed = faccessat(dir_fd, p, F_OK, 0) >= 0;
                if (uncompressed || faccessat(dir_fd, pz, F_OK, 0) >= 0) {
                        log_debug("Found converted keymap %s at %s/%s", n, *dir, uncompressed ? p : pz);
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

int vconsole_serialize(const VCContext *vc, const X11Context *xc, char ***env) {
        int r;

        /* This function modifies the passed strv in place. */

        assert(vc);
        assert(xc);
        assert(env);

        r = strv_env_assign(env, "KEYMAP", empty_to_null(vc->keymap));
        if (r < 0)
                return r;

        r = strv_env_assign(env, "KEYMAP_TOGGLE", empty_to_null(vc->toggle));
        if (r < 0)
                return r;

        r = strv_env_assign(env, "XKBLAYOUT", empty_to_null(xc->layout));
        if (r < 0)
                return r;

        r = strv_env_assign(env, "XKBMODEL", empty_to_null(xc->model));
        if (r < 0)
                return r;

        r = strv_env_assign(env, "XKBVARIANT", empty_to_null(xc->variant));
        if (r < 0)
                return r;

        r = strv_env_assign(env, "XKBOPTIONS", empty_to_null(xc->options));
        if (r < 0)
                return r;

        return 0;
}
