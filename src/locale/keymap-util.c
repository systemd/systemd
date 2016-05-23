/***
  This file is part of systemd.

  Copyright 2011 Lennart Poettering
  Copyright 2013 Kay Sievers

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
#include <string.h>
#include <unistd.h>

#include "def.h"
#include "env-util.h"
#include "fd-util.h"
#include "fileio-label.h"
#include "fileio.h"
#include "keymap-util.h"
#include "locale-util.h"
#include "macro.h"
#include "mkdir.h"
#include "string-util.h"
#include "strv.h"

static bool startswith_comma(const char *s, const char *prefix) {
        const char *t;

        return s && (t = startswith(s, prefix)) && (*t == ',');
}

static const char* strnulldash(const char *s) {
        return isempty(s) || streq(s, "-") ? NULL : s;
}

static void context_free_x11(Context *c) {
        c->x11_layout = mfree(c->x11_layout);
        c->x11_options = mfree(c->x11_options);
        c->x11_model = mfree(c->x11_model);
        c->x11_variant = mfree(c->x11_variant);
}

static void context_free_vconsole(Context *c) {
        c->vc_keymap = mfree(c->vc_keymap);
        c->vc_keymap_toggle = mfree(c->vc_keymap_toggle);
}

static void context_free_locale(Context *c) {
        int p;

        for (p = 0; p < _VARIABLE_LC_MAX; p++)
                c->locale[p] = mfree(c->locale[p]);
}

void context_free(Context *c) {
        context_free_locale(c);
        context_free_x11(c);
        context_free_vconsole(c);
};

void locale_simplify(Context *c) {
        int p;

        for (p = VARIABLE_LANG+1; p < _VARIABLE_LC_MAX; p++)
                if (isempty(c->locale[p]) || streq_ptr(c->locale[VARIABLE_LANG], c->locale[p]))
                        c->locale[p] = mfree(c->locale[p]);
}

static int locale_read_data(Context *c) {
        int r;

        context_free_locale(c);

        r = parse_env_file("/etc/locale.conf", NEWLINE,
                           "LANG",              &c->locale[VARIABLE_LANG],
                           "LANGUAGE",          &c->locale[VARIABLE_LANGUAGE],
                           "LC_CTYPE",          &c->locale[VARIABLE_LC_CTYPE],
                           "LC_NUMERIC",        &c->locale[VARIABLE_LC_NUMERIC],
                           "LC_TIME",           &c->locale[VARIABLE_LC_TIME],
                           "LC_COLLATE",        &c->locale[VARIABLE_LC_COLLATE],
                           "LC_MONETARY",       &c->locale[VARIABLE_LC_MONETARY],
                           "LC_MESSAGES",       &c->locale[VARIABLE_LC_MESSAGES],
                           "LC_PAPER",          &c->locale[VARIABLE_LC_PAPER],
                           "LC_NAME",           &c->locale[VARIABLE_LC_NAME],
                           "LC_ADDRESS",        &c->locale[VARIABLE_LC_ADDRESS],
                           "LC_TELEPHONE",      &c->locale[VARIABLE_LC_TELEPHONE],
                           "LC_MEASUREMENT",    &c->locale[VARIABLE_LC_MEASUREMENT],
                           "LC_IDENTIFICATION", &c->locale[VARIABLE_LC_IDENTIFICATION],
                           NULL);

        if (r == -ENOENT) {
                int p;

                /* Fill in what we got passed from systemd. */
                for (p = 0; p < _VARIABLE_LC_MAX; p++) {
                        const char *name;

                        name = locale_variable_to_string(p);
                        assert(name);

                        r = free_and_strdup(&c->locale[p], empty_to_null(getenv(name)));
                        if (r < 0)
                                return r;
                }

                r = 0;
        }

        locale_simplify(c);
        return r;
}

static int vconsole_read_data(Context *c) {
        int r;

        context_free_vconsole(c);

        r = parse_env_file("/etc/vconsole.conf", NEWLINE,
                           "KEYMAP",        &c->vc_keymap,
                           "KEYMAP_TOGGLE", &c->vc_keymap_toggle,
                           NULL);

        if (r < 0 && r != -ENOENT)
                return r;

        return 0;
}

static int x11_read_data(Context *c) {
        _cleanup_fclose_ FILE *f;
        char line[LINE_MAX];
        bool in_section = false;
        int r;

        context_free_x11(c);

        f = fopen("/etc/X11/xorg.conf.d/00-keyboard.conf", "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        while (fgets(line, sizeof(line), f)) {
                char *l;

                char_array_0(line);
                l = strstrip(line);

                if (l[0] == 0 || l[0] == '#')
                        continue;

                if (in_section && first_word(l, "Option")) {
                        _cleanup_strv_free_ char **a = NULL;

                        r = strv_split_extract(&a, l, WHITESPACE, EXTRACT_QUOTES);
                        if (r < 0)
                                return r;

                        if (strv_length(a) == 3) {
                                char **p = NULL;

                                if (streq(a[1], "XkbLayout"))
                                        p = &c->x11_layout;
                                else if (streq(a[1], "XkbModel"))
                                        p = &c->x11_model;
                                else if (streq(a[1], "XkbVariant"))
                                        p = &c->x11_variant;
                                else if (streq(a[1], "XkbOptions"))
                                        p = &c->x11_options;

                                if (p) {
                                        free(*p);
                                        *p = a[2];
                                        a[2] = NULL;
                                }
                        }

                } else if (!in_section && first_word(l, "Section")) {
                        _cleanup_strv_free_ char **a = NULL;

                        r = strv_split_extract(&a, l, WHITESPACE, EXTRACT_QUOTES);
                        if (r < 0)
                                return -ENOMEM;

                        if (strv_length(a) == 2 && streq(a[1], "InputClass"))
                                in_section = true;

                } else if (in_section && first_word(l, "EndSection"))
                        in_section = false;
        }

        return 0;
}

int context_read_data(Context *c) {
        int r, q, p;

        r = locale_read_data(c);
        q = vconsole_read_data(c);
        p = x11_read_data(c);

        return r < 0 ? r : q < 0 ? q : p;
}

int locale_write_data(Context *c, char ***settings) {
        int r, p;
        _cleanup_strv_free_ char **l = NULL;

        /* Set values will be returned as strv in *settings on success. */

        r = load_env_file(NULL, "/etc/locale.conf", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 0; p < _VARIABLE_LC_MAX; p++) {
                _cleanup_free_ char *t = NULL;
                char **u;
                const char *name;

                name = locale_variable_to_string(p);
                assert(name);

                if (isempty(c->locale[p])) {
                        l = strv_env_unset(l, name);
                        continue;
                }

                if (asprintf(&t, "%s=%s", name, c->locale[p]) < 0)
                        return -ENOMEM;

                u = strv_env_set(l, t);
                if (!u)
                        return -ENOMEM;

                strv_free(l);
                l = u;
        }

        if (strv_isempty(l)) {
                if (unlink("/etc/locale.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file_label("/etc/locale.conf", l);
        if (r < 0)
                return r;

        *settings = l;
        l = NULL;
        return 0;
}

int vconsole_write_data(Context *c) {
        int r;
        _cleanup_strv_free_ char **l = NULL;

        r = load_env_file(NULL, "/etc/vconsole.conf", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        if (isempty(c->vc_keymap))
                l = strv_env_unset(l, "KEYMAP");
        else {
                _cleanup_free_ char *s = NULL;
                char **u;

                s = strappend("KEYMAP=", c->vc_keymap);
                if (!s)
                        return -ENOMEM;

                u = strv_env_set(l, s);
                if (!u)
                        return -ENOMEM;

                strv_free(l);
                l = u;
        }

        if (isempty(c->vc_keymap_toggle))
                l = strv_env_unset(l, "KEYMAP_TOGGLE");
        else  {
                _cleanup_free_ char *s = NULL;
                char **u;

                s = strappend("KEYMAP_TOGGLE=", c->vc_keymap_toggle);
                if (!s)
                        return -ENOMEM;

                u = strv_env_set(l, s);
                if (!u)
                        return -ENOMEM;

                strv_free(l);
                l = u;
        }

        if (strv_isempty(l)) {
                if (unlink("/etc/vconsole.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        return write_env_file_label("/etc/vconsole.conf", l);
}

int x11_write_data(Context *c) {
        _cleanup_fclose_ FILE *f = NULL;
        _cleanup_free_ char *temp_path = NULL;
        int r;

        if (isempty(c->x11_layout) &&
            isempty(c->x11_model) &&
            isempty(c->x11_variant) &&
            isempty(c->x11_options)) {

                if (unlink("/etc/X11/xorg.conf.d/00-keyboard.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        mkdir_p_label("/etc/X11/xorg.conf.d", 0755);

        r = fopen_temporary("/etc/X11/xorg.conf.d/00-keyboard.conf", &f, &temp_path);
        if (r < 0)
                return r;

        fchmod(fileno(f), 0644);

        fputs("# Read and parsed by systemd-localed. It's probably wise not to edit this file\n"
              "# manually too freely.\n"
              "Section \"InputClass\"\n"
              "        Identifier \"system-keyboard\"\n"
              "        MatchIsKeyboard \"on\"\n", f);

        if (!isempty(c->x11_layout))
                fprintf(f, "        Option \"XkbLayout\" \"%s\"\n", c->x11_layout);

        if (!isempty(c->x11_model))
                fprintf(f, "        Option \"XkbModel\" \"%s\"\n", c->x11_model);

        if (!isempty(c->x11_variant))
                fprintf(f, "        Option \"XkbVariant\" \"%s\"\n", c->x11_variant);

        if (!isempty(c->x11_options))
                fprintf(f, "        Option \"XkbOptions\" \"%s\"\n", c->x11_options);

        fputs("EndSection\n", f);

        r = fflush_and_check(f);
        if (r < 0)
                goto fail;

        if (rename(temp_path, "/etc/X11/xorg.conf.d/00-keyboard.conf") < 0) {
                r = -errno;
                goto fail;
        }

        return 0;

fail:
        (void) unlink("/etc/X11/xorg.conf.d/00-keyboard.conf");

        if (temp_path)
                (void) unlink(temp_path);

        return r;
}

static int read_next_mapping(const char* filename,
                             unsigned min_fields, unsigned max_fields,
                             FILE *f, unsigned *n, char ***a) {
        assert(f);
        assert(n);
        assert(a);

        for (;;) {
                char line[LINE_MAX];
                char *l, **b;
                int r;
                size_t length;

                errno = 0;
                if (!fgets(line, sizeof(line), f)) {

                        if (ferror(f))
                                return errno > 0 ? -errno : -EIO;

                        return 0;
                }

                (*n)++;

                l = strstrip(line);
                if (l[0] == 0 || l[0] == '#')
                        continue;

                r = strv_split_extract(&b, l, WHITESPACE, EXTRACT_QUOTES);
                if (r < 0)
                        return r;

                length = strv_length(b);
                if (length < min_fields || length > max_fields) {
                        log_error("Invalid line %s:%u, ignoring.", filename, *n);
                        strv_free(b);
                        continue;

                }

                *a = b;
                return 1;
        }
}

int vconsole_convert_to_x11(Context *c) {
        int modified = -1;

        if (isempty(c->vc_keymap)) {
                modified =
                        !isempty(c->x11_layout) ||
                        !isempty(c->x11_model) ||
                        !isempty(c->x11_variant) ||
                        !isempty(c->x11_options);

                context_free_x11(c);
        } else {
                _cleanup_fclose_ FILE *f = NULL;
                unsigned n = 0;

                f = fopen(SYSTEMD_KBD_MODEL_MAP, "re");
                if (!f)
                        return -errno;

                for (;;) {
                        _cleanup_strv_free_ char **a = NULL;
                        int r;

                        r = read_next_mapping(SYSTEMD_KBD_MODEL_MAP, 5, UINT_MAX, f, &n, &a);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                break;

                        if (!streq(c->vc_keymap, a[0]))
                                continue;

                        if (!streq_ptr(c->x11_layout, strnulldash(a[1])) ||
                            !streq_ptr(c->x11_model, strnulldash(a[2])) ||
                            !streq_ptr(c->x11_variant, strnulldash(a[3])) ||
                            !streq_ptr(c->x11_options, strnulldash(a[4]))) {

                                if (free_and_strdup(&c->x11_layout, strnulldash(a[1])) < 0 ||
                                    free_and_strdup(&c->x11_model, strnulldash(a[2])) < 0 ||
                                    free_and_strdup(&c->x11_variant, strnulldash(a[3])) < 0 ||
                                    free_and_strdup(&c->x11_options, strnulldash(a[4])) < 0)
                                        return -ENOMEM;

                                modified = true;
                        }

                        break;
                }
        }

        if (modified > 0)
                log_info("Changing X11 keyboard layout to '%s' model '%s' variant '%s' options '%s'",
                         strempty(c->x11_layout),
                         strempty(c->x11_model),
                         strempty(c->x11_variant),
                         strempty(c->x11_options));
        else if (modified < 0)
                log_notice("X11 keyboard layout was not modified: no conversion found for \"%s\".",
                           c->vc_keymap);
        else
                log_debug("X11 keyboard layout did not need to be modified.");

        return modified > 0;
}

int find_converted_keymap(const char *x11_layout, const char *x11_variant, char **new_keymap) {
        const char *dir;
        _cleanup_free_ char *n;

        if (x11_variant)
                n = strjoin(x11_layout, "-", x11_variant, NULL);
        else
                n = strdup(x11_layout);
        if (!n)
                return -ENOMEM;

        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                _cleanup_free_ char *p = NULL, *pz = NULL;
                bool uncompressed;

                p = strjoin(dir, "xkb/", n, ".map", NULL);
                pz = strjoin(dir, "xkb/", n, ".map.gz", NULL);
                if (!p || !pz)
                        return -ENOMEM;

                uncompressed = access(p, F_OK) == 0;
                if (uncompressed || access(pz, F_OK) == 0) {
                        log_debug("Found converted keymap %s at %s",
                                  n, uncompressed ? p : pz);

                        *new_keymap = n;
                        n = NULL;
                        return 1;
                }
        }

        return 0;
}

int find_legacy_keymap(Context *c, char **new_keymap) {
        _cleanup_fclose_ FILE *f;
        unsigned n = 0;
        unsigned best_matching = 0;
        int r;

        f = fopen(SYSTEMD_KBD_MODEL_MAP, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_strv_free_ char **a = NULL;
                unsigned matching = 0;

                r = read_next_mapping(SYSTEMD_KBD_MODEL_MAP, 5, UINT_MAX, f, &n, &a);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Determine how well matching this entry is */
                if (streq_ptr(c->x11_layout, a[1]))
                        /* If we got an exact match, this is best */
                        matching = 10;
                else {
                        /* We have multiple X layouts, look for an
                         * entry that matches our key with everything
                         * but the first layout stripped off. */
                        if (startswith_comma(c->x11_layout, a[1]))
                                matching = 5;
                        else  {
                                char *x;

                                /* If that didn't work, strip off the
                                 * other layouts from the entry, too */
                                x = strndupa(a[1], strcspn(a[1], ","));
                                if (startswith_comma(c->x11_layout, x))
                                        matching = 1;
                        }
                }

                if (matching > 0) {
                        if (isempty(c->x11_model) || streq_ptr(c->x11_model, a[2])) {
                                matching++;

                                if (streq_ptr(c->x11_variant, a[3])) {
                                        matching++;

                                        if (streq_ptr(c->x11_options, a[4]))
                                                matching++;
                                }
                        }
                }

                /* The best matching entry so far, then let's save that */
                if (matching >= MAX(best_matching, 1u)) {
                        log_debug("Found legacy keymap %s with score %u",
                                  a[0], matching);

                        if (matching > best_matching) {
                                best_matching = matching;

                                r = free_and_strdup(new_keymap, a[0]);
                                if (r < 0)
                                        return r;
                        }
                }
        }

        if (best_matching < 10 && c->x11_layout) {
                /* The best match is only the first part of the X11
                 * keymap. Check if we have a converted map which
                 * matches just the first layout.
                 */
                char *l, *v = NULL, *converted;

                l = strndupa(c->x11_layout, strcspn(c->x11_layout, ","));
                if (c->x11_variant)
                        v = strndupa(c->x11_variant, strcspn(c->x11_variant, ","));
                r = find_converted_keymap(l, v, &converted);
                if (r < 0)
                        return r;
                if (r > 0) {
                        free(*new_keymap);
                        *new_keymap = converted;
                }
        }

        return 0;
}

int find_language_fallback(const char *lang, char **language) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned n = 0;

        assert(lang);
        assert(language);

        f = fopen(SYSTEMD_LANGUAGE_FALLBACK_MAP, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_strv_free_ char **a = NULL;
                int r;

                r = read_next_mapping(SYSTEMD_LANGUAGE_FALLBACK_MAP, 2, 2, f, &n, &a);
                if (r <= 0)
                        return r;

                if (streq(lang, a[0])) {
                        assert(strv_length(a) == 2);
                        *language = a[1];
                        a[1] = NULL;
                        return 1;
                }
        }

        assert_not_reached("should not be here");
}

int x11_convert_to_vconsole(Context *c) {
        bool modified = false;

        if (isempty(c->x11_layout)) {

                modified =
                        !isempty(c->vc_keymap) ||
                        !isempty(c->vc_keymap_toggle);

                context_free_vconsole(c);
        } else {
                char *new_keymap = NULL;
                int r;

                r = find_converted_keymap(c->x11_layout, c->x11_variant, &new_keymap);
                if (r < 0)
                        return r;
                else if (r == 0) {
                        r = find_legacy_keymap(c, &new_keymap);
                        if (r < 0)
                                return r;
                }

                if (!streq_ptr(c->vc_keymap, new_keymap)) {
                        free(c->vc_keymap);
                        c->vc_keymap = new_keymap;
                        c->vc_keymap_toggle = mfree(c->vc_keymap_toggle);
                        modified = true;
                } else
                        free(new_keymap);
        }

        if (modified)
                log_info("Changing virtual console keymap to '%s' toggle '%s'",
                         strempty(c->vc_keymap), strempty(c->vc_keymap_toggle));
        else
                log_debug("Virtual console keymap was not modified.");

        return modified;
}
