/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

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

#include "sd-bus.h"

#include "util.h"
#include "mkdir.h"
#include "strv.h"
#include "def.h"
#include "env-util.h"
#include "fileio.h"
#include "fileio-label.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-message.h"
#include "event-util.h"
#include "locale-util.h"
#include "selinux-util.h"

#ifdef HAVE_XKBCOMMON
#include <xkbcommon/xkbcommon.h>
#endif

enum {
        /* We don't list LC_ALL here on purpose. People should be
         * using LANG instead. */
        LOCALE_LANG,
        LOCALE_LANGUAGE,
        LOCALE_LC_CTYPE,
        LOCALE_LC_NUMERIC,
        LOCALE_LC_TIME,
        LOCALE_LC_COLLATE,
        LOCALE_LC_MONETARY,
        LOCALE_LC_MESSAGES,
        LOCALE_LC_PAPER,
        LOCALE_LC_NAME,
        LOCALE_LC_ADDRESS,
        LOCALE_LC_TELEPHONE,
        LOCALE_LC_MEASUREMENT,
        LOCALE_LC_IDENTIFICATION,
        _LOCALE_MAX
};

static const char * const names[_LOCALE_MAX] = {
        [LOCALE_LANG] = "LANG",
        [LOCALE_LANGUAGE] = "LANGUAGE",
        [LOCALE_LC_CTYPE] = "LC_CTYPE",
        [LOCALE_LC_NUMERIC] = "LC_NUMERIC",
        [LOCALE_LC_TIME] = "LC_TIME",
        [LOCALE_LC_COLLATE] = "LC_COLLATE",
        [LOCALE_LC_MONETARY] = "LC_MONETARY",
        [LOCALE_LC_MESSAGES] = "LC_MESSAGES",
        [LOCALE_LC_PAPER] = "LC_PAPER",
        [LOCALE_LC_NAME] = "LC_NAME",
        [LOCALE_LC_ADDRESS] = "LC_ADDRESS",
        [LOCALE_LC_TELEPHONE] = "LC_TELEPHONE",
        [LOCALE_LC_MEASUREMENT] = "LC_MEASUREMENT",
        [LOCALE_LC_IDENTIFICATION] = "LC_IDENTIFICATION"
};

typedef struct Context {
        char *locale[_LOCALE_MAX];

        char *x11_layout;
        char *x11_model;
        char *x11_variant;
        char *x11_options;

        char *vc_keymap;
        char *vc_keymap_toggle;

        Hashmap *polkit_registry;
} Context;

static const char* nonempty(const char *s) {
        return isempty(s) ? NULL : s;
}

static void free_and_replace(char **s, char *v) {
        free(*s);
        *s = v;
}

static bool startswith_comma(const char *s, const char *prefix) {
        const char *t;

        return s && (t = startswith(s, prefix)) && (*t == ',');
}

static void context_free_x11(Context *c) {
        free_and_replace(&c->x11_layout, NULL);
        free_and_replace(&c->x11_model, NULL);
        free_and_replace(&c->x11_variant, NULL);
        free_and_replace(&c->x11_options, NULL);
}

static void context_free_vconsole(Context *c) {
        free_and_replace(&c->vc_keymap, NULL);
        free_and_replace(&c->vc_keymap_toggle, NULL);
}

static void context_free_locale(Context *c) {
        int p;

        for (p = 0; p < _LOCALE_MAX; p++)
                free_and_replace(&c->locale[p], NULL);
}

static void context_free(Context *c) {
        context_free_locale(c);
        context_free_x11(c);
        context_free_vconsole(c);

        bus_verify_polkit_async_registry_free(c->polkit_registry);
};

static void locale_simplify(Context *c) {
        int p;

        for (p = LOCALE_LANG+1; p < _LOCALE_MAX; p++)
                if (isempty(c->locale[p]) || streq_ptr(c->locale[LOCALE_LANG], c->locale[p]))
                        free_and_replace(&c->locale[p], NULL);
}

static int locale_read_data(Context *c) {
        int r;

        context_free_locale(c);

        r = parse_env_file("/etc/locale.conf", NEWLINE,
                           "LANG",              &c->locale[LOCALE_LANG],
                           "LANGUAGE",          &c->locale[LOCALE_LANGUAGE],
                           "LC_CTYPE",          &c->locale[LOCALE_LC_CTYPE],
                           "LC_NUMERIC",        &c->locale[LOCALE_LC_NUMERIC],
                           "LC_TIME",           &c->locale[LOCALE_LC_TIME],
                           "LC_COLLATE",        &c->locale[LOCALE_LC_COLLATE],
                           "LC_MONETARY",       &c->locale[LOCALE_LC_MONETARY],
                           "LC_MESSAGES",       &c->locale[LOCALE_LC_MESSAGES],
                           "LC_PAPER",          &c->locale[LOCALE_LC_PAPER],
                           "LC_NAME",           &c->locale[LOCALE_LC_NAME],
                           "LC_ADDRESS",        &c->locale[LOCALE_LC_ADDRESS],
                           "LC_TELEPHONE",      &c->locale[LOCALE_LC_TELEPHONE],
                           "LC_MEASUREMENT",    &c->locale[LOCALE_LC_MEASUREMENT],
                           "LC_IDENTIFICATION", &c->locale[LOCALE_LC_IDENTIFICATION],
                           NULL);

        if (r == -ENOENT) {
                int p;

                /* Fill in what we got passed from systemd. */
                for (p = 0; p < _LOCALE_MAX; p++) {
                        assert(names[p]);

                        r = free_and_strdup(&c->locale[p],
                                            nonempty(getenv(names[p])));
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

                        r = strv_split_quoted(&a, l, 0);
                        if (r < 0)
                                return r;

                        if (strv_length(a) == 3) {
                                if (streq(a[1], "XkbLayout")) {
                                        free_and_replace(&c->x11_layout, a[2]);
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbModel")) {
                                        free_and_replace(&c->x11_model, a[2]);
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbVariant")) {
                                        free_and_replace(&c->x11_variant, a[2]);
                                        a[2] = NULL;
                                } else if (streq(a[1], "XkbOptions")) {
                                        free_and_replace(&c->x11_options, a[2]);
                                        a[2] = NULL;
                                }
                        }

                } else if (!in_section && first_word(l, "Section")) {
                        _cleanup_strv_free_ char **a = NULL;

                        r = strv_split_quoted(&a, l, 0);
                        if (r < 0)
                                return -ENOMEM;

                        if (strv_length(a) == 2 && streq(a[1], "InputClass"))
                                in_section = true;

                } else if (in_section && first_word(l, "EndSection"))
                        in_section = false;
        }

        return 0;
}

static int context_read_data(Context *c) {
        int r, q, p;

        r = locale_read_data(c);
        q = vconsole_read_data(c);
        p = x11_read_data(c);

        return r < 0 ? r : q < 0 ? q : p;
}

static int locale_write_data(Context *c, char ***settings) {
        int r, p;
        _cleanup_strv_free_ char **l = NULL;

        /* Set values will be returned as strv in *settings on success. */

        r = load_env_file(NULL, "/etc/locale.conf", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 0; p < _LOCALE_MAX; p++) {
                _cleanup_free_ char *t = NULL;
                char **u;

                assert(names[p]);

                if (isempty(c->locale[p])) {
                        l = strv_env_unset(l, names[p]);
                        continue;
                }

                if (asprintf(&t, "%s=%s", names[p], c->locale[p]) < 0)
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

static int locale_update_system_manager(Context *c, sd_bus *bus) {
        _cleanup_free_ char **l_unset = NULL;
        _cleanup_strv_free_ char **l_set = NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned c_set, c_unset, p;
        int r;

        assert(bus);

        l_unset = new0(char*, _LOCALE_MAX);
        if (!l_unset)
                return -ENOMEM;

        l_set = new0(char*, _LOCALE_MAX);
        if (!l_set)
                return -ENOMEM;

        for (p = 0, c_set = 0, c_unset = 0; p < _LOCALE_MAX; p++) {
                assert(names[p]);

                if (isempty(c->locale[p]))
                        l_unset[c_set++] = (char*) names[p];
                else {
                        char *s;

                        if (asprintf(&s, "%s=%s", names[p], c->locale[p]) < 0)
                                return -ENOMEM;

                        l_set[c_unset++] = s;
                }
        }

        assert(c_set + c_unset == _LOCALE_MAX);
        r = sd_bus_message_new_method_call(bus, &m,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "UnsetAndSetEnvironment");
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(m, l_unset);
        if (r < 0)
                return r;

        r = sd_bus_message_append_strv(m, l_set);
        if (r < 0)
                return r;

        r = sd_bus_call(bus, m, 0, &error, NULL);
        if (r < 0)
                log_error_errno(r, "Failed to update the manager environment: %m");

        return 0;
}

static int vconsole_write_data(Context *c) {
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

static int x11_write_data(Context *c) {
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
        fflush(f);

        if (ferror(f) || rename(temp_path, "/etc/X11/xorg.conf.d/00-keyboard.conf") < 0) {
                r = -errno;
                unlink("/etc/X11/xorg.conf.d/00-keyboard.conf");
                unlink(temp_path);
                return r;
        } else
                return 0;
}

static int vconsole_reload(sd_bus *bus) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        assert(bus);

        r = sd_bus_call_method(bus,
                        "org.freedesktop.systemd1",
                        "/org/freedesktop/systemd1",
                        "org.freedesktop.systemd1.Manager",
                        "RestartUnit",
                        &error,
                        NULL,
                        "ss", "systemd-vconsole-setup.service", "replace");

        if (r < 0)
                log_error("Failed to issue method call: %s", bus_error_message(&error, -r));
        return r;
}

static const char* strnulldash(const char *s) {
        return isempty(s) || streq(s, "-") ? NULL : s;
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
                                return errno ? -errno : -EIO;

                        return 0;
                }

                (*n) ++;

                l = strstrip(line);
                if (l[0] == 0 || l[0] == '#')
                        continue;

                r = strv_split_quoted(&b, l, 0);
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

static int vconsole_convert_to_x11(Context *c, sd_bus *bus) {
        bool modified = false;

        assert(bus);

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

        if (modified) {
                int r;

                r = x11_write_data(c);
                if (r < 0)
                        return log_error_errno(r, "Failed to set X11 keyboard layout: %m");

                log_info("Changed X11 keyboard layout to '%s' model '%s' variant '%s' options '%s'",
                         strempty(c->x11_layout),
                         strempty(c->x11_model),
                         strempty(c->x11_variant),
                         strempty(c->x11_options));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "X11Layout", "X11Model", "X11Variant", "X11Options", NULL);
        } else
                log_debug("X11 keyboard layout was not modified.");

        return 0;
}

static int find_converted_keymap(const char *x11_layout, const char *x11_variant, char **new_keymap) {
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

static int find_legacy_keymap(Context *c, char **new_keymap) {
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
                if (r > 0)
                        free_and_replace(new_keymap, converted);
        }

        return 0;
}

static int find_language_fallback(const char *lang, char **language) {
        _cleanup_fclose_ FILE *f = NULL;
        unsigned n = 0;

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

static int x11_convert_to_vconsole(Context *c, sd_bus *bus) {
        bool modified = false;
        int r;

        assert(bus);

        if (isempty(c->x11_layout)) {

                modified =
                        !isempty(c->vc_keymap) ||
                        !isempty(c->vc_keymap_toggle);

                context_free_x11(c);
        } else {
                char *new_keymap = NULL;

                r = find_converted_keymap(c->x11_layout, c->x11_variant, &new_keymap);
                if (r < 0)
                        return r;
                else if (r == 0) {
                        r = find_legacy_keymap(c, &new_keymap);
                        if (r < 0)
                                return r;
                }

                if (!streq_ptr(c->vc_keymap, new_keymap)) {
                        free_and_replace(&c->vc_keymap, new_keymap);
                        free_and_replace(&c->vc_keymap_toggle, NULL);
                        modified = true;
                } else
                        free(new_keymap);
        }

        if (modified) {
                r = vconsole_write_data(c);
                if (r < 0)
                        log_error_errno(r, "Failed to set virtual console keymap: %m");

                log_info("Changed virtual console keymap to '%s' toggle '%s'",
                         strempty(c->vc_keymap), strempty(c->vc_keymap_toggle));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

                return vconsole_reload(bus);
        } else
                log_debug("Virtual console keymap was not modified.");

        return 0;
}

static int property_get_locale(
                sd_bus *bus,
                const char *path,
                const char *interface,
                const char *property,
                sd_bus_message *reply,
                void *userdata,
                sd_bus_error *error) {

        Context *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        int p, q;

        l = new0(char*, _LOCALE_MAX+1);
        if (!l)
                return -ENOMEM;

        for (p = 0, q = 0; p < _LOCALE_MAX; p++) {
                char *t;

                if (isempty(c->locale[p]))
                        continue;

                if (asprintf(&t, "%s=%s", names[p], c->locale[p]) < 0)
                        return -ENOMEM;

                l[q++] = t;
        }

        return sd_bus_message_append_strv(reply, l);
}

static int method_set_locale(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        char **i;
        const char *lang = NULL;
        int interactive;
        bool modified = false;
        bool have[_LOCALE_MAX] = {};
        int p;
        int r;

        assert(m);
        assert(c);

        r = bus_message_read_strv_extend(m, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(m, 'b', &interactive);
        if (r < 0)
                return r;

        /* Check whether a variable changed and if it is valid */
        STRV_FOREACH(i, l) {
                bool valid = false;

                for (p = 0; p < _LOCALE_MAX; p++) {
                        size_t k;

                        k = strlen(names[p]);
                        if (startswith(*i, names[p]) &&
                            (*i)[k] == '=' &&
                            locale_is_valid((*i) + k + 1)) {
                                valid = true;
                                have[p] = true;

                                if (p == LOCALE_LANG)
                                        lang = (*i) + k + 1;

                                if (!streq_ptr(*i + k + 1, c->locale[p]))
                                        modified = true;

                                break;
                        }
                }

                if (!valid)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid Locale data.");
        }

        /* If LANG was specified, but not LANGUAGE, check if we should
         * set it based on the language fallback table. */
        if (have[LOCALE_LANG] && !have[LOCALE_LANGUAGE]) {
                _cleanup_free_ char *language = NULL;

                assert(lang);

                (void) find_language_fallback(lang, &language);
                if (language) {
                        log_debug("Converted LANG=%s to LANGUAGE=%s", lang, language);
                        if (!streq_ptr(language, c->locale[LOCALE_LANGUAGE])) {
                                r = strv_extendf(&l, "LANGUAGE=%s", language);
                                if (r < 0)
                                        return r;

                                have[LOCALE_LANGUAGE] = true;
                                modified = true;
                        }
                }
        }

        /* Check whether a variable is unset */
        if (!modified)
                for (p = 0; p < _LOCALE_MAX; p++)
                        if (!isempty(c->locale[p]) && !have[p]) {
                                modified = true;
                                break;
                        }

        if (modified) {
                _cleanup_strv_free_ char **settings = NULL;

                r = bus_verify_polkit_async(
                                m,
                                CAP_SYS_ADMIN,
                                "org.freedesktop.locale1.set-locale",
                                interactive,
                                UID_INVALID,
                                &c->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                STRV_FOREACH(i, l)
                        for (p = 0; p < _LOCALE_MAX; p++) {
                                size_t k;

                                k = strlen(names[p]);
                                if (startswith(*i, names[p]) && (*i)[k] == '=') {
                                        r = free_and_strdup(&c->locale[p], *i + k + 1);
                                        if (r < 0)
                                                return r;
                                        break;
                                }
                        }

                for (p = 0; p < _LOCALE_MAX; p++) {
                        if (have[p])
                                continue;

                        free_and_replace(&c->locale[p], NULL);
                }

                locale_simplify(c);

                r = locale_write_data(c, &settings);
                if (r < 0) {
                        log_error_errno(r, "Failed to set locale: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to set locale: %s", strerror(-r));
                }

                locale_update_system_manager(c, sd_bus_message_get_bus(m));

                if (settings) {
                        _cleanup_free_ char *line;

                        line = strv_join(settings, ", ");
                        log_info("Changed locale to %s.", strnull(line));
                } else
                        log_info("Changed locale to unset.");

                (void) sd_bus_emit_properties_changed(
                                sd_bus_message_get_bus(m),
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "Locale", NULL);
        } else
                log_debug("Locale settings were not modified.");


        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_vc_keyboard(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *keymap, *keymap_toggle;
        int convert, interactive;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "ssbb", &keymap, &keymap_toggle, &convert, &interactive);
        if (r < 0)
                return r;

        if (isempty(keymap))
                keymap = NULL;

        if (isempty(keymap_toggle))
                keymap_toggle = NULL;

        if (!streq_ptr(keymap, c->vc_keymap) ||
            !streq_ptr(keymap_toggle, c->vc_keymap_toggle)) {

                if ((keymap && (!filename_is_valid(keymap) || !string_is_safe(keymap))) ||
                    (keymap_toggle && (!filename_is_valid(keymap_toggle) || !string_is_safe(keymap_toggle))))
                        return sd_bus_error_set_errnof(error, -EINVAL, "Received invalid keymap data");

                r = bus_verify_polkit_async(
                                m,
                                CAP_SYS_ADMIN,
                                "org.freedesktop.locale1.set-keyboard",
                                interactive,
                                UID_INVALID,
                                &c->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                if (free_and_strdup(&c->vc_keymap, keymap) < 0 ||
                    free_and_strdup(&c->vc_keymap_toggle, keymap_toggle) < 0)
                        return -ENOMEM;

                r = vconsole_write_data(c);
                if (r < 0) {
                        log_error_errno(r, "Failed to set virtual console keymap: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to set virtual console keymap: %s", strerror(-r));
                }

                log_info("Changed virtual console keymap to '%s' toggle '%s'",
                         strempty(c->vc_keymap), strempty(c->vc_keymap_toggle));

                r = vconsole_reload(sd_bus_message_get_bus(m));
                if (r < 0)
                        log_error_errno(r, "Failed to request keymap reload: %m");

                (void) sd_bus_emit_properties_changed(
                                sd_bus_message_get_bus(m),
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

                if (convert) {
                        r = vconsole_convert_to_x11(c, sd_bus_message_get_bus(m));
                        if (r < 0)
                                log_error_errno(r, "Failed to convert keymap data: %m");
                }
        }

        return sd_bus_reply_method_return(m, NULL);
}

#ifdef HAVE_XKBCOMMON
static void log_xkb(struct xkb_context *ctx, enum xkb_log_level lvl, const char *format, va_list args) {
        const char *fmt;

        fmt = strjoina("libxkbcommon: ", format);
        log_internalv(LOG_DEBUG, 0, __FILE__, __LINE__, __func__, fmt, args);
}

static int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {
        const struct xkb_rule_names rmlvo = {
                .model          = model,
                .layout         = layout,
                .variant        = variant,
                .options        = options,
        };
        struct xkb_context *ctx = NULL;
        struct xkb_keymap *km = NULL;
        int r;

        /* compile keymap from RMLVO information to check out its validity */

        ctx = xkb_context_new(XKB_CONTEXT_NO_ENVIRONMENT_NAMES);
        if (!ctx) {
                r = -ENOMEM;
                goto exit;
        }

        xkb_context_set_log_fn(ctx, log_xkb);

        km = xkb_keymap_new_from_names(ctx, &rmlvo, XKB_KEYMAP_COMPILE_NO_FLAGS);
        if (!km) {
                r = -EINVAL;
                goto exit;
        }

        r = 0;

exit:
        xkb_keymap_unref(km);
        xkb_context_unref(ctx);
        return r;
}
#else
static int verify_xkb_rmlvo(const char *model, const char *layout, const char *variant, const char *options) {
        return 0;
}
#endif

static int method_set_x11_keyboard(sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *layout, *model, *variant, *options;
        int convert, interactive;
        int r;

        assert(m);
        assert(c);

        r = sd_bus_message_read(m, "ssssbb", &layout, &model, &variant, &options, &convert, &interactive);
        if (r < 0)
                return r;

        if (isempty(layout))
                layout = NULL;

        if (isempty(model))
                model = NULL;

        if (isempty(variant))
                variant = NULL;

        if (isempty(options))
                options = NULL;

        if (!streq_ptr(layout, c->x11_layout) ||
            !streq_ptr(model, c->x11_model) ||
            !streq_ptr(variant, c->x11_variant) ||
            !streq_ptr(options, c->x11_options)) {

                if ((layout && !string_is_safe(layout)) ||
                    (model && !string_is_safe(model)) ||
                    (variant && !string_is_safe(variant)) ||
                    (options && !string_is_safe(options)))
                        return sd_bus_error_set_errnof(error, -EINVAL, "Received invalid keyboard data");

                r = bus_verify_polkit_async(
                                m,
                                CAP_SYS_ADMIN,
                                "org.freedesktop.locale1.set-keyboard",
                                interactive,
                                UID_INVALID,
                                &c->polkit_registry,
                                error);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                r = verify_xkb_rmlvo(model, layout, variant, options);
                if (r < 0) {
                        log_error_errno(r, "Cannot compile XKB keymap for new x11 keyboard layout ('%s' / '%s' / '%s' / '%s'): %m",
                                        strempty(model), strempty(layout), strempty(variant), strempty(options));
                        return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "Cannot compile XKB keymap, refusing");
                }

                if (free_and_strdup(&c->x11_layout, layout) < 0 ||
                    free_and_strdup(&c->x11_model, model) < 0 ||
                    free_and_strdup(&c->x11_variant, variant) < 0 ||
                    free_and_strdup(&c->x11_options, options) < 0)
                        return -ENOMEM;

                r = x11_write_data(c);
                if (r < 0) {
                        log_error_errno(r, "Failed to set X11 keyboard layout: %m");
                        return sd_bus_error_set_errnof(error, r, "Failed to set X11 keyboard layout: %s", strerror(-r));
                }

                log_info("Changed X11 keyboard layout to '%s' model '%s' variant '%s' options '%s'",
                         strempty(c->x11_layout),
                         strempty(c->x11_model),
                         strempty(c->x11_variant),
                         strempty(c->x11_options));

                (void) sd_bus_emit_properties_changed(
                                sd_bus_message_get_bus(m),
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "X11Layout", "X11Model", "X11Variant", "X11Options", NULL);

                if (convert) {
                        r = x11_convert_to_vconsole(c, sd_bus_message_get_bus(m));
                        if (r < 0)
                                log_error_errno(r, "Failed to convert keymap data: %m");
                }
        }

        return sd_bus_reply_method_return(m, NULL);
}

static const sd_bus_vtable locale_vtable[] = {
        SD_BUS_VTABLE_START(0),
        SD_BUS_PROPERTY("Locale", "as", property_get_locale, 0, SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Layout", "s", NULL, offsetof(Context, x11_layout), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Model", "s", NULL, offsetof(Context, x11_model), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Variant", "s", NULL, offsetof(Context, x11_variant), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("X11Options", "s", NULL, offsetof(Context, x11_options), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("VConsoleKeymap", "s", NULL, offsetof(Context, vc_keymap), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_PROPERTY("VConsoleKeymapToggle", "s", NULL, offsetof(Context, vc_keymap_toggle), SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE),
        SD_BUS_METHOD("SetLocale", "asb", NULL, method_set_locale, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetVConsoleKeyboard", "ssbb", NULL, method_set_vc_keyboard, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_METHOD("SetX11Keyboard", "ssssbb", NULL, method_set_x11_keyboard, SD_BUS_VTABLE_UNPRIVILEGED),
        SD_BUS_VTABLE_END
};

static int connect_bus(Context *c, sd_event *event, sd_bus **_bus) {
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to get system bus connection: %m");

        r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/locale1", "org.freedesktop.locale1", locale_vtable, c);
        if (r < 0)
                return log_error_errno(r, "Failed to register object: %m");

        r = sd_bus_request_name(bus, "org.freedesktop.locale1", 0);
        if (r < 0)
                return log_error_errno(r, "Failed to register name: %m");

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus to event loop: %m");

        *_bus = bus;
        bus = NULL;

        return 0;
}

int main(int argc, char *argv[]) {
        _cleanup_(context_free) Context context = {};
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_bus_flush_close_unref_ sd_bus *bus = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);
        mac_selinux_init("/etc");

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = sd_event_default(&event);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate event loop: %m");
                goto finish;
        }

        sd_event_set_watchdog(event, true);

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                goto finish;

        r = context_read_data(&context);
        if (r < 0) {
                log_error_errno(r, "Failed to read locale data: %m");
                goto finish;
        }

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.locale1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0) {
                log_error_errno(r, "Failed to run event loop: %m");
                goto finish;
        }

finish:
        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
