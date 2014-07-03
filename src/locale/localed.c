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
#include "label.h"
#include "bus-util.h"
#include "bus-error.h"
#include "bus-message.h"
#include "event-util.h"

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

static int free_and_copy(char **s, const char *v) {
        int r;
        char *t;

        assert(s);

        r = strdup_or_null(isempty(v) ? NULL : v, &t);
        if (r < 0)
                return r;

        free(*s);
        *s = t;

        return 0;
}

static void free_and_replace(char **s, char *v) {
        free(*s);
        *s = v;
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

static void context_free(Context *c, sd_bus *bus) {
        context_free_locale(c);
        context_free_x11(c);
        context_free_vconsole(c);

        bus_verify_polkit_async_registry_free(bus, c->polkit_registry);
};

static void locale_simplify(Context *c) {
        int p;

        for (p = LOCALE_LANG+1; p < _LOCALE_MAX; p++)
                if (isempty(c->locale[p]) || streq_ptr(c->locale[LOCALE_LANG], c->locale[p])) {
                        free(c->locale[p]);
                        c->locale[p] = NULL;
                }
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

                        r = free_and_copy(&c->locale[p], getenv(names[p]));
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
        FILE *f;
        char line[LINE_MAX];
        bool in_section = false;

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
                        char **a;

                        a = strv_split_quoted(l);
                        if (!a) {
                                fclose(f);
                                return -ENOMEM;
                        }

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

                        strv_free(a);

                } else if (!in_section && first_word(l, "Section")) {
                        char **a;

                        a = strv_split_quoted(l);
                        if (!a) {
                                fclose(f);
                                return -ENOMEM;
                        }

                        if (strv_length(a) == 2 && streq(a[1], "InputClass"))
                                in_section = true;

                        strv_free(a);
                } else if (in_section && first_word(l, "EndSection"))
                        in_section = false;
        }

        fclose(f);

        return 0;
}

static int context_read_data(Context *c) {
        int r, q, p;

        r = locale_read_data(c);
        q = vconsole_read_data(c);
        p = x11_read_data(c);

        return r < 0 ? r : q < 0 ? q : p;
}

static int locale_write_data(Context *c) {
        int r, p;
        char **l = NULL;

        r = load_env_file(NULL, "/etc/locale.conf", NULL, &l);
        if (r < 0 && r != -ENOENT)
                return r;

        for (p = 0; p < _LOCALE_MAX; p++) {
                char *t, **u;

                assert(names[p]);

                if (isempty(c->locale[p])) {
                        l = strv_env_unset(l, names[p]);
                        continue;
                }

                if (asprintf(&t, "%s=%s", names[p], c->locale[p]) < 0) {
                        strv_free(l);
                        return -ENOMEM;
                }

                u = strv_env_set(l, t);
                free(t);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (strv_isempty(l)) {
                strv_free(l);

                if (unlink("/etc/locale.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file_label("/etc/locale.conf", l);
        strv_free(l);

        return r;
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
                log_error("Failed to update the manager environment: %s", strerror(-r));

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
                char *s, **u;

                s = strappend("KEYMAP=", c->vc_keymap);
                if (!s)
                        return -ENOMEM;

                u = strv_env_set(l, s);
                free(s);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (isempty(c->vc_keymap_toggle))
                l = strv_env_unset(l, "KEYMAP_TOGGLE");
        else  {
                char *s, **u;

                s = strappend("KEYMAP_TOGGLE=", c->vc_keymap_toggle);
                if (!s)
                        return -ENOMEM;

                u = strv_env_set(l, s);
                free(s);
                strv_free(l);

                if (!u)
                        return -ENOMEM;

                l = u;
        }

        if (strv_isempty(l)) {
                if (unlink("/etc/vconsole.conf") < 0)
                        return errno == ENOENT ? 0 : -errno;

                return 0;
        }

        r = write_env_file_label("/etc/vconsole.conf", l);
        return r;
}

static int write_data_x11(Context *c) {
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

static char *strnulldash(const char *s) {
        return s == NULL || *s == 0 || (s[0] == '-' && s[1] == 0) ? NULL : (char*) s;
}

static int read_next_mapping(FILE *f, unsigned *n, char ***a) {
        assert(f);
        assert(n);
        assert(a);

        for (;;) {
                char line[LINE_MAX];
                char *l, **b;

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

                b = strv_split_quoted(l);
                if (!b)
                        return -ENOMEM;

                if (strv_length(b) < 5) {
                        log_error("Invalid line "SYSTEMD_KBD_MODEL_MAP":%u, ignoring.", *n);
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

                        r = read_next_mapping(f, &n, &a);
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

                                if (free_and_copy(&c->x11_layout, strnulldash(a[1])) < 0 ||
                                    free_and_copy(&c->x11_model, strnulldash(a[2])) < 0 ||
                                    free_and_copy(&c->x11_variant, strnulldash(a[3])) < 0 ||
                                    free_and_copy(&c->x11_options, strnulldash(a[4])) < 0)
                                        return -ENOMEM;

                                modified = true;
                        }

                        break;
                }
        }

        if (modified) {
                int r;

                r = write_data_x11(c);
                if (r < 0)
                        log_error("Failed to set X11 keyboard layout: %s", strerror(-r));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "X11Layout", "X11Model", "X11Variant", "X11Options", NULL);
        }

        return 0;
}

static int find_converted_keymap(Context *c, char **new_keymap) {
        const char *dir;
        _cleanup_free_ char *n;

        if (c->x11_variant)
                n = strjoin(c->x11_layout, "-", c->x11_variant, NULL);
        else
                n = strdup(c->x11_layout);
        if (!n)
                return -ENOMEM;

        NULSTR_FOREACH(dir, KBD_KEYMAP_DIRS) {
                _cleanup_free_ char *p = NULL, *pz = NULL;

                p = strjoin(dir, "xkb/", n, ".map", NULL);
                pz = strjoin(dir, "xkb/", n, ".map.gz", NULL);
                if (!p || !pz)
                        return -ENOMEM;

                if (access(p, F_OK) == 0 || access(pz, F_OK) == 0) {
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


        f = fopen(SYSTEMD_KBD_MODEL_MAP, "re");
        if (!f)
                return -errno;

        for (;;) {
                _cleanup_strv_free_ char **a = NULL;
                unsigned matching = 0;
                int r;

                r = read_next_mapping(f, &n, &a);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                /* Determine how well matching this entry is */
                if (streq_ptr(c->x11_layout, a[1]))
                        /* If we got an exact match, this is best */
                        matching = 10;
                else {
                        size_t x;

                        x = strcspn(c->x11_layout, ",");

                        /* We have multiple X layouts, look for an
                         * entry that matches our key with everything
                         * but the first layout stripped off. */
                        if (x > 0 &&
                            strlen(a[1]) == x &&
                            strneq(c->x11_layout, a[1], x))
                                matching = 5;
                        else  {
                                size_t w;

                                /* If that didn't work, strip off the
                                 * other layouts from the entry, too */
                                w = strcspn(a[1], ",");

                                if (x > 0 && x == w &&
                                    memcmp(c->x11_layout, a[1], x) == 0)
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
                if (matching > best_matching) {
                        best_matching = matching;

                        free(*new_keymap);
                        *new_keymap = strdup(a[0]);
                        if (!*new_keymap)
                                return -ENOMEM;
                }
        }

        return 0;
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

                r = find_converted_keymap(c, &new_keymap);
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
                        log_error("Failed to set virtual console keymap: %s", strerror(-r));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

                return vconsole_reload(bus);
        }

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

static int method_set_locale(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        _cleanup_strv_free_ char **l = NULL;
        char **i;
        int interactive;
        bool modified = false;
        bool passed[_LOCALE_MAX] = {};
        int p;
        int r;

        r = bus_message_read_strv_extend(m, &l);
        if (r < 0)
                return r;

        r = sd_bus_message_read_basic(m, 'b', &interactive);
        if (r < 0)
                return r;

        /* Check whether a variable changed and if so valid */
        STRV_FOREACH(i, l) {
                bool valid = false;

                for (p = 0; p < _LOCALE_MAX; p++) {
                        size_t k;

                        k = strlen(names[p]);
                        if (startswith(*i, names[p]) &&
                            (*i)[k] == '=' &&
                            string_is_safe((*i) + k + 1)) {
                                valid = true;
                                passed[p] = true;

                                if (!streq_ptr(*i + k + 1, c->locale[p]))
                                        modified = true;

                                break;
                        }
                }

                if (!valid)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid Locale data.");
        }

        /* Check whether a variable is unset */
        if (!modified)  {
                for (p = 0; p < _LOCALE_MAX; p++)
                        if (!isempty(c->locale[p]) && !passed[p]) {
                                modified = true;
                                break;
                        }
        }

        if (modified) {
                r = bus_verify_polkit_async(bus, &c->polkit_registry, m,
                                            "org.freedesktop.locale1.set-locale", interactive,
                                            error, method_set_locale, c);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                STRV_FOREACH(i, l) {
                        for (p = 0; p < _LOCALE_MAX; p++) {
                                size_t k;

                                k = strlen(names[p]);
                                if (startswith(*i, names[p]) && (*i)[k] == '=') {
                                        char *t;

                                        t = strdup(*i + k + 1);
                                        if (!t)
                                                return -ENOMEM;

                                        free(c->locale[p]);
                                        c->locale[p] = t;
                                        break;
                                }
                        }
                }

                for (p = 0; p < _LOCALE_MAX; p++) {
                        if (passed[p])
                                continue;

                        free_and_replace(&c->locale[p], NULL);
                }

                locale_simplify(c);

                r = locale_write_data(c);
                if (r < 0) {
                        log_error("Failed to set locale: %s", strerror(-r));
                        return sd_bus_error_set_errnof(error, r, "Failed to set locale: %s", strerror(-r));
                }

                locale_update_system_manager(c, bus);

                log_info("Changed locale information.");

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "Locale", NULL);
        }

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_vc_keyboard(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *keymap, *keymap_toggle;
        int convert, interactive;
        int r;

        r = sd_bus_message_read(m, "ssbb", &keymap, &keymap_toggle, &convert, &interactive);
        if (r < 0)
                return r;

        if (isempty(keymap))
                keymap = NULL;

        if (isempty(keymap_toggle))
                keymap_toggle = NULL;

        if (!streq_ptr(keymap, c->vc_keymap) ||
            !streq_ptr(keymap_toggle, c->vc_keymap_toggle)) {

                if ((keymap && (!filename_is_safe(keymap) || !string_is_safe(keymap))) ||
                    (keymap_toggle && (!filename_is_safe(keymap_toggle) || !string_is_safe(keymap_toggle))))
                        return sd_bus_error_set_errnof(error, -EINVAL, "Received invalid keymap data");

                r = bus_verify_polkit_async(bus, &c->polkit_registry, m,
                                "org.freedesktop.locale1.set-keyboard",
                                interactive, error, method_set_vc_keyboard, c);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                if (free_and_copy(&c->vc_keymap, keymap) < 0 ||
                    free_and_copy(&c->vc_keymap_toggle, keymap_toggle) < 0)
                        return -ENOMEM;

                r = vconsole_write_data(c);
                if (r < 0) {
                        log_error("Failed to set virtual console keymap: %s", strerror(-r));
                        return sd_bus_error_set_errnof(error, r, "Failed to set virtual console keymap: %s", strerror(-r));
                }

                log_info("Changed virtual console keymap to '%s'", strempty(c->vc_keymap));

                r = vconsole_reload(bus);
                if (r < 0)
                        log_error("Failed to request keymap reload: %s", strerror(-r));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "VConsoleKeymap", "VConsoleKeymapToggle", NULL);

                if (convert) {
                        r = vconsole_convert_to_x11(c, bus);
                        if (r < 0)
                                log_error("Failed to convert keymap data: %s", strerror(-r));
                }
        }

        return sd_bus_reply_method_return(m, NULL);
}

static int method_set_x11_keyboard(sd_bus *bus, sd_bus_message *m, void *userdata, sd_bus_error *error) {
        Context *c = userdata;
        const char *layout, *model, *variant, *options;
        int convert, interactive;
        int r;

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

                r = bus_verify_polkit_async(bus, &c->polkit_registry, m,
                                "org.freedesktop.locale1.set-keyboard",
                                interactive, error, method_set_x11_keyboard, c);
                if (r < 0)
                        return r;
                if (r == 0)
                        return 1; /* No authorization for now, but the async polkit stuff will call us again when it has it */

                if (free_and_copy(&c->x11_layout, layout) < 0 ||
                    free_and_copy(&c->x11_model, model) < 0 ||
                    free_and_copy(&c->x11_variant, variant) < 0 ||
                    free_and_copy(&c->x11_options, options) < 0)
                        return -ENOMEM;

                r = write_data_x11(c);
                if (r < 0) {
                        log_error("Failed to set X11 keyboard layout: %s", strerror(-r));
                        return sd_bus_error_set_errnof(error, r, "Failed to set X11 keyboard layout: %s", strerror(-r));
                }

                log_info("Changed X11 keyboard layout to '%s'", strempty(c->x11_layout));

                sd_bus_emit_properties_changed(bus,
                                "/org/freedesktop/locale1",
                                "org.freedesktop.locale1",
                                "X11Layout" "X11Model" "X11Variant" "X11Options", NULL);

                if (convert) {
                        r = x11_convert_to_vconsole(c, bus);
                        if (r < 0)
                                log_error("Failed to convert keymap data: %s", strerror(-r));
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
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        assert(c);
        assert(event);
        assert(_bus);

        r = sd_bus_default_system(&bus);
        if (r < 0) {
                log_error("Failed to get system bus connection: %s", strerror(-r));
                return r;
        }

        r = sd_bus_add_object_vtable(bus, NULL, "/org/freedesktop/locale1", "org.freedesktop.locale1", locale_vtable, c);
        if (r < 0) {
                log_error("Failed to register object: %s", strerror(-r));
                return r;
        }

        r = sd_bus_request_name(bus, "org.freedesktop.locale1", 0);
        if (r < 0) {
                log_error("Failed to register name: %s", strerror(-r));
                return r;
        }

        r = sd_bus_attach_event(bus, event, 0);
        if (r < 0) {
                log_error("Failed to attach bus to event loop: %s", strerror(-r));
                return r;
        }

        *_bus = bus;
        bus = NULL;

        return 0;
}

int main(int argc, char *argv[]) {
        Context context = {};
        _cleanup_event_unref_ sd_event *event = NULL;
        _cleanup_bus_unref_ sd_bus *bus = NULL;
        int r;

        log_set_target(LOG_TARGET_AUTO);
        log_parse_environment();
        log_open();

        umask(0022);
        label_init("/etc");

        if (argc != 1) {
                log_error("This program takes no arguments.");
                r = -EINVAL;
                goto finish;
        }

        r = sd_event_default(&event);
        if (r < 0) {
                log_error("Failed to allocate event loop: %s", strerror(-r));
                goto finish;
        }

        sd_event_set_watchdog(event, true);

        r = connect_bus(&context, event, &bus);
        if (r < 0)
                goto finish;

        r = context_read_data(&context);
        if (r < 0) {
                log_error("Failed to read locale data: %s", strerror(-r));
                goto finish;
        }

        r = bus_event_loop_with_idle(event, bus, "org.freedesktop.locale1", DEFAULT_EXIT_USEC, NULL, NULL);
        if (r < 0) {
                log_error("Failed to run event loop: %s", strerror(-r));
                goto finish;
        }

finish:
        context_free(&context, bus);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
