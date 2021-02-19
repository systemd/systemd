/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <stdio.h>
#include <unistd.h>

#include "xdg-autostart-service.h"

#include "conf-parser.h"
#include "escape.h"
#include "unit-name.h"
#include "path-util.h"
#include "fd-util.h"
#include "generator.h"
#include "log.h"
#include "specifier.h"
#include "string-util.h"
#include "nulstr-util.h"
#include "strv.h"

XdgAutostartService* xdg_autostart_service_free(XdgAutostartService *s) {
        if (!s)
                return NULL;

        free(s->name);
        free(s->path);
        free(s->description);

        free(s->type);
        free(s->exec_string);
        free(s->working_directory);

        strv_free(s->only_show_in);
        strv_free(s->not_show_in);

        free(s->try_exec);
        free(s->autostart_condition);
        free(s->kde_autostart_condition);

        free(s->gnome_autostart_phase);

        return mfree(s);
}

char *xdg_autostart_service_translate_name(const char *name) {
        _cleanup_free_ char *c = NULL, *escaped = NULL;
        char *res;

        c = strdup(name);
        if (!c)
                return NULL;

        res = endswith(c, ".desktop");
        if (res)
                *res = '\0';

        escaped = unit_name_escape(c);
        if (!escaped)
                return NULL;

        return strjoin("app-", escaped, "@autostart.service");
}

static int xdg_config_parse_bool(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        bool *b = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "true"))
                *b = true;
        else if (streq(rvalue, "false"))
                *b = false;
        else
                return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL), "Invalid value for boolean: %s", rvalue);

        return 0;
}

/* Unescapes the string in-place, returns non-zero status on error. */
static int xdg_unescape_string(
                const char *unit,
                const char *filename,
                int line,
                char *str) {

        char *in;
        char *out;

        assert(str);

        in = out = str;

        for (; *in; in++, out++) {
                if (*in == '\\') {
                        /* Move forward, and ensure it is a valid escape. */
                        in++;

                        switch (*in) {
                                case 's':
                                        *out = ' ';
                                        break;
                                case 'n':
                                        *out = '\n';
                                        break;
                                case 't':
                                        *out = '\t';
                                        break;
                                case 'r':
                                        *out = '\r';
                                        break;
                                case '\\':
                                        *out = '\\';
                                        break;
                                case ';':
                                        /* Technically only permitted for strv. */
                                        *out = ';';
                                        break;
                                default:
                                        return log_syntax(unit, LOG_ERR, filename, line, SYNTHETIC_ERRNO(EINVAL), "Undefined escape sequence \\%c.", *in);
                        }

                        continue;
                }

                *out = *in;
        }
        *out = '\0';

        return 0;
}

/* Note: We do not bother with unescaping the strings, hence the _raw postfix. */
static int xdg_config_parse_string(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        _cleanup_free_ char *res = NULL;
        char **out = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* XDG does not allow duplicate definitions. */
        if (*out) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Key %s was defined multiple times, ignoring.", lvalue);
                return 0;
        }

        res = strdup(rvalue);
        if (!res)
                return log_oom();

        r = xdg_unescape_string(unit, filename, line, res);
        if (r < 0)
                return r;

        *out = TAKE_PTR(res);
        return 0;
}

static int strv_strndup_unescape_and_push(
                const char *unit,
                const char *filename,
                unsigned line,
                char ***sv,
                size_t *n_allocated,
                size_t *n,
                const char *start,
                const char *end) {

        if (end == start)
                return 0;

        _cleanup_free_ char *copy = NULL;
        int r;

        copy = strndup(start, end - start);
        if (!copy)
                return log_oom();

        r = xdg_unescape_string(unit, filename, line, copy);
        if (r < 0)
                return r;

        if (!greedy_realloc((void**) sv, n_allocated, *n + 2, sizeof(char*))) /* One extra for NULL */
                return log_oom();

        (*sv)[*n] = TAKE_PTR(copy);
        (*sv)[*n + 1] = NULL;
        (*n)++;

        return 0;
}

static int xdg_config_parse_strv(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        char ***ret_sv = data;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        /* XDG does not allow duplicate definitions. */
        if (*ret_sv) {
                log_syntax(unit, LOG_WARNING, filename, line, 0, "Key %s was already defined, ignoring.", lvalue);
                return 0;
        }

        size_t n = 0, n_allocated = 0;
        _cleanup_strv_free_ char **sv = NULL;

        if (!GREEDY_REALLOC0(sv, n_allocated, 1))
                return log_oom();

        /* We cannot use strv_split because it does not handle escaping correctly. */
        const char *start = rvalue, *end;

        for (end = start; *end; end++) {
                if (*end == '\\') {
                        /* Move forward, and ensure it is a valid escape. */
                        end++;
                        if (!strchr("sntr\\;", *end)) {
                                log_syntax(unit, LOG_WARNING, filename, line, 0, "Undefined escape sequence \\%c.", *end);
                                return 0;
                        }
                        continue;
                }

                if (*end == ';') {
                        r = strv_strndup_unescape_and_push(unit, filename, line,
                                                           &sv, &n_allocated, &n,
                                                           start, end);
                        if (r < 0)
                                return r;

                        start = end + 1;
                }
        }

        /* Handle the trailing entry after the last separator */
        r = strv_strndup_unescape_and_push(unit, filename, line,
                                           &sv, &n_allocated, &n,
                                           start, end);
        if (r < 0)
                return r;

        *ret_sv = TAKE_PTR(sv);
        return 0;
}

static int xdg_config_item_table_lookup(
                const void *table,
                const char *section,
                const char *lvalue,
                ConfigParserCallback *func,
                int *ltype,
                void **data,
                void *userdata) {

        assert(lvalue);

        /* Ignore any keys with [] as those are translations. */
        if (strchr(lvalue, '[')) {
                *func = NULL;
                *ltype = 0;
                *data = NULL;
                return 1;
        }

        return config_item_table_lookup(table, section, lvalue, func, ltype, data, userdata);
}

XdgAutostartService *xdg_autostart_service_parse_desktop(const char *path) {
        _cleanup_(xdg_autostart_service_freep) XdgAutostartService *service = NULL;
        int r;

        service = new0(XdgAutostartService, 1);
        if (!service)
                return NULL;

        service->path = strdup(path);
        if (!service->path)
                return NULL;

        const ConfigTableItem items[] = {
                { "Desktop Entry", "Name",                      xdg_config_parse_string, 0, &service->description             },
                { "Desktop Entry", "Exec",                      xdg_config_parse_string, 0, &service->exec_string             },
                { "Desktop Entry", "Path",                      xdg_config_parse_string, 0, &service->working_directory       },
                { "Desktop Entry", "TryExec",                   xdg_config_parse_string, 0, &service->try_exec                },
                { "Desktop Entry", "Type",                      xdg_config_parse_string, 0, &service->type                    },
                { "Desktop Entry", "OnlyShowIn",                xdg_config_parse_strv,   0, &service->only_show_in            },
                { "Desktop Entry", "NotShowIn",                 xdg_config_parse_strv,   0, &service->not_show_in             },
                { "Desktop Entry", "Hidden",                    xdg_config_parse_bool,   0, &service->hidden                  },
                { "Desktop Entry", "AutostartCondition",        xdg_config_parse_string, 0, &service->autostart_condition     },
                { "Desktop Entry", "X-KDE-autostart-condition", xdg_config_parse_string, 0, &service->kde_autostart_condition },
                { "Desktop Entry", "X-GNOME-Autostart-Phase",   xdg_config_parse_string, 0, &service->gnome_autostart_phase   },
                { "Desktop Entry", "X-systemd-skip",            xdg_config_parse_bool,   0, &service->systemd_skip            },

                /* Common entries that we do not use currently. */
                { "Desktop Entry", "Categories",                NULL, 0, NULL},
                { "Desktop Entry", "Comment",                   NULL, 0, NULL},
                { "Desktop Entry", "DBusActivatable",           NULL, 0, NULL},
                { "Desktop Entry", "Encoding",                  NULL, 0, NULL},
                { "Desktop Entry", "GenericName",               NULL, 0, NULL},
                { "Desktop Entry", "Icon",                      NULL, 0, NULL},
                { "Desktop Entry", "Keywords",                  NULL, 0, NULL},
                { "Desktop Entry", "MimeType",                  NULL, 0, NULL},
                { "Desktop Entry", "NoDisplay",                 NULL, 0, NULL},
                { "Desktop Entry", "StartupNotify",             NULL, 0, NULL},
                { "Desktop Entry", "StartupWMClass",            NULL, 0, NULL},
                { "Desktop Entry", "Terminal",                  NULL, 0, NULL},
                { "Desktop Entry", "URL",                       NULL, 0, NULL},
                { "Desktop Entry", "Version",                   NULL, 0, NULL},
                {}
        };

        r = config_parse(NULL, service->path, NULL,
                         "Desktop Entry\0",
                         xdg_config_item_table_lookup, items,
                         CONFIG_PARSE_WARN, service,
                         NULL);
        /* If parsing failed, only hide the file so it will still mask others. */
        if (r < 0) {
                log_warning_errno(r, "Failed to parse %s, ignoring it", service->path);
                service->hidden = true;
        }

        return TAKE_PTR(service);
}

int xdg_autostart_format_exec_start(
                const char *exec,
                char **ret_exec_start) {

        _cleanup_strv_free_ char **exec_split = NULL;
        char *res;
        size_t n, i;
        bool first_arg;
        int r;

        /*
         * Unfortunately, there is a mismatch between systemd's idea of $PATH and XDGs. I.e. we need to
         * ensure that we have an absolute path to support cases where $PATH has been modified from the
         * default set.
         *
         * Note that this is only needed for development environments though; so while it is important, this
         * should have no effect in production environments.
         *
         * To be compliant with the XDG specification, we also need to strip certain parameters and
         * such. Doing so properly makes parsing the command line unavoidable.
         *
         * NOTE: Technically, XDG only specifies " as quotes, while this also accepts '.
         */
        r = strv_split_full(&exec_split, exec, NULL, EXTRACT_UNQUOTE | EXTRACT_RELAX);
        if (r < 0)
                return r;

        if (strv_isempty(exec_split))
                return log_warning_errno(SYNTHETIC_ERRNO(EINVAL), "Exec line is empty");

        first_arg = true;
        for (i = n = 0; exec_split[i]; i++) {
                _cleanup_free_ char *c = NULL, *raw = NULL, *p = NULL, *escaped = NULL, *quoted = NULL;

                r = cunescape(exec_split[i], 0, &c);
                if (r < 0)
                        return log_debug_errno(r, "Failed to unescape '%s': %m", exec_split[i]);

                if (first_arg) {
                        _cleanup_free_ char *executable = NULL;

                        /* This is the executable, find it in $PATH */
                        first_arg = false;
                        r = find_executable(c, &executable);
                        if (r < 0)
                                return log_info_errno(r, "Exec binary '%s' does not exist: %m", c);

                        escaped = cescape(executable);
                        if (!escaped)
                                return log_oom();

                        free(exec_split[n]);
                        exec_split[n++] = TAKE_PTR(escaped);
                        continue;
                }

                /*
                 * Remove any standardised XDG fields; we assume they never appear as part of another
                 * argument as that just does not make any sense as they can be empty (GLib will e.g. turn
                 * "%f" into an empty argument).  Other implementations may handle this differently.
                 */
                if (STR_IN_SET(c,
                               "%f", "%F",
                               "%u", "%U",
                               "%d", "%D",
                               "%n", "%N",
                               "%i",          /* Location of icon, could be implemented. */
                               "%c",          /* Translated application name, could be implemented. */
                               "%k",          /* Location of desktop file, could be implemented. */
                               "%v",
                               "%m"
                               ))
                        continue;

                /*
                 * %% -> % and then % -> %% means that we correctly quote any % and also quote any left over
                 * (and invalid) % specifier from the desktop file.
                 */
                raw = strreplace(c, "%%", "%");
                if (!raw)
                        return log_oom();
                p = strreplace(raw, "%", "%%");
                if (!p)
                        return log_oom();
                escaped = cescape(p);
                if (!escaped)
                        return log_oom();

                quoted = strjoin("\"", escaped, "\"");
                if (!quoted)
                        return log_oom();

                free(exec_split[n]);
                exec_split[n++] = TAKE_PTR(quoted);
        }
        for (; exec_split[n]; n++)
                exec_split[n] = mfree(exec_split[n]);

        res = strv_join(exec_split, " ");
        if (!res)
                return log_oom();

        *ret_exec_start = res;
        return 0;
}

static int xdg_autostart_generate_desktop_condition(
                FILE *f,
                const char *test_binary,
                const char *condition) {

        int r;

        /* Generate an ExecCondition for GNOME autostart condition */
        if (!isempty(condition)) {
                _cleanup_free_ char *gnome_autostart_condition_path = NULL, *e_autostart_condition = NULL;

                r = find_executable(test_binary, &gnome_autostart_condition_path);
                if (r < 0) {
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "%s not found: %m", test_binary);
                        fprintf(f, "# ExecCondition using %s skipped due to missing binary.\n", test_binary);
                        return r;
                }

                e_autostart_condition = cescape(condition);
                if (!e_autostart_condition)
                        return log_oom();

                fprintf(f,
                         "ExecCondition=%s --condition \"%s\"\n",
                         gnome_autostart_condition_path,
                         e_autostart_condition);
        }

        return 0;
}

int xdg_autostart_service_generate_unit(
                XdgAutostartService *service,
                const char *dest) {

        _cleanup_free_ char *path_escaped = NULL, *exec_start = NULL, *unit = NULL;
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(service);

        /* Nothing to do for hidden services. */
        if (service->hidden) {
                log_debug("Not generating service for XDG autostart %s, it is hidden.", service->name);
                return 0;
        }

        if (service->systemd_skip) {
                log_debug("Not generating service for XDG autostart %s, should be skipped by generator.", service->name);
                return 0;
        }

        /* Nothing to do if type is not Application. */
        if (!streq_ptr(service->type, "Application")) {
                log_debug("Not generating service for XDG autostart %s, only Type=Application is supported.", service->name);
                return 0;
        }

        if (!service->exec_string) {
                log_warning("Not generating service for XDG autostart %s, it is has no Exec= line.", service->name);
                return 0;
        }

        /* The TryExec key cannot be checked properly from the systemd unit, it is trivial to check using
         * find_executable though. */
        if (service->try_exec) {
                r = find_executable(service->try_exec, NULL);
                if (r < 0) {
                        log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_WARNING, r,
                                       "Not generating service for XDG autostart %s, could not find TryExec= binary %s: %m",
                                       service->name, service->try_exec);
                        return 0;
                }
        }

        r = xdg_autostart_format_exec_start(service->exec_string, &exec_start);
        if (r < 0) {
                log_warning_errno(r,
                                  "Not generating service for XDG autostart %s, error parsing Exec= line: %m",
                                  service->name);
                return 0;
        }

        if (service->gnome_autostart_phase) {
                /* There is no explicit value for the "Application" phase. */
                log_debug("Not generating service for XDG autostart %s, startup phases are not supported.",
                          service->name);
                return 0;
        }

        path_escaped = specifier_escape(service->path);
        if (!path_escaped)
                return log_oom();

        unit = path_join(dest, service->name);
        if (!unit)
                return log_oom();

        f = fopen(unit, "wxe");
        if (!f)
                return log_error_errno(errno, "Failed to create unit file %s: %m", unit);

        fprintf(f,
                "# Automatically generated by systemd-xdg-autostart-generator\n\n"
                "[Unit]\n"
                "Documentation=man:systemd-xdg-autostart-generator(8)\n"
                "SourcePath=%s\n"
                "PartOf=graphical-session.target\n\n",
                path_escaped);

        if (service->description) {
                _cleanup_free_ char *t = NULL;

                t = specifier_escape(service->description);
                if (!t)
                        return log_oom();

                fprintf(f, "Description=%s\n", t);
        }

        /* Only start after the session is ready. */
        fprintf(f,
                "After=graphical-session.target\n");

        fprintf(f,
                "\n[Service]\n"
                "Type=exec\n"
                "ExecStart=:%s\n"
                "Restart=no\n"
                "TimeoutSec=5s\n"
                "Slice=app.slice\n",
                exec_start);

        if (service->working_directory) {
                _cleanup_free_ char *e_working_directory = NULL;

                e_working_directory = cescape(service->working_directory);
                if (!e_working_directory)
                        return log_oom();

                fprintf(f, "WorkingDirectory=-%s\n", e_working_directory);
        }

        /* Generate an ExecCondition to check $XDG_CURRENT_DESKTOP */
        if (!strv_isempty(service->only_show_in) || !strv_isempty(service->not_show_in)) {
                _cleanup_free_ char *only_show_in = NULL, *not_show_in = NULL, *e_only_show_in = NULL, *e_not_show_in = NULL;

                only_show_in = strv_join(service->only_show_in, ":");
                not_show_in = strv_join(service->not_show_in, ":");
                if (!only_show_in || !not_show_in)
                        return log_oom();

                e_only_show_in = cescape(only_show_in);
                e_not_show_in = cescape(not_show_in);
                if (!e_only_show_in || !e_not_show_in)
                        return log_oom();

                /* Just assume the values are reasonably sane */
                fprintf(f,
                        "ExecCondition=" ROOTLIBEXECDIR "/systemd-xdg-autostart-condition \"%s\" \"%s\"\n",
                        e_only_show_in,
                        e_not_show_in);
        }

        r = xdg_autostart_generate_desktop_condition(f,
                                                     "gnome-systemd-autostart-condition",
                                                     service->autostart_condition);
        if (r < 0)
                return r;

        r = xdg_autostart_generate_desktop_condition(f,
                                                     "kde-systemd-start-condition",
                                                     service->kde_autostart_condition);
        if (r < 0)
                return r;

        (void) generator_add_symlink(dest, "xdg-desktop-autostart.target", "wants", service->name);

        return 0;
}
