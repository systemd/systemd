/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "macro.h"

typedef struct XdgAutostartService {
        char *name;
        char *path;
        char *description; /* Name in XDG desktop file */

        char *type; /* Purely as an assertion check */
        char *exec_string;
        char *working_directory;

        char **only_show_in;
        char **not_show_in;

        char *try_exec;
        char *autostart_condition; /* This is mostly GNOME specific */
        char *kde_autostart_condition;

        char *gnome_autostart_phase;

        bool hidden;
        bool systemd_skip;

} XdgAutostartService;

XdgAutostartService * xdg_autostart_service_free(XdgAutostartService *s);
DEFINE_TRIVIAL_CLEANUP_FUNC(XdgAutostartService*, xdg_autostart_service_free);

char *xdg_autostart_service_translate_name(const char *name);
int xdg_autostart_format_exec_start(const char *exec, char **ret_exec_start);

XdgAutostartService *xdg_autostart_service_parse_desktop(const char *path);
int xdg_autostart_service_generate_unit(const XdgAutostartService *service, const char *dest);
