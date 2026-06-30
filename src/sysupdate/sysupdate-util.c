/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-bus.h"

#include "bus-error.h"
#include "bus-locator.h"
#include "conf-files.h"
#include "constants.h"
#include "log.h"
#include "login-util.h"
#include "path-util.h"
#include "set.h"
#include "string-util.h"
#include "strv.h"
#include "sysupdate-util.h"

int reboot_now(void) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = sd_bus_open_system(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to open bus connection: %m");

        r = bus_call_method(bus, bus_login_mgr, "RebootWithFlags", &error, NULL, "t",
                            (uint64_t) SD_LOGIND_ROOT_CHECK_INHIBITORS);
        if (r < 0)
                return log_error_errno(r, "Failed to issue reboot request: %s", bus_error_message(&error, r));

        return 0;
}

bool component_name_valid(const char *c) {
        /* See if the specified string enclosed in the directory prefix+suffix would be a valid file name */

        if (!string_is_safe(c, STRING_FILENAME_PART))
                return false;

        /* Stack allocation is safe, since STRING_FILENAME_PART includes a length check */
        const char *j = strjoina("sysupdate.", c, ".d");

        return filename_is_valid(j);
}

bool feature_name_valid(const char *c) {
        /* See if the specified string enclosed in the file suffix would be a valid file name */

        if (!string_is_safe(c, STRING_FILENAME_PART))
                return false;

        /* Stack allocation is safe, since STRING_FILENAME_PART includes a length check */
        const char *j = strjoina(c, ".feature");

        return filename_is_valid(j);
}

int get_component_list(const char *root, char ***ret) {
        int r;

        assert(ret);

        ConfFile **directories = NULL;
        size_t n_directories = 0;
        CLEANUP_ARRAY(directories, n_directories, conf_file_free_array);

        r = conf_files_list_strv_full(
                        ".d",
                        root,
                        CONF_FILES_DIRECTORY|CONF_FILES_WARN,
                        (const char * const *) CONF_PATHS_STRV(""),
                        &directories,
                        &n_directories);
        if (r < 0)
                return r;

        _cleanup_set_free_ Set *names = NULL;

        FOREACH_ARRAY(i, directories, n_directories) {
                ConfFile *e = *i;

                const char *s = startswith(e->filename, "sysupdate.");
                if (!s)
                        continue;

                const char *a = endswith(s, ".d");
                if (!a)
                        continue;

                if (a == s)
                        continue;

                /* Skip the per-component metadata drop-in directories (sysupdate.<component>.component.d/).
                 * These are not components of their own, they carry metadata (and enablement state) for the
                 * component <component>, whose transfer definitions live in sysupdate.<component>.d/. */
                if (endswith(s, ".component.d"))
                        continue;

                _cleanup_free_ char *n = strndup(s, a - s);
                if (!n)
                        return log_oom();

                if (!component_name_valid(n))
                        continue;

                r = set_ensure_consume(&names, &string_hash_ops_free, TAKE_PTR(n));
                if (r < 0 && r != -EEXIST)
                        return r;
        }

        _cleanup_strv_free_ char **z = set_to_strv(&names);
        if (!z)
                return -ENOMEM;

        strv_sort(z);

        *ret = TAKE_PTR(z);
        return 0;
}
