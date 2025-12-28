/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "analyze.h"
#include "analyze-dlopen-metadata.h"
#include "chase.h"
#include "elf-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "json-util.h"
#include "strv.h"

int verb_dlopen_metadata(int argc, char *argv[], void *userdata) {
        int r;

        _cleanup_free_ char *abspath = NULL;
        _cleanup_close_ int fd = -EBADF;
        fd = chase_and_open(argv[1], arg_root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC, &abspath);
        if (fd < 0)
                return log_error_errno(fd, "Could not open \"%s\": %m", argv[1]);

        _cleanup_(sd_json_variant_unrefp) sd_json_variant *dlopen_metadata = NULL;
        r = parse_elf_object(
                        fd,
                        abspath,
                        arg_root,
                        /* fork_disable_dump= */ false,
                        /* ret= */ NULL,
                        NULL,
                        &dlopen_metadata);
        if (r < 0)
                return log_error_errno(r, "Parsing \"%s\" as ELF object failed: %m", abspath);

        if (!dlopen_metadata)
                return log_error_errno(SYNTHETIC_ERRNO(ENODATA), "%s does not contain any .note.dlopen sections", argv[1]);

        if (sd_json_format_enabled(arg_json_format_flags))
                return sd_json_variant_dump(dlopen_metadata, arg_json_format_flags, stdout, NULL);

        _cleanup_(table_unrefp) Table *t = NULL;
        t = table_new("feature", "description", "soname", "priority");
        if (!t)
                return log_oom();

        table_set_ersatz_string(t, TABLE_ERSATZ_NA);

        sd_json_variant *z;
        JSON_VARIANT_ARRAY_FOREACH(z, dlopen_metadata) {
                _cleanup_strv_free_ char **sonames = NULL;

                r = sd_json_variant_strv(sd_json_variant_by_key(z, "soname"), &sonames);
                if (r < 0)
                        return log_error_errno(r, "Failed to extract sonames from dlopen metadata: %m");

                r = table_add_many(
                                t,
                                TABLE_STRING, sd_json_variant_string(sd_json_variant_by_key(z, "feature")),
                                TABLE_STRING, sd_json_variant_string(sd_json_variant_by_key(z, "description")),
                                TABLE_STRV_WRAPPED, sonames,
                                TABLE_STRING, sd_json_variant_string(sd_json_variant_by_key(z, "priority")));
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = table_print_with_pager(t, SD_JSON_FORMAT_OFF, arg_pager_flags, arg_legend);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}
