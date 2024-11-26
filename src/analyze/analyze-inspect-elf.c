/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "analyze.h"
#include "analyze-inspect-elf.h"
#include "chase.h"
#include "elf-util.h"
#include "errno-util.h"
#include "fd-util.h"
#include "format-table.h"
#include "format-util.h"
#include "json-util.h"
#include "path-util.h"
#include "strv.h"

static int analyze_elf(char **filenames, sd_json_format_flags_t json_flags) {
        int r;

        STRV_FOREACH(filename, filenames) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *package_metadata = NULL;
                _cleanup_(table_unrefp) Table *t = NULL;
                _cleanup_free_ char *abspath = NULL, *stacktrace = NULL;
                _cleanup_close_ int fd = -EBADF;
                bool coredump = false;

                fd = chase_and_open(*filename, arg_root, CHASE_PREFIX_ROOT, O_RDONLY|O_CLOEXEC, &abspath);
                if (fd < 0)
                        return log_error_errno(fd, "Could not open \"%s\": %m", *filename);

                r = parse_elf_object(fd, abspath, arg_root, /* fork_disable_dump= */false, &stacktrace, &package_metadata);
                if (r < 0)
                        return log_error_errno(r, "Parsing \"%s\" as ELF object failed: %m", abspath);

                t = table_new_vertical();
                if (!t)
                        return log_oom();

                r = table_add_many(
                                t,
                                TABLE_FIELD, "path",
                                TABLE_STRING, abspath);
                if (r < 0)
                        return table_log_add_error(r);

                if (package_metadata) {
                        sd_json_variant *module_json;
                        const char *module_name;

                        JSON_VARIANT_OBJECT_FOREACH(module_name, module_json, package_metadata) {
                                const char *field_name;
                                sd_json_variant *field;

                                /* The ELF type and architecture are added as top-level objects,
                                 * since they are only parsed for the file itself, but the packaging
                                 * metadata is parsed recursively in core files, so there might be
                                 * multiple modules. */
                                if (STR_IN_SET(module_name, "elfType", "elfArchitecture")) {
                                        if (streq(module_name, "elfType") && streq(sd_json_variant_string(module_json), "coredump"))
                                                coredump = true;

                                        r = table_add_many(
                                                        t,
                                                        TABLE_FIELD, module_name,
                                                        TABLE_STRING, sd_json_variant_string(module_json));
                                        if (r < 0)
                                                return table_log_add_error(r);

                                        continue;
                                }

                                /* path/elfType/elfArchitecture come first just once per file,
                                 * then we might have multiple modules, so add a separator between
                                 * them to make the output more readable. */
                                r = table_add_many(t, TABLE_EMPTY, TABLE_EMPTY);
                                if (r < 0)
                                        return table_log_add_error(r);

                                /* In case of core files the module name will be the executable,
                                 * but for binaries/libraries it's just the path, so don't print it
                                 * twice. */
                                if (!streq(abspath, module_name)) {
                                        r = table_add_many(
                                                        t,
                                                        TABLE_FIELD, "module name",
                                                        TABLE_STRING, module_name);
                                        if (r < 0)
                                                return table_log_add_error(r);
                                }

                                JSON_VARIANT_OBJECT_FOREACH(field_name, field, module_json)
                                        if (sd_json_variant_is_string(field)) {
                                                r = table_add_many(
                                                                t,
                                                                TABLE_FIELD, field_name,
                                                                TABLE_STRING, sd_json_variant_string(field));
                                                if (r < 0)
                                                        return table_log_add_error(r);
                                        }
                        }
                }

                if (coredump) {
                        r = table_add_many(t,
                                        TABLE_EMPTY, TABLE_EMPTY,
                                        TABLE_FIELD, "stacktrace",
                                        TABLE_STRING, stacktrace);
                        if (r < 0)
                                return table_log_add_error(r);
                }

                if (sd_json_format_enabled(json_flags))
                        sd_json_variant_dump(package_metadata, json_flags, stdout, NULL);
                else {
                        r = table_print(t, NULL);
                        if (r < 0)
                                return table_log_print_error(r);
                }
        }

        return 0;
}

int verb_elf_inspection(int argc, char *argv[], void *userdata) {
        pager_open(arg_pager_flags);

        return analyze_elf(strv_skip(argv, 1), arg_json_format_flags);
}
