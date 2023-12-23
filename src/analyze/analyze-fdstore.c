/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "analyze-fdstore.h"
#include "analyze.h"
#include "bus-error.h"
#include "bus-locator.h"
#include "fd-util.h"
#include "format-table.h"

static int dump_fdstore(sd_bus *bus, const char *arg) {
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        _cleanup_free_ char *unit = NULL;
        int r;

        assert(bus);
        assert(arg);

        r = unit_name_mangle_with_suffix(arg, NULL, UNIT_NAME_MANGLE_GLOB, ".service", &unit);
        if (r < 0)
                return log_error_errno(r, "Failed to mangle name '%s': %m", arg);

        r = bus_call_method(
                        bus,
                        bus_systemd_mgr,
                        "DumpUnitFileDescriptorStore",
                        &error,
                        &reply,
                        "s", unit);
        if (r < 0)
                return log_error_errno(r, "Failed to call DumpUnitFileDescriptorStore: %s",
                                       bus_error_message(&error, r));

        r = sd_bus_message_enter_container(reply, 'a', "(suuutuusu)");
        if (r < 0)
                return bus_log_parse_error(r);

        table = table_new("fdname", "type", "devno", "inode", "rdevno", "path", "flags");
        if (!table)
                return log_oom();

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        (void) table_set_align_percent(table, TABLE_HEADER_CELL(3), 100);

        for (;;) {
                uint32_t mode, major, minor, rmajor, rminor, flags;
                const char *fdname, *path;
                uint64_t inode;

                r = sd_bus_message_read(
                                reply,
                                "(suuutuusu)",
                                &fdname,
                                &mode,
                                &major, &minor,
                                &inode,
                                &rmajor, &rminor,
                                &path,
                                &flags);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r == 0)
                        break;

                r = table_add_many(
                                table,
                                TABLE_STRING, fdname,
                                TABLE_MODE_INODE_TYPE, mode,
                                TABLE_DEVNUM, makedev(major, minor),
                                TABLE_UINT64, inode,
                                TABLE_DEVNUM, makedev(rmajor, rminor),
                                TABLE_PATH, path,
                                TABLE_STRING, accmode_to_string(flags));
                if (r < 0)
                        return table_log_add_error(r);
        }

        r = sd_bus_message_exit_container(reply);
        if (r < 0)
                return r;

        if (FLAGS_SET(arg_json_format_flags, JSON_FORMAT_OFF) && table_get_rows(table) <= 1)
                log_info("No file descriptors in fdstore of '%s'.", unit);
        else {
                r = table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, /* show_header= */true);
                if (r < 0)
                        return r;
        }

        return EXIT_SUCCESS;
}

int verb_fdstore(int argc, char *argv[], void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        r = acquire_bus(&bus, NULL);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport);

        STRV_FOREACH(arg, strv_skip(argv, 1)) {
                r = dump_fdstore(bus, *arg);
                if (r < 0)
                        return r;
        }

        return EXIT_SUCCESS;
}
