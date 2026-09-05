/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "ansi-color.h"
#include "bus-map-properties.h"
#include "exit-status.h"
#include "format-table.h"
#include "format-util.h"
#include "process-util.h"
#include "signal-util.h"
#include "string-util.h"
#include "time-util.h"
#include "unit-result.h"

void unit_result_done(UnitResult *u) {
        assert(u);

        u->load_state = mfree(u->load_state);
        u->active_state = mfree(u->active_state);
        u->result = mfree(u->result);
}

const struct bus_properties_map unit_result_property_map[] = {
        { "LoadState",                       "s", NULL, offsetof(UnitResult, load_state)          },
        { "ActiveState",                     "s", NULL, offsetof(UnitResult, active_state)        },
        { "InactiveExitTimestampMonotonic",  "t", NULL, offsetof(UnitResult, inactive_exit_usec)  },
        { "InactiveEnterTimestampMonotonic", "t", NULL, offsetof(UnitResult, inactive_enter_usec) },
        { "Result",                          "s", NULL, offsetof(UnitResult, result)              },
        { "ExecMainCode",                    "i", NULL, offsetof(UnitResult, exit_code)           },
        { "ExecMainStatus",                  "i", NULL, offsetof(UnitResult, exit_status)         },
        { "CPUUsageNSec",                    "t", NULL, offsetof(UnitResult, cpu_usage_nsec)      },
        { "MemoryPeak",                      "t", NULL, offsetof(UnitResult, memory_peak)         },
        { "MemorySwapPeak",                  "t", NULL, offsetof(UnitResult, memory_swap_peak)    },
        { "IPIngressBytes",                  "t", NULL, offsetof(UnitResult, ip_ingress_bytes)    },
        { "IPEgressBytes",                   "t", NULL, offsetof(UnitResult, ip_egress_bytes)     },
        { "IOReadBytes",                     "t", NULL, offsetof(UnitResult, io_read_bytes)       },
        { "IOWriteBytes",                    "t", NULL, offsetof(UnitResult, io_write_bytes)      },
        {}
};

int unit_result_show(const UnitResult *u, FILE *f, sd_json_format_flags_t json_format_flags) {
        int r;

        assert(u);
        assert(f);

        _cleanup_(table_unrefp) Table *t = table_new_vertical();
        if (!t)
                return log_oom();

        if (!isempty(u->result)) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "Finished with result",
                                TABLE_STRING, u->result,
                                TABLE_SET_COLOR, streq(u->result, "success") ? ansi_highlight_green() : ansi_highlight_red());
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (u->exit_code > 0) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD,
                                "Main processes terminated with");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "code=%s, status=%i/%s",
                                strna(sigchld_code_to_string(u->exit_code)),
                                u->exit_status,
                                strna(u->exit_code == CLD_EXITED ?
                                      exit_status_to_string(u->exit_status, EXIT_STATUS_FULL) :
                                      signal_to_string(u->exit_status)));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (timestamp_is_set(u->inactive_enter_usec) &&
            timestamp_is_set(u->inactive_exit_usec) &&
            u->inactive_enter_usec > u->inactive_exit_usec) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "Service runtime",
                                TABLE_TIMESPAN_MSEC, u->inactive_enter_usec - u->inactive_exit_usec);
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (u->cpu_usage_nsec != NSEC_INFINITY) {
                r = table_add_many(
                                t,
                                TABLE_FIELD, "CPU time consumed",
                                TABLE_TIMESPAN_MSEC, DIV_ROUND_UP(u->cpu_usage_nsec, NSEC_PER_USEC));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (u->memory_peak != UINT64_MAX) {
                const char *swap;

                if (u->memory_swap_peak != UINT64_MAX)
                        swap = strjoina(" (swap: ", FORMAT_BYTES(u->memory_swap_peak), ")");
                else
                        swap = "";

                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "Memory peak");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s",
                                FORMAT_BYTES(u->memory_peak), swap);
                if (r < 0)
                        return table_log_add_error(r);
        }

        const char *ip_ingress = NULL, *ip_egress = NULL;
        if (!IN_SET(u->ip_ingress_bytes, 0, UINT64_MAX))
                ip_ingress = strjoina("received ", FORMAT_BYTES(u->ip_ingress_bytes));
        if (!IN_SET(u->ip_egress_bytes, 0, UINT64_MAX))
                ip_egress = strjoina("sent ", FORMAT_BYTES(u->ip_egress_bytes));

        if (ip_ingress || ip_egress) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "IP Traffic");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s%s", strempty(ip_ingress), ip_ingress && ip_egress ? ", " : "", strempty(ip_egress));
                if (r < 0)
                        return table_log_add_error(r);
        }

        const char *io_read = NULL, *io_write = NULL;
        if (!IN_SET(u->io_read_bytes, 0, UINT64_MAX))
                io_read = strjoina("read ", FORMAT_BYTES(u->io_read_bytes));
        if (!IN_SET(u->io_write_bytes, 0, UINT64_MAX))
                io_write = strjoina("written ", FORMAT_BYTES(u->io_write_bytes));

        if (io_read || io_write) {
                r = table_add_cell(
                                t,
                                /* ret_cell= */ NULL,
                                TABLE_FIELD, "IO Bytes");
                if (r < 0)
                        return table_log_add_error(r);

                r = table_add_cell_stringf(
                                t,
                                /* ret_cell= */ NULL,
                                "%s%s%s", strempty(io_read), io_read && io_write ? ", " : "", strempty(io_write));
                if (r < 0)
                        return table_log_add_error(r);
        }

        if (sd_json_format_enabled(json_format_flags))
                r = table_print_json(t, f, json_format_flags);
        else
                r = table_print_full(t, f, /* flush= */ true);
        if (r < 0)
                return table_log_print_error(r);

        return 0;
}

int unit_result_to_exit_status(const UnitResult *u) {
        assert(u);

        /* Converts the result of a unit into an exit status to return, propagating the unit's main process
         * exit status where we can. If the unit defines e.g. SuccessExitStatus=, honour this, and return 0
         * to mean "success". */

        if (streq_ptr(u->result, "success"))
                return EXIT_SUCCESS;
        if (streq_ptr(u->result, "exit-code") && u->exit_status > 0)
                return u->exit_status;
        if (streq_ptr(u->result, "signal"))
                return EXIT_EXCEPTION;

        return EXIT_FAILURE;
}
