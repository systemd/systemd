/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-map-properties.h"
#include "forward.h"

/* The final state of a unit that terminated, and the resources it consumed while running, as queried from
 * the unit's bus object. */
typedef struct UnitResult {
        char *load_state;
        char *active_state;
        char *result;
        int exit_code;                  /* CLD_* of the main process */
        int exit_status;
        usec_t inactive_exit_usec;
        usec_t inactive_enter_usec;
        uint64_t cpu_usage_nsec;
        uint64_t memory_peak;
        uint64_t memory_swap_peak;
        uint64_t ip_ingress_bytes;
        uint64_t ip_egress_bytes;
        uint64_t io_read_bytes;
        uint64_t io_write_bytes;
} UnitResult;

#define UNIT_RESULT_INIT                                \
        (UnitResult) {                                  \
                .inactive_exit_usec = USEC_INFINITY,    \
                .inactive_enter_usec = USEC_INFINITY,   \
                .cpu_usage_nsec = NSEC_INFINITY,        \
                .memory_peak = UINT64_MAX,              \
                .memory_swap_peak = UINT64_MAX,         \
                .ip_ingress_bytes = UINT64_MAX,         \
                .ip_egress_bytes = UINT64_MAX,          \
                .io_read_bytes = UINT64_MAX,            \
                .io_write_bytes = UINT64_MAX,           \
        }

void unit_result_done(UnitResult *u);

/* Note: the property mapping calls only write the fields actually found in the reply, hence the structure
 * must be initialized with UNIT_RESULT_INIT before mapping properties into it. */
extern const struct bus_properties_map unit_result_property_map[];

int unit_result_show(const UnitResult *u, FILE *f);

int unit_result_to_exit_status(const UnitResult *u);
