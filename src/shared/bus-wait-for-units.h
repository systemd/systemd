/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "forward.h"

typedef struct BusWaitForUnits BusWaitForUnits;

typedef enum BusWaitForUnitsState {
        BUS_WAIT_SUCCESS,    /* Nothing to wait for anymore and nothing failed */
        BUS_WAIT_FAILURE,    /* ditto, but something failed */
        BUS_WAIT_RUNNING,    /* Still something to wait for */
        _BUS_WAIT_FOR_UNITS_STATE_MAX,
        _BUS_WAIT_FOR_UNITS_STATE_INVALID = -EINVAL,
} BusWaitForUnitsState;

typedef enum BusWaitForUnitsFlags {
        BUS_WAIT_FOR_MAINTENANCE_END = 1 << 0, /* Wait until the unit is no longer in maintenance state */
        BUS_WAIT_FOR_INACTIVE        = 1 << 1, /* Wait until the unit is back in inactive or dead state */
        BUS_WAIT_NO_JOB              = 1 << 2, /* Wait until there's no more job pending */
        BUS_WAIT_REFFED              = 1 << 3, /* The unit is already reffed with RefUnit() */
        BUS_WAIT_COLLECT_RESULT      = 1 << 4, /* Query the unit's final state and resource usage once done, and pass it to the callback */
        _BUS_WAIT_FOR_TARGET         = BUS_WAIT_FOR_MAINTENANCE_END|BUS_WAIT_FOR_INACTIVE|BUS_WAIT_NO_JOB,
} BusWaitForUnitsFlags;

/* Note: 'result' is non-NULL only if BUS_WAIT_COLLECT_RESULT was set for the unit. The callback may take
 * ownership of its contents via TAKE_STRUCT(). */
typedef void (*bus_wait_for_units_unit_callback_t)(BusWaitForUnits *d, const char *unit, bool good, UnitResult *result, void *userdata);

int bus_wait_for_units_new(sd_bus *bus, BusWaitForUnits **ret);

BusWaitForUnits* bus_wait_for_units_free(BusWaitForUnits *d);
DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForUnits*, bus_wait_for_units_free);

int bus_wait_for_units_add_unit(
                BusWaitForUnits *d,
                const char *unit,
                BusWaitForUnitsFlags flags,
                bus_wait_for_units_unit_callback_t callback,
                void *userdata);

int bus_wait_for_units_run(BusWaitForUnits *d);
BusWaitForUnitsState bus_wait_for_units_state(BusWaitForUnits *d);
