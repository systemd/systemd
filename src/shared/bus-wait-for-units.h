/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include "macro.h"
#include "sd-bus.h"

typedef struct BusWaitForUnits BusWaitForUnits;

typedef enum BusWaitForUnitsState {
        BUS_WAIT_SUCCESS,    /* Nothing to wait for anymore and nothing failed */
        BUS_WAIT_FAILURE,    /* dito, but something failed */
        BUS_WAIT_RUNNING,    /* Still something to wait for */
        _BUS_WAIT_FOR_UNITS_STATE_MAX,
        _BUS_WAIT_FOR_UNITS_STATE_INVALID = -1,
} BusWaitForUnitsState;

typedef enum BusWaitForUnitsFlags {
        BUS_WAIT_FOR_MAINTENANCE_END = 1 << 0, /* Wait until the unit is no longer in maintenance state */
        BUS_WAIT_FOR_INACTIVE        = 1 << 1, /* Wait until the unit is back in inactive or dead state */
        BUS_WAIT_NO_JOB              = 1 << 2, /* Wait until there's no more job pending */
        BUS_WAIT_REFFED              = 1 << 3, /* The unit is already reffed with RefUnit() */
} BusWaitForUnitsFlags;

typedef void (*bus_wait_for_units_ready_callback)(BusWaitForUnits *d, BusWaitForUnitsState state, void *userdata);
typedef void (*bus_wait_for_units_unit_callback)(BusWaitForUnits *d, const char *unit_path, bool good, void *userdata);

int bus_wait_for_units_new(sd_bus *bus, BusWaitForUnits **ret);
BusWaitForUnits* bus_wait_for_units_free(BusWaitForUnits *d);

BusWaitForUnitsState bus_wait_for_units_state(BusWaitForUnits *d);
void bus_wait_for_units_set_ready_callback(BusWaitForUnits *d, bus_wait_for_units_ready_callback callback, void *userdata);
int bus_wait_for_units_add_unit(BusWaitForUnits *d, const char *unit, BusWaitForUnitsFlags flags, bus_wait_for_units_unit_callback callback, void *userdata);
int bus_wait_for_units_run(BusWaitForUnits *d);

DEFINE_TRIVIAL_CLEANUP_FUNC(BusWaitForUnits*, bus_wait_for_units_free);
