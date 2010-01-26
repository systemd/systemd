/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "unit.h"
#include "device.h"
#include "strv.h"

static void device_done(Unit *u) {
        Device *d = DEVICE(u);

        assert(d);
        strv_free(d->sysfs);
}

static void device_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const state_table[_DEVICE_STATE_MAX] = {
                [DEVICE_DEAD] = "dead",
                [DEVICE_AVAILABLE] = "available"
        };

        Device *s = DEVICE(u);

        assert(s);

        fprintf(f,
                "%sDevice State: %s\n",
                prefix, state_table[s->state]);
}

static UnitActiveState device_active_state(Unit *u) {
        return DEVICE(u)->state == DEVICE_DEAD ? UNIT_INACTIVE : UNIT_ACTIVE;
}

const UnitVTable device_vtable = {
        .suffix = ".device",

        .init = unit_load_fragment_and_dropin,
        .done = device_done,
        .dump = device_dump,

        .active_state = device_active_state
};
