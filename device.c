/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "device.h"
#include "strv.h"

static void device_done(Name *n) {
        Device *d = DEVICE(n);

        assert(d);
        strv_free(d->sysfs);
}

static void device_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const state_table[_DEVICE_STATE_MAX] = {
                [DEVICE_DEAD] = "dead",
                [DEVICE_AVAILABLE] = "available"
        };

        Device *s = DEVICE(n);

        assert(s);

        fprintf(f,
                "%sDevice State: %s\n",
                prefix, state_table[s->state]);
}

static NameActiveState device_active_state(Name *n) {
        return DEVICE(n)->state == DEVICE_DEAD ? NAME_INACTIVE : NAME_ACTIVE;
}

const NameVTable device_vtable = {
        .suffix = ".device",

        .init = name_load_fragment_and_dropin,
        .done = device_done,
        .dump = device_dump,

        .active_state = device_active_state
};
