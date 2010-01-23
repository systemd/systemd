/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "device.h"
#include "strv.h"

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

static void device_free_hook(Name *n) {
        Device *d = DEVICE(n);

        assert(d);
        strv_free(d->sysfs);
}

const NameVTable device_vtable = {
        .suffix = ".device",

        .load = name_load_fragment_and_dropin,
        .dump = device_dump,

        .start = NULL,
        .stop = NULL,
        .reload = NULL,

        .active_state = device_active_state,

        .free_hook = device_free_hook
};
