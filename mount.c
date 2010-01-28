/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "unit.h"
#include "mount.h"
#include "load-fragment.h"
#include "load-fstab.h"
#include "load-dropin.h"

static int mount_init(Unit *u) {
        int r;
        Mount *m = MOUNT(u);

        assert(m);

        /* Load a .mount file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        /* Load entry from /etc/fstab */
        if ((r = unit_load_fstab(u)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(u)) < 0)
                return r;

        return r;
}

static void mount_done(Unit *u) {
        Mount *d = MOUNT(u);

        assert(d);
        free(d->path);
}

static void mount_dump(Unit *u, FILE *f, const char *prefix) {

        static const char* const state_table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = "dead",
                [MOUNT_MOUNTING] = "mounting",
                [MOUNT_MOUNTED] = "mounted",
                [MOUNT_UNMOUNTING] = "unmounting",
                [MOUNT_MAINTAINANCE] = "maintainance"
        };

        Mount *s = MOUNT(u);

        assert(s);

        fprintf(f,
                "%sMount State: %s\n"
                "%sPath: %s\n",
                prefix, state_table[s->state],
                prefix, s->path);
}

static UnitActiveState mount_active_state(Unit *u) {

        static const UnitActiveState table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = UNIT_INACTIVE,
                [MOUNT_MOUNTING] = UNIT_ACTIVATING,
                [MOUNT_MOUNTED] = UNIT_ACTIVE,
                [MOUNT_UNMOUNTING] = UNIT_DEACTIVATING,
                [MOUNT_MAINTAINANCE] = UNIT_INACTIVE,
        };

        return table[MOUNT(u)->state];
}

const UnitVTable mount_vtable = {
        .suffix = ".mount",

        .init = mount_init,
        .done = mount_done,

        .dump = mount_dump,

        .active_state = mount_active_state,
};
