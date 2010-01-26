/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "name.h"
#include "mount.h"
#include "load-fragment.h"
#include "load-fstab.h"
#include "load-dropin.h"

static int mount_init(Name *n) {
        int r;
        Mount *m = MOUNT(n);

        assert(m);

        /* Load a .mount file */
        if ((r = name_load_fragment(n)) < 0 && errno != -ENOENT)
                return r;

        /* Load entry from /etc/fstab */
        if ((r = name_load_fstab(n)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = name_load_dropin(n)) < 0)
                return r;

        return r;
}

static void mount_done(Name *n) {
        Mount *d = MOUNT(n);

        assert(d);
        free(d->path);
}

static void mount_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const state_table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = "dead",
                [MOUNT_MOUNTING] = "mounting",
                [MOUNT_MOUNTED] = "mounted",
                [MOUNT_UNMOUNTING] = "unmounting",
                [MOUNT_MAINTAINANCE] = "maintainance"
        };

        Mount *s = MOUNT(n);

        assert(s);

        fprintf(f,
                "%sMount State: %s\n"
                "%sPath: %s\n",
                prefix, state_table[s->state],
                prefix, s->path);
}

static NameActiveState mount_active_state(Name *n) {

        static const NameActiveState table[_MOUNT_STATE_MAX] = {
                [MOUNT_DEAD] = NAME_INACTIVE,
                [MOUNT_MOUNTING] = NAME_ACTIVATING,
                [MOUNT_MOUNTED] = NAME_ACTIVE,
                [MOUNT_UNMOUNTING] = NAME_DEACTIVATING,
                [MOUNT_MAINTAINANCE] = NAME_INACTIVE,
        };

        return table[MOUNT(n)->state];
}

const NameVTable mount_vtable = {
        .suffix = ".mount",

        .init = mount_init,
        .done = mount_done,

        .dump = mount_dump,

        .active_state = mount_active_state,
};
