/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "name.h"
#include "automount.h"
#include "load-fragment.h"
#include "load-fstab.h"
#include "load-dropin.h"

static int automount_init(Name *n) {
        int r;
        Automount *a = AUTOMOUNT(n);

        assert(a);

        exec_context_init(&a->exec_context);

        /* Load a .automount file */
        if ((r = name_load_fragment(n)) < 0 && errno != -ENOENT)
                return r;

        /* Load entry from /etc/fstab */
        if ((r = name_load_fstab(n)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = name_load_dropin(n)) < 0)
                return r;

        return 0;
}

static void automount_done(Name *n) {
        Automount *d = AUTOMOUNT(n);

        assert(d);
        free(d->path);
}

static void automount_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const state_table[_AUTOMOUNT_STATE_MAX] = {
                [AUTOMOUNT_DEAD] = "dead",
                [AUTOMOUNT_START_PRE] = "start-pre",
                [AUTOMOUNT_START_POST] = "start-post",
                [AUTOMOUNT_WAITING] = "waiting",
                [AUTOMOUNT_RUNNING] = "running",
                [AUTOMOUNT_STOP_PRE] = "stop-pre",
                [AUTOMOUNT_STOP_POST] = "stop-post",
                [AUTOMOUNT_MAINTAINANCE] = "maintainance"
        };

        static const char* const command_table[_AUTOMOUNT_EXEC_MAX] = {
                [AUTOMOUNT_EXEC_START_PRE] = "StartPre",
                [AUTOMOUNT_EXEC_START_POST] = "StartPost",
                [AUTOMOUNT_EXEC_STOP_PRE] = "StopPre",
                [AUTOMOUNT_EXEC_STOP_POST] = "StopPost"
        };

        AutomountExecCommand c;
        Automount *s = AUTOMOUNT(n);

        assert(s);

        fprintf(f,
                "%sAutomount State: %s\n"
                "%sPath: %s\n",
                prefix, state_table[s->state],
                prefix, s->path);

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _AUTOMOUNT_EXEC_MAX; c++) {
                ExecCommand *i;

                LIST_FOREACH(command, i, s->exec_command[c])
                        fprintf(f, "%s%s: %s\n", prefix, command_table[c], i->path);
        }
}

static NameActiveState automount_active_state(Name *n) {

        static const NameActiveState table[_AUTOMOUNT_STATE_MAX] = {
                [AUTOMOUNT_DEAD] = NAME_INACTIVE,
                [AUTOMOUNT_START_PRE] = NAME_ACTIVATING,
                [AUTOMOUNT_START_POST] = NAME_ACTIVATING,
                [AUTOMOUNT_WAITING] = NAME_ACTIVE,
                [AUTOMOUNT_RUNNING] = NAME_ACTIVE,
                [AUTOMOUNT_STOP_PRE] = NAME_DEACTIVATING,
                [AUTOMOUNT_STOP_POST] = NAME_DEACTIVATING,
                [AUTOMOUNT_MAINTAINANCE] = NAME_INACTIVE,
        };

        return table[AUTOMOUNT(n)->state];
}

const NameVTable automount_vtable = {
        .suffix = ".mount",

        .init = automount_init,
        .done = automount_done,

        .dump = automount_dump,

        .active_state = automount_active_state
};
