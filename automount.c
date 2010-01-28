/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "unit.h"
#include "automount.h"
#include "load-fragment.h"
#include "load-fstab.h"
#include "load-dropin.h"

static int automount_init(Unit *u) {
        int r;
        Automount *a = AUTOMOUNT(u);

        assert(a);

        exec_context_init(&a->exec_context);

        /* Load a .automount file */
        if ((r = unit_load_fragment(u)) < 0)
                return r;

        /* Load entry from /etc/fstab */
        if ((r = unit_load_fstab(u)) < 0)
                return r;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(u)) < 0)
                return r;

        return 0;
}

static void automount_done(Unit *u) {
        Automount *d = AUTOMOUNT(u);

        assert(d);
        free(d->path);
}

static void automount_dump(Unit *u, FILE *f, const char *prefix) {

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
        Automount *s = AUTOMOUNT(u);

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

static UnitActiveState automount_active_state(Unit *u) {

        static const UnitActiveState table[_AUTOMOUNT_STATE_MAX] = {
                [AUTOMOUNT_DEAD] = UNIT_INACTIVE,
                [AUTOMOUNT_START_PRE] = UNIT_ACTIVATING,
                [AUTOMOUNT_START_POST] = UNIT_ACTIVATING,
                [AUTOMOUNT_WAITING] = UNIT_ACTIVE,
                [AUTOMOUNT_RUNNING] = UNIT_ACTIVE,
                [AUTOMOUNT_STOP_PRE] = UNIT_DEACTIVATING,
                [AUTOMOUNT_STOP_POST] = UNIT_DEACTIVATING,
                [AUTOMOUNT_MAINTAINANCE] = UNIT_INACTIVE,
        };

        return table[AUTOMOUNT(u)->state];
}

const UnitVTable automount_vtable = {
        .suffix = ".mount",

        .init = automount_init,
        .done = automount_done,

        .dump = automount_dump,

        .active_state = automount_active_state
};
