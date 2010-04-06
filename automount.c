/*-*- Mode: C; c-basic-offset: 8 -*-*/

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <errno.h>

#include "unit.h"
#include "automount.h"
#include "load-fragment.h"
#include "load-dropin.h"

static int automount_init(Unit *u, UnitLoadState *new_state) {
        int r;
        Automount *a = AUTOMOUNT(u);

        assert(a);

        exec_context_init(&a->exec_context);

        /* Load a .automount file */
        if ((r = unit_load_fragment(u, new_state)) < 0)
                return r;

        if (*new_state == UNIT_STUB)
                *new_state = UNIT_LOADED;

        /* Load drop-in directory data */
        if ((r = unit_load_dropin(unit_follow_merge(u))) < 0)
                return r;

        if (*new_state == UNIT_LOADED) {

                if ((r = unit_add_dependency(u, UNIT_BEFORE, UNIT(a->mount))) < 0)
                        return r;

                if ((r = unit_add_exec_dependencies(u, &a->exec_context)) < 0)
                        return r;

                if ((r = unit_add_default_cgroup(u)) < 0)
                        return r;
        }

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
