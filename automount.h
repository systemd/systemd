/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef fooautomounthfoo
#define fooautomounthfoo

typedef struct Automount Automount;

#include "unit.h"

typedef enum AutomountState {
        AUTOMOUNT_DEAD,
        AUTOMOUNT_START_PRE,
        AUTOMOUNT_START_POST,
        AUTOMOUNT_WAITING,
        AUTOMOUNT_RUNNING,
        AUTOMOUNT_STOP_PRE,
        AUTOMOUNT_STOP_POST,
        AUTOMOUNT_MAINTAINANCE,
        _AUTOMOUNT_STATE_MAX
} AutomountState;

typedef enum AutomountExecCommand {
        AUTOMOUNT_EXEC_START_PRE,
        AUTOMOUNT_EXEC_START_POST,
        AUTOMOUNT_EXEC_STOP_PRE,
        AUTOMOUNT_EXEC_STOP_POST,
        _AUTOMOUNT_EXEC_MAX
} AutomountExecCommand;

struct Automount {
        Meta meta;

        AutomountState state;
        char *path;

        ExecCommand* exec_command[_AUTOMOUNT_EXEC_MAX];
        ExecContext exec_context;

        pid_t contol_pid;

        Mount *mount;
};

extern const UnitVTable automount_vtable;

#endif
