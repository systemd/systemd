/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <errno.h>

#include "name.h"
#include "service.h"
#include "load-fragment.h"
#include "load-dropin.h"

static int service_load_sysv(Service *s) {
        assert(s);

        /* Load service data from SysV init scripts, preferably with
         * LSB headers ... */

        return -ENOENT;
}

static int service_load(Name *n) {
        int r;
        Service *s = SERVICE(n);

        assert(s);

        exec_context_defaults(&s->exec_context);

        /* Load a .service file */
        r = name_load_fragment(n);

        /* Load a classic init script as a fallback */
        if (r == -ENOENT)
                r = service_load_sysv(s);

        if (r < 0)
                return r;

        /* Load dropin directory data */
        if ((r = name_load_dropin(n)) < 0)
                return r;

        return 0;
}

static void service_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const state_table[_SERVICE_STATE_MAX] = {
                [SERVICE_DEAD] = "dead",
                [SERVICE_START_PRE] = "start-pre",
                [SERVICE_START] = "start",
                [SERVICE_START_POST] = "post",
                [SERVICE_RUNNING] = "running",
                [SERVICE_RELOAD_PRE] = "reload-pre",
                [SERVICE_RELOAD] = "reload",
                [SERVICE_RELOAD_POST] = "reload-post",
                [SERVICE_STOP_PRE] = "stop-pre",
                [SERVICE_STOP] = "stop",
                [SERVICE_SIGTERM] = "sigterm",
                [SERVICE_SIGKILL] = "sigkill",
                [SERVICE_STOP_POST] = "stop-post",
                [SERVICE_MAINTAINANCE] = "maintainance"
        };

        static const char* const command_table[_SERVICE_EXEC_MAX] = {
                [SERVICE_EXEC_START_PRE] = "StartPre",
                [SERVICE_EXEC_START] = "Start",
                [SERVICE_EXEC_START_POST] = "StartPost",
                [SERVICE_EXEC_RELOAD_PRE] = "ReloadPre",
                [SERVICE_EXEC_RELOAD] = "Reload",
                [SERVICE_EXEC_RELOAD_POST] = "ReloadPost",
                [SERVICE_EXEC_STOP_PRE] = "StopPre",
                [SERVICE_EXEC_STOP] = "Stop",
                [SERVICE_EXEC_STOP_POST] = "StopPost",
        };

        ServiceExecCommand c;
        Service *s = SERVICE(n);

        assert(s);

        fprintf(f,
                "%sService State: %s\n",
                prefix, state_table[s->state]);

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SERVICE_EXEC_MAX; c++) {
                ExecCommand *i;

                LIST_FOREACH(i, s->exec_command[c])
                        fprintf(f, "%s%s: %s\n", prefix, command_table[c], i->path);
        }
}

static int service_set_state(Service *s, ServiceState state) {
        assert(s);

        s->state = state;
        return 0;
}

static int service_start(Name *n) {
        Service *s = SERVICE(n);

        assert(s);

        /* We cannot fulfill this request right now */
        if (s->state == SERVICE_STOP_PRE ||
            s->state == SERVICE_STOP ||
            s->state == SERVICE_SIGTERM ||
            s->state == SERVICE_SIGKILL ||
            s->state == SERVICE_STOP_POST)
                return -EAGAIN;

        assert(s->state == SERVICE_DEAD || s->state == SERVICE_MAINTAINANCE);

        return service_set_state(s, SERVICE_START_PRE);
}

static int service_stop(Name *n) {
        Service *s = SERVICE(n);

        assert(s);


        return 0;
}

static int service_reload(Name *n) {
        return 0;
}

static NameActiveState service_active_state(Name *n) {

        static const NameActiveState table[_SERVICE_STATE_MAX] = {
                [SERVICE_DEAD] = NAME_INACTIVE,
                [SERVICE_START_PRE] = NAME_ACTIVATING,
                [SERVICE_START] = NAME_ACTIVATING,
                [SERVICE_START_POST] = NAME_ACTIVATING,
                [SERVICE_RUNNING] = NAME_ACTIVE,
                [SERVICE_RELOAD_PRE] = NAME_ACTIVE_RELOADING,
                [SERVICE_RELOAD] = NAME_ACTIVE_RELOADING,
                [SERVICE_RELOAD_POST] = NAME_ACTIVE_RELOADING,
                [SERVICE_STOP_PRE] = NAME_DEACTIVATING,
                [SERVICE_STOP] = NAME_DEACTIVATING,
                [SERVICE_SIGTERM] = NAME_DEACTIVATING,
                [SERVICE_SIGKILL] = NAME_DEACTIVATING,
                [SERVICE_STOP_POST] = NAME_DEACTIVATING,
                [SERVICE_MAINTAINANCE] = NAME_INACTIVE,
        };

        return table[SERVICE(n)->state];
}

static void service_free_hook(Name *n) {
        Service *s = SERVICE(n);
        unsigned c;

        assert(s);

        exec_context_free(&s->exec_context);

        for (c = 0; c < _SERVICE_EXEC_MAX; c++)
                exec_command_free_list(s->exec_command[c]);

        if (s->socket)
                s->socket->service = NULL;
}

const NameVTable service_vtable = {
        .suffix = ".service",

        .load = service_load,
        .dump = service_dump,

        .start = service_start,
        .stop = service_stop,
        .reload = service_reload,

        .active_state = service_active_state,

        .free_hook = service_free_hook
};
