/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "socket.h"

static int socket_load(Name *n) {
        Socket *s = SOCKET(n);

        exec_context_defaults(&s->exec_context);

        return name_load_fragment_and_dropin(n);
}

static void socket_dump(Name *n, FILE *f, const char *prefix) {

        static const char* const state_table[_SOCKET_STATE_MAX] = {
                [SOCKET_DEAD] = "dead",
                [SOCKET_START_PRE] = "start-pre",
                [SOCKET_START_POST] = "start-post",
                [SOCKET_LISTENING] = "listening",
                [SOCKET_RUNNING] = "running",
                [SOCKET_STOP_PRE] = "stop-pre",
                [SOCKET_STOP_POST] = "stop-post",
                [SOCKET_MAINTAINANCE] = "maintainance"
        };

        static const char* const command_table[_SOCKET_EXEC_MAX] = {
                [SOCKET_EXEC_START_PRE] = "StartPre",
                [SOCKET_EXEC_START_POST] = "StartPost",
                [SOCKET_EXEC_STOP_PRE] = "StopPre",
                [SOCKET_EXEC_STOP_POST] = "StopPost"
        };

        SocketExecCommand c;
        Socket *s = SOCKET(n);
        const char *t;
        int r;
        char *k;

        assert(s);

        if ((r = address_print(&n->socket.address, &k)) < 0)
                t = strerror(-r);
        else
                t = k;

        fprintf(f,
                "%sSocket State: %s\n"
                "%sAddress: %s\n",
                prefix, state_table[s->state],
                prefix, t);

        free(k);

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SOCKET_EXEC_MAX; c++) {
                ExecCommand *i;

                LIST_FOREACH(i, s->exec_command[c])
                        fprintf(f, "%s%s: %s\n", prefix, command_table[c], i->path);
        }
}

static NameActiveState socket_active_state(Name *n) {

        static const NameActiveState table[_SOCKET_STATE_MAX] = {
                [SOCKET_DEAD] = NAME_INACTIVE,
                [SOCKET_START_PRE] = NAME_ACTIVATING,
                [SOCKET_START_POST] = NAME_ACTIVATING,
                [SOCKET_LISTENING] = NAME_ACTIVE,
                [SOCKET_RUNNING] = NAME_ACTIVE,
                [SOCKET_STOP_PRE] = NAME_DEACTIVATING,
                [SOCKET_STOP_POST] = NAME_DEACTIVATING,
                [SOCKET_MAINTAINANCE] = NAME_INACTIVE,
        };

        return table[SOCKET(n)->state];
}

static void socket_free_hook(Name *n) {
        unsigned i;
        SocketExecCommand c;
        Socket *s = SOCKET(n);

        assert(s);

        for (i = 0; i < s->n_fds; i++)
                close_nointr(s->fds[i]);

        exec_context_free(&s->exec_context);

        for (c = 0; c < _SOCKET_EXEC_MAX; c++)
                exec_command_free_list(s->exec_command[c]);

        if (s->service)
                s->service->socket = NULL;
}

const NameVTable socket_vtable = {
        .suffix = ".socket",

        .load = socket_load,
        .dump = socket_dump,

        .start = NULL,
        .stop = NULL,
        .reload = NULL,

        .active_state = socket_active_state,

        .free_hook = socket_free_hook
};
