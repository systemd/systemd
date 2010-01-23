/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include "name.h"
#include "socket.h"

static int socket_load(Name *n) {
        Socket *s = SOCKET(n);

        exec_context_defaults(&s->exec_context);
        s->backlog = SOMAXCONN;

        return name_load_fragment_and_dropin(n);
}

static const char* listen_lookup(int type) {

        if (type == SOCK_STREAM)
                return "ListenStream";
        else if (type == SOCK_DGRAM)
                return "ListenDatagram";
        else if (type == SOCK_SEQPACKET)
                return "ListenSequentialPacket";

        assert_not_reached("Unkown socket type");
        return NULL;
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
        SocketPort *p;

        assert(s);

        fprintf(f,
                "%sSocket State: %s\n"
                "%sBindIPv6Only: %s\n"
                "%sBacklog: %u\n",
                prefix, state_table[s->state],
                prefix, yes_no(s->bind_ipv6_only),
                prefix, s->backlog);

        LIST_FOREACH(p, s->ports) {

                if (p->type == SOCKET_SOCKET) {
                        const char *t;
                        int r;
                        char *k;

                        if ((r = socket_address_print(&p->address, &k)) < 0)
                                t = strerror(-r);
                        else
                                t = k;

                        fprintf(f, "%s%s: %s\n", prefix, listen_lookup(p->address.type), k);
                        free(k);
                } else
                        fprintf(f, "%sListenFIFO: %s\n", prefix, p->path);
        }

        exec_context_dump(&s->exec_context, f, prefix);

        for (c = 0; c < _SOCKET_EXEC_MAX; c++) {
                ExecCommand *i;

                LIST_FOREACH(i, s->exec_command[c])
                        fprintf(f, "%s%s: %s\n", prefix, command_table[c], i->path);
        }
}

static int socket_start(Name *n) {
        return 0;
}

static int socket_stop(Name *n) {
        return 0;
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
        SocketExecCommand c;
        Socket *s = SOCKET(n);
        SocketPort *p;

        assert(s);

        while ((p = s->ports)) {
                LIST_REMOVE(SocketPort, s->ports, p);

                if (p->fd >= 0)
                        close_nointr(p->fd);
                free(p->path);
                free(p);
        }

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

        .start = socket_start,
        .stop = socket_stop,
        .reload = NULL,

        .active_state = socket_active_state,

        .free_hook = socket_free_hook
};
