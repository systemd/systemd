/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "name.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"
#include "log.h"

static int config_parse_deps(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **set = data;
        Name *name = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, &l, rvalue, state) {
                char *t;
                int r;
                Name *other;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = manager_load_name(name->meta.manager, t, &other);
                free(t);

                if (r < 0)
                        return r;

                if (!*set)
                        if (!(*set = set_new(trivial_hash_func, trivial_compare_func)))
                                return -ENOMEM;

                if ((r = set_put(*set, other)) < 0)
                        return r;
        }

        return 0;
}

static int config_parse_names(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Set **set = data;
        Name *name = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        FOREACH_WORD(w, &l, rvalue, state) {
                char *t;
                int r;
                Name *other;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                other = manager_get_name(name->meta.manager, t);

                if (other) {

                        if (other != name) {

                                if (other->meta.load_state != NAME_STUB) {
                                        free(t);
                                        return -EEXIST;
                                }

                                if ((r = name_merge(name, other)) < 0) {
                                        free(t);
                                        return r;
                                }
                        }

                } else {

                        if (!*set)
                                if (!(*set = set_new(trivial_hash_func, trivial_compare_func))) {
                                        free(t);
                                        return -ENOMEM;
                                }

                        if ((r = set_put(*set, t)) < 0) {
                                free(t);
                                return r;
                        }

                        t = NULL;
                }

                free(t);
        }

        return 0;
}

static int config_parse_listen(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r;
        SocketPort *p;
        Socket *s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = (Socket*) data;

        if (!(p = new0(SocketPort, 1)))
                return -ENOMEM;

        if (streq(lvalue, "ListenFIFO")) {
                p->type = SOCKET_FIFO;

                if (!(p->path = strdup(rvalue))) {
                        free(p);
                        return -ENOMEM;
                }
        } else {
                p->type = SOCKET_SOCKET;

                if ((r = socket_address_parse(&p->address, rvalue)) < 0) {
                        log_error("[%s:%u] Failed to parse address value: %s", filename, line, rvalue);
                        free(p);
                        return r;
                }

                if (streq(lvalue, "ListenStream"))
                        p->address.type = SOCK_STREAM;
                else if (streq(lvalue, "ListenDatagram"))
                        p->address.type = SOCK_DGRAM;
                else {
                        assert(streq(lvalue, "ListenSequentialPacket"));
                        p->address.type = SOCK_SEQPACKET;
                }

                if (socket_address_family(&p->address) != AF_LOCAL && p->address.type == SOCK_SEQPACKET) {
                        free(p);
                        return -EPROTONOSUPPORT;
                }
        }

        p->fd = -1;
        LIST_PREPEND(SocketPort, s->ports, p);

        return 0;
}

static int config_parse_bind(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int r;
        Socket *s;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        s = (Socket*) data;

        if ((r = parse_boolean(rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse bind IPv6 only value: %s", filename, line, rvalue);
                return r;
        }

        s->bind_ipv6_only = r ? SOCKET_ADDRESS_IPV6_ONLY : SOCKET_ADDRESS_BOTH;

        return 0;
}

int name_load_fragment(Name *n) {

        static const char* const section_table[_NAME_TYPE_MAX] = {
                [NAME_SERVICE]   = "Service",
                [NAME_TIMER]     = "Timer",
                [NAME_SOCKET]    = "Socket",
                [NAME_MILESTONE] = "Milestone",
                [NAME_DEVICE]    = "Device",
                [NAME_MOUNT]     = "Mount",
                [NAME_AUTOMOUNT] = "Automount",
                [NAME_SNAPSHOT]  = "Snapshot"
        };

        const ConfigItem items[] = {
                { "Names",                  config_parse_names,    &n->meta.names,                           "Meta"   },
                { "Description",            config_parse_string,   &n->meta.description,                     "Meta"   },
                { "Requires",               config_parse_deps,     n->meta.dependencies+NAME_REQUIRES,       "Meta"   },
                { "SoftRequires",           config_parse_deps,     n->meta.dependencies+NAME_SOFT_REQUIRES,  "Meta"   },
                { "Wants",                  config_parse_deps,     n->meta.dependencies+NAME_WANTS,          "Meta"   },
                { "Requisite",              config_parse_deps,     n->meta.dependencies+NAME_REQUISITE,      "Meta"   },
                { "SoftRequisite",          config_parse_deps,     n->meta.dependencies+NAME_SOFT_REQUISITE, "Meta"   },
                { "Conflicts",              config_parse_deps,     n->meta.dependencies+NAME_CONFLICTS,      "Meta"   },
                { "Before",                 config_parse_deps,     n->meta.dependencies+NAME_BEFORE,         "Meta"   },
                { "After",                  config_parse_deps,     n->meta.dependencies+NAME_AFTER,          "Meta"   },
                { "ListenStream",           config_parse_listen,   &n->socket,                               "Socket" },
                { "ListenDatagram",         config_parse_listen,   &n->socket,                               "Socket" },
                { "ListenSequentialPacket", config_parse_listen,   &n->socket,                               "Socket" },
                { "ListenFIFO",             config_parse_listen,   &n->socket,                               "Socket" },
                { "BindIPv6Only",           config_parse_bind,     &n->socket,                               "Socket" },
                { "Backlog",                config_parse_unsigned, &n->socket.backlog,                       "Socket" },
                { NULL, NULL, NULL, NULL }
        };

        const

        char *t;
        int r;
        void *state;
        const char *sections[3];

        assert(n);
        assert(n->meta.load_state == NAME_STUB);

        sections[0] = "Meta";
        sections[1] = section_table[n->meta.type];
        sections[2] = NULL;

        SET_FOREACH(t, n->meta.names, state)
                if ((r = config_parse(t, sections, items, n)) < 0)
                        goto fail;

        r = 0;

fail:
        return r;
}
