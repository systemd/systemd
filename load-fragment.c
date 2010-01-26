/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>
#include <linux/oom.h>

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

        NameDependency d = PTR_TO_UINT(data);
        Name *name = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

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

                if ((r = name_add_dependency(name, d, other)) < 0)
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
        LIST_PREPEND(SocketPort, port, s->ports, p);

        return 0;
}

static int config_parse_socket_bind(
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

static int config_parse_nice(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *i = data, priority, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, &priority)) < 0) {
                log_error("[%s:%u] Failed to parse nice priority: %s", filename, line, rvalue);
                return r;
        }

        if (priority < PRIO_MIN || priority >= PRIO_MAX) {
                log_error("[%s:%u] Nice priority out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        *i = priority;
        return 0;
}

static int config_parse_oom_adjust(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *i = data, oa, r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atoi(rvalue, &oa)) < 0) {
                log_error("[%s:%u] Failed to parse OOM adjust value: %s", filename, line, rvalue);
                return r;
        }

        if (oa < OOM_DISABLE || oa > OOM_ADJUST_MAX) {
                log_error("[%s:%u] OOM adjust value out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        *i = oa;
        return 0;
}

static int config_parse_umask(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        mode_t *m = data;
        long l;
        char *x = NULL;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        errno = 0;
        l = strtol(rvalue, &x, 8);
        if (!x || *x || errno) {
                log_error("[%s:%u] Failed to parse umask value: %s", filename, line, rvalue);
                return errno ? -errno : -EINVAL;
        }

        if (l < 0000 || l > 0777) {
                log_error("[%s:%u] umask value out of range: %s", filename, line, rvalue);
                return -ERANGE;
        }

        *m = (mode_t) l;
        return 0;
}

static int config_parse_exec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        ExecCommand **e = data, *ee, *nce = NULL;
        char **n;
        char *w;
        unsigned k;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        k = 0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                k++;

        if (!(n = new(char*, k+1)))
                return -ENOMEM;

        k = 0;
        FOREACH_WORD_QUOTED(w, l, rvalue, state)
                if (!(n[k++] = strndup(w, l)))
                        goto fail;

        n[k] = NULL;

        if (!n[0] || n[0][0] != '/') {
                log_error("[%s:%u] Invalid executable path in command line: %s", filename, line, rvalue);
                strv_free(n);
                return -EINVAL;
        }

        if (!(nce = new0(ExecCommand, 1)))
                goto fail;

        nce->argv = n;
        if (!(nce->path = strdup(n[0])))
                goto fail;

        if (*e) {
                /* It's kinda important that we keep the order here */
                LIST_FIND_TAIL(ExecCommand, command, *e, ee);
                LIST_INSERT_AFTER(ExecCommand, command, *e, ee, nce);
        } else
                *e = nce;

        return 0;

fail:
        for (; k > 0; k--)
                free(n[k-1]);
        free(n);

        free(nce);

        return -ENOMEM;
}

static int config_parse_usec(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        usec_t *usec = data;
        unsigned long long u;
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = safe_atollu(rvalue, &u)) < 0) {
                log_error("[%s:%u] Failed to parse time value: %s", filename, line, rvalue);
                return r;
        }

        /* We actually assume the user configures seconds. Later on we
         * might choose to support suffixes for time values, to
         * configure bigger or smaller units */

        *usec = u * USEC_PER_SEC;

        return 0;
}

static int config_parse_service_type(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Service *s = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "forking"))
                s->type = SERVICE_FORKING;
        else if (streq(rvalue, "simple"))
                s->type = SERVICE_SIMPLE;
        else {
                log_error("[%s:%u] Failed to parse service type: %s", filename, line, rvalue);
                return -EBADMSG;
        }

        return 0;
}

static int config_parse_service_restart(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        Service *s = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "once"))
                s->restart = SERVICE_ONCE;
        else if (streq(rvalue, "on-success"))
                s->type = SERVICE_RESTART_ON_SUCCESS;
        else if (streq(rvalue, "always"))
                s->type = SERVICE_RESTART_ALWAYS;
        else {
                log_error("[%s:%u] Failed to parse service type: %s", filename, line, rvalue);
                return -EBADMSG;
        }

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

#define EXEC_CONTEXT_CONFIG_ITEMS(context, section) \
                { "Directory",              config_parse_path,            &(context).directory,                              section   }, \
                { "User",                   config_parse_string,          &(context).user,                                   section   }, \
                { "Group",                  config_parse_string,          &(context).group,                                  section   }, \
                { "SupplementaryGroups",    config_parse_strv,            &(context).supplementary_groups,                   section   }, \
                { "Nice",                   config_parse_nice,            &(context).nice,                                   section   }, \
                { "OOMAdjust",              config_parse_oom_adjust,      &(context).oom_adjust,                             section   }, \
                { "UMask",                  config_parse_umask,           &(context).umask,                                  section   }, \
                { "Environment",            config_parse_strv,            &(context).environment,                            section   }

        const ConfigItem items[] = {
                { "Names",                  config_parse_names,           &n->meta.names,                                    "Meta"    },
                { "Description",            config_parse_string,          &n->meta.description,                              "Meta"    },
                { "Requires",               config_parse_deps,            UINT_TO_PTR(NAME_REQUIRES),                        "Meta"    },
                { "SoftRequires",           config_parse_deps,            UINT_TO_PTR(NAME_SOFT_REQUIRES),                   "Meta"    },
                { "Wants",                  config_parse_deps,            UINT_TO_PTR(NAME_WANTS),                           "Meta"    },
                { "Requisite",              config_parse_deps,            UINT_TO_PTR(NAME_REQUISITE),                       "Meta"    },
                { "SoftRequisite",          config_parse_deps,            UINT_TO_PTR(NAME_SOFT_REQUISITE),                  "Meta"    },
                { "Conflicts",              config_parse_deps,            UINT_TO_PTR(NAME_CONFLICTS),                       "Meta"    },
                { "Before",                 config_parse_deps,            UINT_TO_PTR(NAME_BEFORE),                          "Meta"    },
                { "After",                  config_parse_deps,            UINT_TO_PTR(NAME_AFTER),                           "Meta"    },

                { "PIDFile",                config_parse_path,            &n->service.pid_file,                              "Service" },
                { "ExecStartPre",           config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_START_PRE],  "Service" },
                { "ExecStart",              config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_START],      "Service" },
                { "ExecStartPost",          config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_START_POST], "Service" },
                { "ExecReload",             config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_RELOAD],     "Service" },
                { "ExecStop",               config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_STOP],       "Service" },
                { "ExecStopPost",           config_parse_exec,            &n->service.exec_command[SERVICE_EXEC_STOP_POST],  "Service" },
                { "RestartSec",             config_parse_usec,            &n->service.restart_usec,                          "Service" },
                { "TimeoutSec",             config_parse_usec,            &n->service.timeout_usec,                          "Service" },
                { "Type",                   config_parse_service_type,    &n->service,                                       "Service" },
                { "Restart",                config_parse_service_restart, &n->service,                                       "Service" },
                EXEC_CONTEXT_CONFIG_ITEMS(n->service.exec_context, "Service"),

                { "ListenStream",           config_parse_listen,          &n->socket,                                        "Socket"  },
                { "ListenDatagram",         config_parse_listen,          &n->socket,                                        "Socket"  },
                { "ListenSequentialPacket", config_parse_listen,          &n->socket,                                        "Socket"  },
                { "ListenFIFO",             config_parse_listen,          &n->socket,                                        "Socket"  },
                { "BindIPv6Only",           config_parse_socket_bind,     &n->socket,                                        "Socket"  },
                { "Backlog",                config_parse_unsigned,        &n->socket.backlog,                                "Socket"  },
                { "ExecStartPre",           config_parse_exec,            &n->service.exec_command[SOCKET_EXEC_START_PRE],   "Socket"  },
                { "ExecStartPost",          config_parse_exec,            &n->service.exec_command[SOCKET_EXEC_START_POST],  "Socket"  },
                { "ExecStopPre",            config_parse_exec,            &n->service.exec_command[SOCKET_EXEC_STOP_PRE],    "Socket"  },
                { "ExecStopPost",           config_parse_exec,            &n->service.exec_command[SOCKET_EXEC_STOP_POST],   "Socket"  },
                EXEC_CONTEXT_CONFIG_ITEMS(n->socket.exec_context, "Socket"),

                EXEC_CONTEXT_CONFIG_ITEMS(n->automount.exec_context, "Automount"),

                { NULL, NULL, NULL, NULL }
        };

#undef EXEC_CONTEXT_CONFIG_ITEMS

        char *t;
        int r;
        const char *sections[3];
        Iterator i;

        assert(n);
        assert(n->meta.load_state == NAME_STUB);

        sections[0] = "Meta";
        sections[1] = section_table[n->meta.type];
        sections[2] = NULL;

        SET_FOREACH(t, n->meta.names, i) {

                /* Try to find a name we can load this with */
                if ((r = config_parse(t, sections, items, n)) == -ENOENT)
                        continue;

                /* Yay, we succeeded! Now let's call this our identifier */
                if (r == 0)
                        n->meta.id = t;

                return r;
        }

        return -ENOENT;
}
