/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <linux/oom.h>
#include <assert.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>

#include "unit.h"
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

        UnitDependency d = PTR_TO_UINT(data);
        Unit *u = userdata;
        char *w;
        size_t l;
        char *state;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        FOREACH_WORD(w, &l, rvalue, state) {
                char *t;
                int r;
                Unit *other;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                r = manager_load_unit(u->meta.manager, t, &other);
                free(t);

                if (r < 0)
                        return r;

                if ((r = unit_add_dependency(u, d, other)) < 0)
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

        Unit *u = userdata;
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
                Unit *other;

                if (!(t = strndup(w, l)))
                        return -ENOMEM;

                other = manager_get_unit(u->meta.manager, t);

                if (other) {

                        if (other != u) {

                                if (other->meta.load_state != UNIT_STUB) {
                                        free(t);
                                        return -EEXIST;
                                }

                                if ((r = unit_merge(u, other)) < 0) {
                                        free(t);
                                        return r;
                                }
                        }

                } else {
                        if ((r = unit_add_name(u, t)) < 0) {
                                free(t);
                                return r;
                        }
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

        if (!n[0] || !path_is_absolute(n[0])) {
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

#define FOLLOW_MAX 8

static char *build_path(const char *path, const char *filename) {
        char *e, *r;
        size_t k;

        assert(path);
        assert(filename);

        /* This removes the last component of path and appends
         * filename, unless the latter is absolute anyway or the
         * former isn't */

        if (path_is_absolute(filename))
                return strdup(filename);

        if (!(e = strrchr(path, '/')))
                return strdup(filename);

        k = strlen(filename);
        if (!(r = new(char, e-path+1+k+1)))
                return NULL;

        memcpy(r, path, e-path+1);
        memcpy(r+(e-path)+1, filename, k+1);

        return r;
}

static int open_follow(char **filename, FILE **_f, Set *names, char **_id) {
        unsigned c = 0;
        int fd, r;
        FILE *f;
        char *id = NULL;

        assert(filename);
        assert(*filename);
        assert(_f);
        assert(names);

        /* This will update the filename pointer if the loaded file is
         * reached by a symlink. The old string will be freed. */

        for (;;) {
                char *target, *k, *name;

                if (c++ >= FOLLOW_MAX)
                        return -ELOOP;

                /* Add the file name we are currently looking at to
                 * the names of this unit */
                name = file_name_from_path(*filename);
                if (!(id = set_get(names, name))) {

                        if (!(id = strdup(name)))
                                return -ENOMEM;

                        if ((r = set_put(names, id)) < 0) {
                                free(id);
                                return r;
                        }
                }

                /* Try to open the file name, but don't if its a symlink */
                if ((fd = open(*filename, O_RDONLY|O_CLOEXEC|O_NOCTTY|O_NOFOLLOW)) >= 0)
                        break;

                if (errno != ELOOP)
                        return -errno;

                /* Hmm, so this is a symlink. Let's read the name, and follow it manually */
                if ((r = readlink_malloc(*filename, &target)) < 0)
                        return r;

                k = build_path(*filename, target);
                free(target);

                if (!k)
                        return -ENOMEM;

                free(*filename);
                *filename = k;
        }

        if (!(f = fdopen(fd, "r"))) {
                r = -errno;
                assert(close_nointr(fd) == 0);
                return r;
        }

        *_f = f;
        *_id = id;
        return 0;
}

static int load_from_path(Unit *u, const char *path) {

        static const char* const section_table[_UNIT_TYPE_MAX] = {
                [UNIT_SERVICE]   = "Service",
                [UNIT_TIMER]     = "Timer",
                [UNIT_SOCKET]    = "Socket",
                [UNIT_TARGET]    = "Target",
                [UNIT_DEVICE]    = "Device",
                [UNIT_MOUNT]     = "Mount",
                [UNIT_AUTOMOUNT] = "Automount",
                [UNIT_SNAPSHOT]  = "Snapshot"
        };

#define EXEC_CONTEXT_CONFIG_ITEMS(context, section) \
                { "Directory",              config_parse_path,            &(context).directory,                            section   }, \
                { "User",                   config_parse_string,          &(context).user,                                 section   }, \
                { "Group",                  config_parse_string,          &(context).group,                                section   }, \
                { "SupplementaryGroups",    config_parse_strv,            &(context).supplementary_groups,                 section   }, \
                { "Nice",                   config_parse_nice,            &(context).nice,                                 section   }, \
                { "OOMAdjust",              config_parse_oom_adjust,      &(context).oom_adjust,                           section   }, \
                { "UMask",                  config_parse_umask,           &(context).umask,                                section   }, \
                { "Environment",            config_parse_strv,            &(context).environment,                          section   }

        const ConfigItem items[] = {
                { "Names",                  config_parse_names,           u,                                               "Meta"    },
                { "Description",            config_parse_string,          &u->meta.description,                            "Meta"    },
                { "Requires",               config_parse_deps,            UINT_TO_PTR(UNIT_REQUIRES),                      "Meta"    },
                { "SoftRequires",           config_parse_deps,            UINT_TO_PTR(UNIT_SOFT_REQUIRES),                 "Meta"    },
                { "Wants",                  config_parse_deps,            UINT_TO_PTR(UNIT_WANTS),                         "Meta"    },
                { "Requisite",              config_parse_deps,            UINT_TO_PTR(UNIT_REQUISITE),                     "Meta"    },
                { "SoftRequisite",          config_parse_deps,            UINT_TO_PTR(UNIT_SOFT_REQUISITE),                "Meta"    },
                { "Conflicts",              config_parse_deps,            UINT_TO_PTR(UNIT_CONFLICTS),                     "Meta"    },
                { "Before",                 config_parse_deps,            UINT_TO_PTR(UNIT_BEFORE),                        "Meta"    },
                { "After",                  config_parse_deps,            UINT_TO_PTR(UNIT_AFTER),                         "Meta"    },

                { "PIDFile",                config_parse_path,            &u->service.pid_file,                            "Service" },
                { "ExecStartPre",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_PRE,  "Service" },
                { "ExecStart",              config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START,      "Service" },
                { "ExecStartPost",          config_parse_exec,            u->service.exec_command+SERVICE_EXEC_START_POST, "Service" },
                { "ExecReload",             config_parse_exec,            u->service.exec_command+SERVICE_EXEC_RELOAD,     "Service" },
                { "ExecStop",               config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP,       "Service" },
                { "ExecStopPost",           config_parse_exec,            u->service.exec_command+SERVICE_EXEC_STOP_POST,  "Service" },
                { "RestartSec",             config_parse_usec,            &u->service.restart_usec,                        "Service" },
                { "TimeoutSec",             config_parse_usec,            &u->service.timeout_usec,                        "Service" },
                { "Type",                   config_parse_service_type,    &u->service,                                     "Service" },
                { "Restart",                config_parse_service_restart, &u->service,                                     "Service" },
                EXEC_CONTEXT_CONFIG_ITEMS(u->service.exec_context, "Service"),

                { "ListenStream",           config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenDatagram",         config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenSequentialPacket", config_parse_listen,          &u->socket,                                      "Socket"  },
                { "ListenFIFO",             config_parse_listen,          &u->socket,                                      "Socket"  },
                { "BindIPv6Only",           config_parse_socket_bind,     &u->socket,                                      "Socket"  },
                { "Backlog",                config_parse_unsigned,        &u->socket.backlog,                              "Socket"  },
                { "ExecStartPre",           config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_START_PRE,    "Socket"  },
                { "ExecStartPost",          config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_START_POST,   "Socket"  },
                { "ExecStopPre",            config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_STOP_PRE,     "Socket"  },
                { "ExecStopPost",           config_parse_exec,            u->socket.exec_command+SOCKET_EXEC_STOP_POST,    "Socket"  },
                EXEC_CONTEXT_CONFIG_ITEMS(u->socket.exec_context, "Socket"),

                EXEC_CONTEXT_CONFIG_ITEMS(u->automount.exec_context, "Automount"),

                { NULL, NULL, NULL, NULL }
        };

#undef EXEC_CONTEXT_CONFIG_ITEMS

        const char *sections[3];
        char *k;
        int r;
        Set *symlink_names;
        FILE *f;
        char *filename, *id;

        sections[0] = "Meta";
        sections[1] = section_table[u->meta.type];
        sections[2] = NULL;

        if (!(symlink_names = set_new(string_hash_func, string_compare_func)))
                return -ENOMEM;

        /* Instead of opening the path right away, we manually
         * follow all symlinks and add their name to our unit
         * name set while doing so */
        if (!(filename = path_make_absolute(path, unit_path()))) {
                r = -ENOMEM;
                goto finish;
        }

        if ((r = open_follow(&filename, &f, symlink_names, &id)) < 0) {
                if (r == -ENOENT)
                        r = 0; /* returning 0 means: no suitable config file found */

                goto finish;
        }

        /* Now, parse the file contents */
        r = config_parse(filename, f, sections, items, u);
        if (r < 0)
                goto finish;

        /* Let's try to add in all symlink names we found */
        while ((k = set_steal_first(symlink_names))) {
                if ((r = unit_add_name(u, k)) < 0)
                        goto finish;

                if (id == k)
                        assert_se(u->meta.id = set_get(u->meta.names, k));

                free(k);
        }

        free(u->meta.load_path);
        u->meta.load_path = filename;
        filename = NULL;

        r = 1; /* returning 1 means: suitable config file found and loaded */

finish:
        while ((k = set_steal_first(symlink_names)))
                free(k);
        set_free(symlink_names);
        free(filename);

        return r;
}

int unit_load_fragment(Unit *u) {
        int r = -ENOENT;

        assert(u);
        assert(u->meta.load_state == UNIT_STUB);

        if (u->meta.load_path)
                r = load_from_path(u, u->meta.load_path);
        else {
                Iterator i;
                char *t;

                /* Try to find a name we can load this with */
                SET_FOREACH(t, u->meta.names, i)
                        if ((r = load_from_path(u, t)) != 0)
                                return r;
        }

        return r;
}
