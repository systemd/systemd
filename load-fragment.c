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

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if ((r = address_parse(data, rvalue)) < 0) {
                log_error("[%s:%u] Failed to parse address value: %s", filename, line, rvalue);
                return r;
        }

        return 0;
}

static int config_parse_type(
                const char *filename,
                unsigned line,
                const char *section,
                const char *lvalue,
                const char *rvalue,
                void *data,
                void *userdata) {

        int *type = data;

        assert(filename);
        assert(lvalue);
        assert(rvalue);
        assert(data);

        if (streq(rvalue, "stream"))
                *type = SOCK_STREAM;
        else if (streq(rvalue, "dgram"))
                *type = SOCK_DGRAM;
        else {
                log_error("[%s:%u] Failed to parse socket type value: %s", filename, line, rvalue);
                return -EINVAL;
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

        const ConfigItem items[] = {
                { "Names",         config_parse_names,  &n->meta.names,                           "Meta"   },
                { "Description",   config_parse_string, &n->meta.description,                     "Meta"   },
                { "Requires",      config_parse_deps,   n->meta.dependencies+NAME_REQUIRES,       "Meta"   },
                { "SoftRequires",  config_parse_deps,   n->meta.dependencies+NAME_SOFT_REQUIRES,  "Meta"   },
                { "Wants",         config_parse_deps,   n->meta.dependencies+NAME_WANTS,          "Meta"   },
                { "Requisite",     config_parse_deps,   n->meta.dependencies+NAME_REQUISITE,      "Meta"   },
                { "SoftRequisite", config_parse_deps,   n->meta.dependencies+NAME_SOFT_REQUISITE, "Meta"   },
                { "Conflicts",     config_parse_deps,   n->meta.dependencies+NAME_CONFLICTS,      "Meta"   },
                { "Before",        config_parse_deps,   n->meta.dependencies+NAME_BEFORE,         "Meta"   },
                { "After",         config_parse_deps,   n->meta.dependencies+NAME_AFTER,          "Meta"   },
                { "Listen",        config_parse_listen, &n->socket.address,                       "Socket" },
                { "Type",          config_parse_type,   &n->socket.address.type,                  "Socket" },
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
