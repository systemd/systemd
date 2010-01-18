/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "name.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"

int config_parse_deps(
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

int config_parse_names(
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

                                if (other->meta.state != NAME_STUB) {
                                        free(t);
                                        return -EEXIST;
                                }

                                if ((r = name_merge(name, other) < 0)) {
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
                }

                free(t);
        }

        return 0;
}

int name_load_fragment(Name *n) {

        const ConfigItem items[] = {
                { "Names",         config_parse_names,  &n->meta.names,                           "Meta" },
                { "Description",   config_parse_string, &n->meta.description,                     "Meta" },
                { "Requires",      config_parse_deps,   n->meta.dependencies+NAME_REQUIRES,       "Meta" },
                { "SoftRequires",  config_parse_deps,   n->meta.dependencies+NAME_SOFT_REQUIRES,  "Meta" },
                { "Wants",         config_parse_deps,   n->meta.dependencies+NAME_WANTS,          "Meta" },
                { "Requisite",     config_parse_deps,   n->meta.dependencies+NAME_REQUISITE,      "Meta" },
                { "SoftRequisite", config_parse_deps,   n->meta.dependencies+NAME_SOFT_REQUISITE, "Meta" },
                { "Conflicts",     config_parse_deps,   n->meta.dependencies+NAME_CONFLICTS,      "Meta" },
                { "Before",        config_parse_deps,   n->meta.dependencies+NAME_BEFORE,         "Meta" },
                { "After",         config_parse_deps,   n->meta.dependencies+NAME_AFTER,          "Meta" },
                { NULL, NULL, NULL, NULL }
        };

        char *t;
        int r;
        void *state;

        assert(n);
        assert(n->meta.state == NAME_STUB);

        SET_FOREACH(t, n->meta.names, state)
                if ((r = config_parse(t, items, n)) < 0)
                        goto fail;

        r = 0;

fail:
        return r;
}
