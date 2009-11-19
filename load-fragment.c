/*-*- Mode: C; c-basic-offset: 8 -*-*/

#include <assert.h>
#include <errno.h>
#include <string.h>

#include "name.h"
#include "strv.h"
#include "conf-parser.h"
#include "load-fragment.h"

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

int name_load_fragment(Name *n) {

        const ConfigItem items[] = {
                { "Names",         config_parse_strv,   &n->meta.names,          "Meta" },
                { "Description",   config_parse_string, &n->meta.description,    "Meta" },
                { "Requires",      config_parse_names,  &n->meta.requires,       "Meta" },
                { "SoftRequires",  config_parse_names,  &n->meta.soft_requires,  "Meta" },
                { "Wants",         config_parse_names,  &n->meta.wants,          "Meta" },
                { "Requisite",     config_parse_names,  &n->meta.requisite,      "Meta" },
                { "SoftRequisite", config_parse_names,  &n->meta.soft_requisite, "Meta" },
                { "Conflicts",     config_parse_names,  &n->meta.conflicts,      "Meta" },
                { "Before",        config_parse_names,  &n->meta.before,         "Meta" },
                { "After",         config_parse_names,  &n->meta.after,          "Meta" },
                { NULL, NULL, NULL, NULL }
        };

        char **t, **l;
        int r;

        assert(n);
        assert(n->meta.state == NAME_STUB);

        /* We copy the strv here so that we can iterate through it
         * while being safe for modification */
        if (!(l = strv_copy(n->meta.names)))
                return -ENOMEM;

        STRV_FOREACH(t, n->meta.names)
                if ((r = config_parse(*t, items, n)) < 0)
                        goto fail;

        return 0;

fail:

        strv_free(l);
        return 0;
}
