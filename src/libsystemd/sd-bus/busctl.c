/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <getopt.h>

#include "strv.h"
#include "util.h"
#include "log.h"
#include "build.h"
#include "pager.h"
#include "path-util.h"
#include "set.h"

#include "sd-bus.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "bus-dump.h"
#include "bus-signature.h"
#include "bus-type.h"
#include "busctl-introspect.h"
#include "terminal-util.h"

static bool arg_no_pager = false;
static bool arg_legend = true;
static char *arg_address = NULL;
static bool arg_unique = false;
static bool arg_acquired = false;
static bool arg_activatable = false;
static bool arg_show_machine = false;
static char **arg_matches = NULL;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static char *arg_host = NULL;
static bool arg_user = false;
static size_t arg_snaplen = 4096;
static bool arg_list = false;
static bool arg_quiet = false;
static bool arg_verbose = false;
static bool arg_expect_reply = true;
static bool arg_auto_start = true;
static bool arg_allow_interactive_authorization = true;
static bool arg_augment_creds = true;
static usec_t arg_timeout = 0;

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

#define NAME_IS_ACQUIRED INT_TO_PTR(1)
#define NAME_IS_ACTIVATABLE INT_TO_PTR(2)

static int list_bus_names(sd_bus *bus, char **argv) {
        _cleanup_strv_free_ char **acquired = NULL, **activatable = NULL;
        _cleanup_free_ char **merged = NULL;
        _cleanup_hashmap_free_ Hashmap *names = NULL;
        char **i;
        int r;
        size_t max_i = 0;
        unsigned n = 0;
        void *v;
        char *k;
        Iterator iterator;

        assert(bus);

        if (!arg_unique && !arg_acquired && !arg_activatable)
                arg_unique = arg_acquired = arg_activatable = true;

        r = sd_bus_list_names(bus, (arg_acquired || arg_unique) ? &acquired : NULL, arg_activatable ? &activatable : NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list names: %m");

        pager_open_if_enabled();

        names = hashmap_new(&string_hash_ops);
        if (!names)
                return log_oom();

        STRV_FOREACH(i, acquired) {
                max_i = MAX(max_i, strlen(*i));

                r = hashmap_put(names, *i, NAME_IS_ACQUIRED);
                if (r < 0)
                        return log_error_errno(r, "Failed to add to hashmap: %m");
        }

        STRV_FOREACH(i, activatable) {
                max_i = MAX(max_i, strlen(*i));

                r = hashmap_put(names, *i, NAME_IS_ACTIVATABLE);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to add to hashmap: %m");
        }

        merged = new(char*, hashmap_size(names) + 1);
        HASHMAP_FOREACH_KEY(v, k, names, iterator)
                merged[n++] = k;

        merged[n] = NULL;
        strv_sort(merged);

        if (arg_legend) {
                printf("%-*s %*s %-*s %-*s %-*s %-*s %-*s %-*s",
                       (int) max_i, "NAME", 10, "PID", 15, "PROCESS", 16, "USER", 13, "CONNECTION", 25, "UNIT", 10, "SESSION", 19, "DESCRIPTION");

                if (arg_show_machine)
                        puts(" MACHINE");
                else
                        putchar('\n');
        }

        STRV_FOREACH(i, merged) {
                _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
                sd_id128_t mid;

                if (hashmap_get(names, *i) == NAME_IS_ACTIVATABLE) {
                        /* Activatable */

                        printf("%-*s", (int) max_i, *i);
                        printf("          - -               -                (activatable) -                         -         ");
                        if (arg_show_machine)
                                puts(" -");
                        else
                                putchar('\n');
                        continue;

                }

                if (!arg_unique && (*i)[0] == ':')
                        continue;

                if (!arg_acquired && (*i)[0] != ':')
                        continue;

                printf("%-*s", (int) max_i, *i);

                r = sd_bus_get_name_creds(
                                bus, *i,
                                (arg_augment_creds ? SD_BUS_CREDS_AUGMENT : 0) |
                                SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|
                                SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_SESSION|
                                SD_BUS_CREDS_DESCRIPTION, &creds);
                if (r >= 0) {
                        const char *unique, *session, *unit, *cn;
                        pid_t pid;
                        uid_t uid;

                        r = sd_bus_creds_get_pid(creds, &pid);
                        if (r >= 0) {
                                const char *comm = NULL;

                                sd_bus_creds_get_comm(creds, &comm);

                                printf(" %10lu %-15s", (unsigned long) pid, strna(comm));
                        } else
                                fputs("          - -              ", stdout);

                        r = sd_bus_creds_get_euid(creds, &uid);
                        if (r >= 0) {
                                _cleanup_free_ char *u = NULL;

                                u = uid_to_name(uid);
                                if (!u)
                                        return log_oom();

                                if (strlen(u) > 16)
                                        u[16] = 0;

                                printf(" %-16s", u);
                        } else
                                fputs(" -               ", stdout);

                        r = sd_bus_creds_get_unique_name(creds, &unique);
                        if (r >= 0)
                                printf(" %-13s", unique);
                        else
                                fputs(" -            ", stdout);

                        r = sd_bus_creds_get_unit(creds, &unit);
                        if (r >= 0) {
                                _cleanup_free_ char *e;

                                e = ellipsize(unit, 25, 100);
                                if (!e)
                                        return log_oom();

                                printf(" %-25s", e);
                        } else
                                fputs(" -                        ", stdout);

                        r = sd_bus_creds_get_session(creds, &session);
                        if (r >= 0)
                                printf(" %-10s", session);
                        else
                                fputs(" -         ", stdout);

                        r = sd_bus_creds_get_description(creds, &cn);
                        if (r >= 0)
                                printf(" %-19s", cn);
                        else
                                fputs(" -                  ", stdout);

                } else
                        printf("          - -               -                -             -                         -          -                  ");

                if (arg_show_machine) {
                        r = sd_bus_get_name_machine_id(bus, *i, &mid);
                        if (r >= 0) {
                                char m[SD_ID128_STRING_MAX];
                                printf(" %s\n", sd_id128_to_string(mid, m));
                        } else
                                puts(" -");
                } else
                        putchar('\n');
        }

        return 0;
}

static void print_subtree(const char *prefix, const char *path, char **l) {
        const char *vertical, *space;
        char **n;

        /* We assume the list is sorted. Let's first skip over the
         * entry we are looking at. */
        for (;;) {
                if (!*l)
                        return;

                if (!streq(*l, path))
                        break;

                l++;
        }

        vertical = strjoina(prefix, draw_special_char(DRAW_TREE_VERTICAL));
        space = strjoina(prefix, draw_special_char(DRAW_TREE_SPACE));

        for (;;) {
                bool has_more = false;

                if (!*l || !path_startswith(*l, path))
                        break;

                n = l + 1;
                for (;;) {
                        if (!*n || !path_startswith(*n, path))
                                break;

                        if (!path_startswith(*n, *l)) {
                                has_more = true;
                                break;
                        }

                        n++;
                }

                printf("%s%s%s\n", prefix, draw_special_char(has_more ? DRAW_TREE_BRANCH : DRAW_TREE_RIGHT), *l);

                print_subtree(has_more ? vertical : space, *l, l);
                l = n;
        }
}

static void print_tree(const char *prefix, char **l) {

        pager_open_if_enabled();

        prefix = strempty(prefix);

        if (arg_list) {
                char **i;

                STRV_FOREACH(i, l)
                        printf("%s%s\n", prefix, *i);
                return;
        }

        if (strv_isempty(l)) {
                printf("No objects discovered.\n");
                return;
        }

        if (streq(l[0], "/") && !l[1]) {
                printf("Only root object discovered.\n");
                return;
        }

        print_subtree(prefix, "/", l);
}

static int on_path(const char *path, void *userdata) {
        Set *paths = userdata;
        int r;

        assert(paths);

        r = set_put_strdup(paths, path);
        if (r < 0)
                return log_oom();

        return 0;
}

static int find_nodes(sd_bus *bus, const char *service, const char *path, Set *paths, bool many) {
        static const XMLIntrospectOps ops = {
                .on_path = on_path,
        };

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *xml;
        int r;

        r = sd_bus_call_method(bus, service, path, "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        if (r < 0) {
                if (many)
                        printf("Failed to introspect object %s of service %s: %s\n", path, service, bus_error_message(&error, r));
                else
                        log_error("Failed to introspect object %s of service %s: %s", path, service, bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        return parse_xml_introspect(path, xml, &ops, paths);
}

static int tree_one(sd_bus *bus, const char *service, const char *prefix, bool many) {
        _cleanup_set_free_free_ Set *paths = NULL, *done = NULL, *failed = NULL;
        _cleanup_free_ char **l = NULL;
        char *m;
        int r;

        paths = set_new(&string_hash_ops);
        if (!paths)
                return log_oom();

        done = set_new(&string_hash_ops);
        if (!done)
                return log_oom();

        failed = set_new(&string_hash_ops);
        if (!failed)
                return log_oom();

        m = strdup("/");
        if (!m)
                return log_oom();

        r = set_put(paths, m);
        if (r < 0) {
                free(m);
                return log_oom();
        }

        for (;;) {
                _cleanup_free_ char *p = NULL;
                int q;

                p = set_steal_first(paths);
                if (!p)
                        break;

                if (set_contains(done, p) ||
                    set_contains(failed, p))
                        continue;

                q = find_nodes(bus, service, p, paths, many);
                if (q < 0) {
                        if (r >= 0)
                                r = q;

                        q = set_put(failed, p);
                } else
                        q = set_put(done, p);

                if (q < 0)
                        return log_oom();

                assert(q != 0);
                p = NULL;
        }

        pager_open_if_enabled();

        l = set_get_strv(done);
        if (!l)
                return log_oom();

        strv_sort(l);
        print_tree(prefix, l);

        fflush(stdout);

        return r;
}

static int tree(sd_bus *bus, char **argv) {
        char **i;
        int r = 0;

        if (!arg_unique && !arg_acquired)
                arg_acquired = true;

        if (strv_length(argv) <= 1) {
                _cleanup_strv_free_ char **names = NULL;
                bool not_first = false;

                r = sd_bus_list_names(bus, &names, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to get name list: %m");

                pager_open_if_enabled();

                STRV_FOREACH(i, names) {
                        int q;

                        if (!arg_unique && (*i)[0] == ':')
                                continue;

                        if (!arg_acquired && (*i)[0] == ':')
                                continue;

                        if (not_first)
                                printf("\n");

                        printf("Service %s%s%s:\n", ansi_highlight(), *i, ansi_highlight_off());

                        q = tree_one(bus, *i, NULL, true);
                        if (q < 0 && r >= 0)
                                r = q;

                        not_first = true;
                }
        } else {
                STRV_FOREACH(i, argv+1) {
                        int q;

                        if (i > argv+1)
                                printf("\n");

                        if (argv[2]) {
                                pager_open_if_enabled();
                                printf("Service %s%s%s:\n", ansi_highlight(), *i, ansi_highlight_off());
                        }

                        q = tree_one(bus, *i, NULL, !!argv[2]);
                        if (q < 0 && r >= 0)
                                r = q;
                }
        }

        return r;
}

static int format_cmdline(sd_bus_message *m, FILE *f, bool needs_space) {
        int r;

        for (;;) {
                const char *contents = NULL;
                char type;
                union {
                        uint8_t u8;
                        uint16_t u16;
                        int16_t s16;
                        uint32_t u32;
                        int32_t s32;
                        uint64_t u64;
                        int64_t s64;
                        double d64;
                        const char *string;
                        int i;
                } basic;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r <= 0)
                        return r;

                if (bus_type_is_container(type) > 0) {

                        r = sd_bus_message_enter_container(m, type, contents);
                        if (r < 0)
                                return r;

                        if (type == SD_BUS_TYPE_ARRAY) {
                                unsigned n = 0;

                                /* count array entries */
                                for (;;) {

                                        r = sd_bus_message_skip(m, contents);
                                        if (r < 0)
                                                return r;
                                        if (r == 0)
                                                break;

                                        n++;
                                }

                                r = sd_bus_message_rewind(m, false);
                                if (r < 0)
                                        return r;

                                if (needs_space)
                                        fputc(' ', f);

                                fprintf(f, "%u", n);
                        } else if (type == SD_BUS_TYPE_VARIANT) {

                                if (needs_space)
                                        fputc(' ', f);

                                fprintf(f, "%s", contents);
                        }

                        r = format_cmdline(m, f, needs_space || IN_SET(type, SD_BUS_TYPE_ARRAY, SD_BUS_TYPE_VARIANT));
                        if (r < 0)
                                return r;

                        r = sd_bus_message_exit_container(m);
                        if (r < 0)
                                return r;

                        continue;
                }

                r = sd_bus_message_read_basic(m, type, &basic);
                if (r < 0)
                        return r;

                if (needs_space)
                        fputc(' ', f);

                switch (type) {
                case SD_BUS_TYPE_BYTE:
                        fprintf(f, "%u", basic.u8);
                        break;

                case SD_BUS_TYPE_BOOLEAN:
                        fputs(true_false(basic.i), f);
                        break;

                case SD_BUS_TYPE_INT16:
                        fprintf(f, "%i", basic.s16);
                        break;

                case SD_BUS_TYPE_UINT16:
                        fprintf(f, "%u", basic.u16);
                        break;

                case SD_BUS_TYPE_INT32:
                        fprintf(f, "%i", basic.s32);
                        break;

                case SD_BUS_TYPE_UINT32:
                        fprintf(f, "%u", basic.u32);
                        break;

                case SD_BUS_TYPE_INT64:
                        fprintf(f, "%" PRIi64, basic.s64);
                        break;

                case SD_BUS_TYPE_UINT64:
                        fprintf(f, "%" PRIu64, basic.u64);
                        break;

                case SD_BUS_TYPE_DOUBLE:
                        fprintf(f, "%g", basic.d64);
                        break;

                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE: {
                        _cleanup_free_ char *b = NULL;

                        b = cescape(basic.string);
                        if (!b)
                                return -ENOMEM;

                        fprintf(f, "\"%s\"", b);
                        break;
                }

                case SD_BUS_TYPE_UNIX_FD:
                        fprintf(f, "%i", basic.i);
                        break;

                default:
                        assert_not_reached("Unknown basic type.");
                }

                needs_space = true;
        }
}

typedef struct Member {
        const char *type;
        char *interface;
        char *name;
        char *signature;
        char *result;
        char *value;
        bool writable;
        uint64_t flags;
} Member;

static unsigned long member_hash_func(const void *p, const uint8_t hash_key[]) {
        const Member *m = p;
        unsigned long ul;

        assert(m);
        assert(m->type);

        ul = string_hash_func(m->type, hash_key);

        if (m->name)
                ul ^= string_hash_func(m->name, hash_key);

        if (m->interface)
                ul ^= string_hash_func(m->interface, hash_key);

        return ul;
}

static int member_compare_func(const void *a, const void *b) {
        const Member *x = a, *y = b;
        int d;

        assert(x);
        assert(y);
        assert(x->type);
        assert(y->type);

        if (!x->interface && y->interface)
                return -1;
        if (x->interface && !y->interface)
                return 1;
        if (x->interface && y->interface) {
                d = strcmp(x->interface, y->interface);
                if (d != 0)
                        return d;
        }

        d = strcmp(x->type, y->type);
        if (d != 0)
                return d;

        if (!x->name && y->name)
                return -1;
        if (x->name && !y->name)
                return 1;
        if (x->name && y->name)
                return strcmp(x->name, y->name);

        return 0;
}

static int member_compare_funcp(const void *a, const void *b) {
        const Member *const * x = (const Member *const *) a, * const *y = (const Member *const *) b;

        return member_compare_func(*x, *y);
}

static void member_free(Member *m) {
        if (!m)
                return;

        free(m->interface);
        free(m->name);
        free(m->signature);
        free(m->result);
        free(m->value);
        free(m);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Member*, member_free);

static void member_set_free(Set *s) {
        Member *m;

        while ((m = set_steal_first(s)))
                member_free(m);

        set_free(s);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, member_set_free);

static int on_interface(const char *interface, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(members);

        m = new0(Member, 1);
        if (!m)
                return log_oom();

        m->type = "interface";
        m->flags = flags;

        r = free_and_strdup(&m->interface, interface);
        if (r < 0)
                return log_oom();

        r = set_put(members, m);
        if (r <= 0) {
                log_error("Duplicate interface");
                return -EINVAL;
        }

        m = NULL;
        return 0;
}

static int on_method(const char *interface, const char *name, const char *signature, const char *result, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new0(Member, 1);
        if (!m)
                return log_oom();

        m->type = "method";
        m->flags = flags;

        r = free_and_strdup(&m->interface, interface);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->name, name);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->signature, signature);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->result, result);
        if (r < 0)
                return log_oom();

        r = set_put(members, m);
        if (r <= 0) {
                log_error("Duplicate method");
                return -EINVAL;
        }

        m = NULL;
        return 0;
}

static int on_signal(const char *interface, const char *name, const char *signature, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new0(Member, 1);
        if (!m)
                return log_oom();

        m->type = "signal";
        m->flags = flags;

        r = free_and_strdup(&m->interface, interface);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->name, name);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->signature, signature);
        if (r < 0)
                return log_oom();

        r = set_put(members, m);
        if (r <= 0) {
                log_error("Duplicate signal");
                return -EINVAL;
        }

        m = NULL;
        return 0;
}

static int on_property(const char *interface, const char *name, const char *signature, bool writable, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new0(Member, 1);
        if (!m)
                return log_oom();

        m->type = "property";
        m->flags = flags;
        m->writable = writable;

        r = free_and_strdup(&m->interface, interface);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->name, name);
        if (r < 0)
                return log_oom();

        r = free_and_strdup(&m->signature, signature);
        if (r < 0)
                return log_oom();

        r = set_put(members, m);
        if (r <= 0) {
                log_error("Duplicate property");
                return -EINVAL;
        }

        m = NULL;
        return 0;
}

static const char *strdash(const char *x) {
        return isempty(x) ? "-" : x;
}

static int introspect(sd_bus *bus, char **argv) {
        static const struct hash_ops member_hash_ops = {
                .hash = member_hash_func,
                .compare = member_compare_func,
        };

        static const XMLIntrospectOps ops = {
                .on_interface = on_interface,
                .on_method = on_method,
                .on_signal = on_signal,
                .on_property = on_property,
        };

        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(member_set_freep) Set *members = NULL;
        Iterator i;
        Member *m;
        const char *xml;
        int r;
        unsigned name_width,  type_width, signature_width, result_width;
        Member **sorted = NULL;
        unsigned k = 0, j, n_args;

        n_args = strv_length(argv);
        if (n_args < 3) {
                log_error("Requires service and object path argument.");
                return -EINVAL;
        }

        if (n_args > 4) {
                log_error("Too many arguments.");
                return -EINVAL;
        }

        members = set_new(&member_hash_ops);
        if (!members)
                return log_oom();

        r = sd_bus_call_method(bus, argv[1], argv[2], "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        if (r < 0) {
                log_error("Failed to introspect object %s of service %s: %s", argv[2], argv[1], bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        /* First, get list of all properties */
        r = parse_xml_introspect(argv[2], xml, &ops, members);
        if (r < 0)
                return r;

        /* Second, find the current values for them */
        SET_FOREACH(m, members, i) {

                if (!streq(m->type, "property"))
                        continue;

                if (m->value)
                        continue;

                if (argv[3] && !streq(argv[3], m->interface))
                        continue;

                r = sd_bus_call_method(bus, argv[1], argv[2], "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", m->interface);
                if (r < 0) {
                        log_error("%s", bus_error_message(&error, r));
                        return r;
                }

                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                if (r < 0)
                        return bus_log_parse_error(r);

                for (;;) {
                        Member *z;
                        _cleanup_free_ char *buf = NULL;
                        _cleanup_fclose_ FILE *mf = NULL;
                        size_t sz = 0;
                        const char *name;

                        r = sd_bus_message_enter_container(reply, 'e', "sv");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (r == 0)
                                break;

                        r = sd_bus_message_read(reply, "s", &name);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_enter_container(reply, 'v', NULL);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        mf = open_memstream(&buf, &sz);
                        if (!mf)
                                return log_oom();

                        r = format_cmdline(reply, mf, false);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        fclose(mf);
                        mf = NULL;

                        z = set_get(members, &((Member) {
                                                .type = "property",
                                                .interface = m->interface,
                                                .name = (char*) name }));
                        if (z) {
                                free(z->value);
                                z->value = buf;
                                buf = NULL;
                        }

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        pager_open_if_enabled();

        name_width = strlen("NAME");
        type_width = strlen("TYPE");
        signature_width = strlen("SIGNATURE");
        result_width = strlen("RESULT/VALUE");

        sorted = newa(Member*, set_size(members));

        SET_FOREACH(m, members, i) {

                if (argv[3] && !streq(argv[3], m->interface))
                        continue;

                if (m->interface)
                        name_width = MAX(name_width, strlen(m->interface));
                if (m->name)
                        name_width = MAX(name_width, strlen(m->name) + 1);
                if (m->type)
                        type_width = MAX(type_width, strlen(m->type));
                if (m->signature)
                        signature_width = MAX(signature_width, strlen(m->signature));
                if (m->result)
                        result_width = MAX(result_width, strlen(m->result));
                if (m->value)
                        result_width = MAX(result_width, strlen(m->value));

                sorted[k++] = m;
        }

        if (result_width > 40)
                result_width = 40;

        qsort(sorted, k, sizeof(Member*), member_compare_funcp);

        if (arg_legend) {
                printf("%-*s %-*s %-*s %-*s %s\n",
                       (int) name_width, "NAME",
                       (int) type_width, "TYPE",
                       (int) signature_width, "SIGNATURE",
                       (int) result_width, "RESULT/VALUE",
                       "FLAGS");
        }

        for (j = 0; j < k; j++) {
                _cleanup_free_ char *ellipsized = NULL;
                const char *rv;
                bool is_interface;

                m = sorted[j];

                if (argv[3] && !streq(argv[3], m->interface))
                        continue;

                is_interface = streq(m->type, "interface");

                if (argv[3] && is_interface)
                        continue;

                if (m->value) {
                        ellipsized = ellipsize(m->value, result_width, 100);
                        if (!ellipsized)
                                return log_oom();

                        rv = ellipsized;
                } else
                        rv = strdash(m->result);

                printf("%s%s%-*s%s %-*s %-*s %-*s%s%s%s%s%s%s\n",
                       is_interface ? ansi_highlight() : "",
                       is_interface ? "" : ".",
                       - !is_interface + (int) name_width, strdash(streq_ptr(m->type, "interface") ? m->interface : m->name),
                       is_interface ? ansi_highlight_off() : "",
                       (int) type_width, strdash(m->type),
                       (int) signature_width, strdash(m->signature),
                       (int) result_width, rv,
                       (m->flags & SD_BUS_VTABLE_DEPRECATED) ? " deprecated" : (m->flags || m->writable ? "" : " -"),
                       (m->flags & SD_BUS_VTABLE_METHOD_NO_REPLY) ? " no-reply" : "",
                       (m->flags & SD_BUS_VTABLE_PROPERTY_CONST) ? " const" : "",
                       (m->flags & SD_BUS_VTABLE_PROPERTY_EMITS_CHANGE) ? " emits-change" : "",
                       (m->flags & SD_BUS_VTABLE_PROPERTY_EMITS_INVALIDATION) ? " emits-invalidation" : "",
                       m->writable ? " writable" : "");
        }

        return 0;
}

static int message_dump(sd_bus_message *m, FILE *f) {
        return bus_message_dump(m, f, BUS_MESSAGE_DUMP_WITH_HEADER);
}

static int message_pcap(sd_bus_message *m, FILE *f) {
        return bus_message_pcap_frame(m, arg_snaplen, f);
}

static int monitor(sd_bus *bus, char *argv[], int (*dump)(sd_bus_message *m, FILE *f)) {
        bool added_something = false;
        char **i;
        int r;

        STRV_FOREACH(i, argv+1) {
                _cleanup_free_ char *m = NULL;

                if (!service_name_is_valid(*i)) {
                        log_error("Invalid service name '%s'", *i);
                        return -EINVAL;
                }

                m = strjoin("sender='", *i, "'", NULL);
                if (!m)
                        return log_oom();

                r = sd_bus_add_match(bus, NULL, m, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");

                added_something = true;
        }

        STRV_FOREACH(i, arg_matches) {
                r = sd_bus_add_match(bus, NULL, *i, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");

                added_something = true;
        }

        if (!added_something) {
                r = sd_bus_add_match(bus, NULL, "", NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to add match: %m");
        }

        log_info("Monitoring bus message stream.");

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus: %m");

                if (m) {
                        dump(m, stdout);

                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected") > 0) {
                                log_info("Connection terminated, exiting.");
                                return 0;
                        }

                        continue;
                }

                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for bus: %m");
        }
}

static int capture(sd_bus *bus, char *argv[]) {
        int r;

        if (isatty(fileno(stdout)) > 0) {
                log_error("Refusing to write message data to console, please redirect output to a file.");
                return -EINVAL;
        }

        bus_pcap_header(arg_snaplen, stdout);

        r = monitor(bus, argv, message_pcap);
        if (r < 0)
                return r;

        if (ferror(stdout)) {
                log_error("Couldn't write capture file.");
                return -EIO;
        }

        return r;
}

static int status(sd_bus *bus, char *argv[]) {
        _cleanup_bus_creds_unref_ sd_bus_creds *creds = NULL;
        pid_t pid;
        int r;

        assert(bus);

        if (strv_length(argv) > 2) {
                log_error("Expects no or one argument.");
                return -EINVAL;
        }

        if (argv[1]) {
                r = parse_pid(argv[1], &pid);
                if (r < 0)
                        r = sd_bus_get_name_creds(
                                        bus,
                                        argv[1],
                                        (arg_augment_creds ? SD_BUS_CREDS_AUGMENT : 0) | _SD_BUS_CREDS_ALL,
                                        &creds);
                else
                        r = sd_bus_creds_new_from_pid(
                                        &creds,
                                        pid,
                                        _SD_BUS_CREDS_ALL);
        } else {
                const char *scope, *address;
                sd_id128_t bus_id;

                r = sd_bus_get_address(bus, &address);
                if (r >= 0)
                        printf("BusAddress=%s%s%s\n", ansi_highlight(), address, ansi_highlight_off());

                r = sd_bus_get_scope(bus, &scope);
                if (r >= 0)
                        printf("BusScope=%s%s%s\n", ansi_highlight(), scope, ansi_highlight_off());

                r = sd_bus_get_bus_id(bus, &bus_id);
                if (r >= 0)
                        printf("BusID=%s" SD_ID128_FORMAT_STR "%s\n", ansi_highlight(), SD_ID128_FORMAT_VAL(bus_id), ansi_highlight_off());

                r = sd_bus_get_owner_creds(
                                bus,
                                (arg_augment_creds ? SD_BUS_CREDS_AUGMENT : 0) | _SD_BUS_CREDS_ALL,
                                &creds);
        }

        if (r < 0)
                return log_error_errno(r, "Failed to get credentials: %m");

        bus_creds_dump(creds, NULL, false);
        return 0;
}

static int message_append_cmdline(sd_bus_message *m, const char *signature, char ***x) {
        char **p;
        int r;

        assert(m);
        assert(signature);
        assert(x);

        p = *x;

        for (;;) {
                const char *v;
                char t;

                t = *signature;
                v = *p;

                if (t == 0)
                        break;
                if (!v) {
                        log_error("Too few parameters for signature.");
                        return -EINVAL;
                }

                signature++;
                p++;

                switch (t) {

                case SD_BUS_TYPE_BOOLEAN:

                        r = parse_boolean(v);
                        if (r < 0) {
                                log_error("Failed to parse as boolean: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &r);
                        break;

                case SD_BUS_TYPE_BYTE: {
                        uint8_t z;

                        r = safe_atou8(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as byte (unsigned 8bit integer): %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT16: {
                        int16_t z;

                        r = safe_atoi16(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as signed 16bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT16: {
                        uint16_t z;

                        r = safe_atou16(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as unsigned 16bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT32: {
                        int32_t z;

                        r = safe_atoi32(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as signed 32bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT32: {
                        uint32_t z;

                        r = safe_atou32(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as unsigned 32bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT64: {
                        int64_t z;

                        r = safe_atoi64(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as signed 64bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT64: {
                        uint64_t z;

                        r = safe_atou64(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as unsigned 64bit integer: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }


                case SD_BUS_TYPE_DOUBLE: {
                        double z;

                        r = safe_atod(v, &z);
                        if (r < 0) {
                                log_error("Failed to parse as double precision floating point: %s", v);
                                return r;
                        }

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_STRING:
                case SD_BUS_TYPE_OBJECT_PATH:
                case SD_BUS_TYPE_SIGNATURE:

                        r = sd_bus_message_append_basic(m, t, v);
                        break;

                case SD_BUS_TYPE_ARRAY: {
                        uint32_t n;
                        size_t k;

                        r = safe_atou32(v, &n);
                        if (r < 0) {
                                log_error("Failed to parse number of array entries: %s", v);
                                return r;
                        }

                        r = signature_element_length(signature, &k);
                        if (r < 0) {
                                log_error("Invalid array signature.");
                                return r;
                        }

                        {
                                unsigned i;
                                char s[k + 1];
                                memcpy(s, signature, k);
                                s[k] = 0;

                                r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, s);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                for (i = 0; i < n; i++) {
                                        r = message_append_cmdline(m, s, &p);
                                        if (r < 0)
                                                return r;
                                }
                        }

                        signature += k;

                        r = sd_bus_message_close_container(m);
                        break;
                }

                case SD_BUS_TYPE_VARIANT:
                        r = sd_bus_message_open_container(m, SD_BUS_TYPE_VARIANT, v);
                        if (r < 0)
                                return bus_log_create_error(r);

                        r = message_append_cmdline(m, v, &p);
                        if (r < 0)
                                return r;

                        r = sd_bus_message_close_container(m);
                        break;

                case SD_BUS_TYPE_STRUCT_BEGIN:
                case SD_BUS_TYPE_DICT_ENTRY_BEGIN: {
                        size_t k;

                        signature--;
                        p--;

                        r = signature_element_length(signature, &k);
                        if (r < 0) {
                                log_error("Invalid struct/dict entry signature.");
                                return r;
                        }

                        {
                                char s[k-1];
                                memcpy(s, signature + 1, k - 2);
                                s[k - 2] = 0;

                                r = sd_bus_message_open_container(m, t == SD_BUS_TYPE_STRUCT_BEGIN ? SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY, s);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                r = message_append_cmdline(m, s, &p);
                                if (r < 0)
                                        return r;
                        }

                        signature += k;

                        r = sd_bus_message_close_container(m);
                        break;
                }

                case SD_BUS_TYPE_UNIX_FD:
                        log_error("UNIX file descriptor not supported as type.");
                        return -EINVAL;

                default:
                        log_error("Unknown signature type %c.", t);
                        return -EINVAL;
                }

                if (r < 0)
                        return bus_log_create_error(r);
        }

        *x = p;
        return 0;
}

static int call(sd_bus *bus, char *argv[]) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL, *reply = NULL;
        int r;

        assert(bus);

        if (strv_length(argv) < 5) {
                log_error("Expects at least four arguments.");
                return -EINVAL;
        }

        r = sd_bus_message_new_method_call(bus, &m, argv[1], argv[2], argv[3], argv[4]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_expect_reply(m, arg_expect_reply);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_auto_start(m, arg_auto_start);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_set_allow_interactive_authorization(m, arg_allow_interactive_authorization);
        if (r < 0)
                return bus_log_create_error(r);

        if (!isempty(argv[5])) {
                char **p;

                p = argv+6;

                r = message_append_cmdline(m, argv[5], &p);
                if (r < 0)
                        return r;

                if (*p) {
                        log_error("Too many parameters for signature.");
                        return -EINVAL;
                }
        }

        if (!arg_expect_reply) {
                r = sd_bus_send(bus, m, NULL);
                if (r < 0) {
                        log_error("Failed to send message.");
                        return r;
                }

                return 0;
        }

        r = sd_bus_call(bus, m, arg_timeout, &error, &reply);
        if (r < 0) {
                log_error("%s", bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_is_empty(reply);
        if (r < 0)
                return bus_log_parse_error(r);

        if (r == 0 && !arg_quiet) {

                if (arg_verbose) {
                        pager_open_if_enabled();

                        r = bus_message_dump(reply, stdout, 0);
                        if (r < 0)
                                return r;
                } else {

                        fputs(sd_bus_message_get_signature(reply, true), stdout);
                        fputc(' ', stdout);

                        r = format_cmdline(reply, stdout, false);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        fputc('\n', stdout);
                }
        }

        return 0;
}

static int get_property(sd_bus *bus, char *argv[]) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned n;
        char **i;
        int r;

        assert(bus);

        n = strv_length(argv);
        if (n < 5) {
                log_error("Expects at least four arguments.");
                return -EINVAL;
        }

        STRV_FOREACH(i, argv + 4) {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                const char *contents = NULL;
                char type;

                r = sd_bus_call_method(bus, argv[1], argv[2], "org.freedesktop.DBus.Properties", "Get", &error, &reply, "ss", argv[3], *i);
                if (r < 0) {
                        log_error("%s", bus_error_message(&error, r));
                        return r;
                }

                r = sd_bus_message_peek_type(reply, &type, &contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_enter_container(reply, 'v', contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (arg_verbose)  {
                        pager_open_if_enabled();

                        r = bus_message_dump(reply, stdout, BUS_MESSAGE_DUMP_SUBTREE_ONLY);
                        if (r < 0)
                                return r;
                } else {
                        fputs(contents, stdout);
                        fputc(' ', stdout);

                        r = format_cmdline(reply, stdout, false);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        fputc('\n', stdout);
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        return 0;
}

static int set_property(sd_bus *bus, char *argv[]) {
        _cleanup_bus_message_unref_ sd_bus_message *m = NULL;
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned n;
        char **p;
        int r;

        assert(bus);

        n = strv_length(argv);
        if (n < 6) {
                log_error("Expects at least five arguments.");
                return -EINVAL;
        }

        r = sd_bus_message_new_method_call(bus, &m, argv[1], argv[2], "org.freedesktop.DBus.Properties", "Set");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ss", argv[3], argv[4]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', argv[5]);
        if (r < 0)
                return bus_log_create_error(r);

        p = argv+6;
        r = message_append_cmdline(m, argv[5], &p);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        if (*p) {
                log_error("Too many parameters for signature.");
                return -EINVAL;
        }

        r = sd_bus_call(bus, m, arg_timeout, &error, NULL);
        if (r < 0) {
                log_error("%s", bus_error_message(&error, r));
                return r;
        }

        return 0;
}

static int help(void) {
        printf("%s [OPTIONS...] {COMMAND} ...\n\n"
               "Introspect the bus.\n\n"
               "  -h --help               Show this help\n"
               "     --version            Show package version\n"
               "     --no-pager           Do not pipe output into a pager\n"
               "     --no-legend          Do not show the headers and footers\n"
               "     --system             Connect to system bus\n"
               "     --user               Connect to user bus\n"
               "  -H --host=[USER@]HOST   Operate on remote host\n"
               "  -M --machine=CONTAINER  Operate on local container\n"
               "     --address=ADDRESS    Connect to bus specified by address\n"
               "     --show-machine       Show machine ID column in list\n"
               "     --unique             Only show unique names\n"
               "     --acquired           Only show acquired names\n"
               "     --activatable        Only show activatable names\n"
               "     --match=MATCH        Only show matching messages\n"
               "     --list               Don't show tree, but simple object path list\n"
               "     --quiet              Don't show method call reply\n"
               "     --verbose            Show result values in long format\n"
               "     --expect-reply=BOOL  Expect a method call reply\n"
               "     --auto-start=BOOL    Auto-start destination service\n"
               "     --allow-interactive-authorization=BOOL\n"
               "                          Allow interactive authorization for operation\n"
               "     --timeout=SECS       Maximum time to wait for method call completion\n"
               "     --augment-creds=BOOL Extend credential data with data read from /proc/$PID\n\n"
               "Commands:\n"
               "  list                    List bus names\n"
               "  status [SERVICE]        Show bus service, process or bus owner credentials\n"
               "  monitor [SERVICE...]    Show bus traffic\n"
               "  capture [SERVICE...]    Capture bus traffic as pcap\n"
               "  tree [SERVICE...]       Show object tree of service\n"
               "  introspect SERVICE OBJECT [INTERFACE]\n"
               "  call SERVICE OBJECT INTERFACE METHOD [SIGNATURE [ARGUMENT...]]\n"
               "                          Call a method\n"
               "  get-property SERVICE OBJECT INTERFACE PROPERTY...\n"
               "                          Get property value\n"
               "  set-property SERVICE OBJECT INTERFACE PROPERTY SIGNATURE ARGUMENT...\n"
               "                          Set property value\n"
               "  help                    Show this help\n"
               , program_invocation_short_name);

        return 0;
}

static int parse_argv(int argc, char *argv[]) {

        enum {
                ARG_VERSION = 0x100,
                ARG_NO_PAGER,
                ARG_NO_LEGEND,
                ARG_SYSTEM,
                ARG_USER,
                ARG_ADDRESS,
                ARG_MATCH,
                ARG_SHOW_MACHINE,
                ARG_UNIQUE,
                ARG_ACQUIRED,
                ARG_ACTIVATABLE,
                ARG_SIZE,
                ARG_LIST,
                ARG_VERBOSE,
                ARG_EXPECT_REPLY,
                ARG_AUTO_START,
                ARG_ALLOW_INTERACTIVE_AUTHORIZATION,
                ARG_TIMEOUT,
                ARG_AUGMENT_CREDS,
        };

        static const struct option options[] = {
                { "help",         no_argument,       NULL, 'h'              },
                { "version",      no_argument,       NULL, ARG_VERSION      },
                { "no-pager",     no_argument,       NULL, ARG_NO_PAGER     },
                { "no-legend",    no_argument,       NULL, ARG_NO_LEGEND    },
                { "system",       no_argument,       NULL, ARG_SYSTEM       },
                { "user",         no_argument,       NULL, ARG_USER         },
                { "address",      required_argument, NULL, ARG_ADDRESS      },
                { "show-machine", no_argument,       NULL, ARG_SHOW_MACHINE },
                { "unique",       no_argument,       NULL, ARG_UNIQUE       },
                { "acquired",     no_argument,       NULL, ARG_ACQUIRED     },
                { "activatable",  no_argument,       NULL, ARG_ACTIVATABLE  },
                { "match",        required_argument, NULL, ARG_MATCH        },
                { "host",         required_argument, NULL, 'H'              },
                { "machine",      required_argument, NULL, 'M'              },
                { "size",         required_argument, NULL, ARG_SIZE         },
                { "list",         no_argument,       NULL, ARG_LIST         },
                { "quiet",        no_argument,       NULL, 'q'              },
                { "verbose",      no_argument,       NULL, ARG_VERBOSE      },
                { "expect-reply", required_argument, NULL, ARG_EXPECT_REPLY },
                { "auto-start",   required_argument, NULL, ARG_AUTO_START   },
                { "allow-interactive-authorization", required_argument, NULL, ARG_ALLOW_INTERACTIVE_AUTHORIZATION },
                { "timeout",      required_argument, NULL, ARG_TIMEOUT      },
                { "augment-creds",required_argument, NULL, ARG_AUGMENT_CREDS},
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:q", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        puts(PACKAGE_STRING);
                        puts(SYSTEMD_FEATURES);
                        return 0;

                case ARG_NO_PAGER:
                        arg_no_pager = true;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case ARG_USER:
                        arg_user = true;
                        break;

                case ARG_SYSTEM:
                        arg_user = false;
                        break;

                case ARG_ADDRESS:
                        arg_address = optarg;
                        break;

                case ARG_SHOW_MACHINE:
                        arg_show_machine = true;
                        break;

                case ARG_UNIQUE:
                        arg_unique = true;
                        break;

                case ARG_ACQUIRED:
                        arg_acquired = true;
                        break;

                case ARG_ACTIVATABLE:
                        arg_activatable = true;
                        break;

                case ARG_MATCH:
                        if (strv_extend(&arg_matches, optarg) < 0)
                                return log_oom();
                        break;

                case ARG_SIZE: {
                        off_t o;

                        r = parse_size(optarg, 0, &o);
                        if (r < 0) {
                                log_error("Failed to parse size: %s", optarg);
                                return r;
                        }

                        if ((off_t) (size_t) o !=  o) {
                                log_error("Size out of range.");
                                return -E2BIG;
                        }

                        arg_snaplen = (size_t) o;
                        break;
                }

                case ARG_LIST:
                        arg_list = true;
                        break;

                case 'H':
                        arg_transport = BUS_TRANSPORT_REMOTE;
                        arg_host = optarg;
                        break;

                case 'M':
                        arg_transport = BUS_TRANSPORT_MACHINE;
                        arg_host = optarg;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERBOSE:
                        arg_verbose = true;
                        break;

                case ARG_EXPECT_REPLY:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --expect-reply= parameter.");
                                return r;
                        }

                        arg_expect_reply = !!r;
                        break;


                case ARG_AUTO_START:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --auto-start= parameter.");
                                return r;
                        }

                        arg_auto_start = !!r;
                        break;


                case ARG_ALLOW_INTERACTIVE_AUTHORIZATION:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --allow-interactive-authorization= parameter.");
                                return r;
                        }

                        arg_allow_interactive_authorization = !!r;
                        break;

                case ARG_TIMEOUT:
                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0) {
                                log_error("Failed to parse --timeout= parameter.");
                                return r;
                        }

                        break;

                case ARG_AUGMENT_CREDS:
                        r = parse_boolean(optarg);
                        if (r < 0) {
                                log_error("Failed to parse --augment-creds= parameter.");
                                return r;
                        }

                        arg_augment_creds = !!r;
                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached("Unhandled option");
                }

        return 1;
}

static int busctl_main(sd_bus *bus, int argc, char *argv[]) {
        assert(bus);

        if (optind >= argc ||
            streq(argv[optind], "list"))
                return list_bus_names(bus, argv + optind);

        if (streq(argv[optind], "monitor"))
                return monitor(bus, argv + optind, message_dump);

        if (streq(argv[optind], "capture"))
                return capture(bus, argv + optind);

        if (streq(argv[optind], "status"))
                return status(bus, argv + optind);

        if (streq(argv[optind], "tree"))
                return tree(bus, argv + optind);

        if (streq(argv[optind], "introspect"))
                return introspect(bus, argv + optind);

        if (streq(argv[optind], "call"))
                return call(bus, argv + optind);

        if (streq(argv[optind], "get-property"))
                return get_property(bus, argv + optind);

        if (streq(argv[optind], "set-property"))
                return set_property(bus, argv + optind);

        if (streq(argv[optind], "help"))
                return help();

        log_error("Unknown command '%s'", argv[optind]);
        return -EINVAL;
}

int main(int argc, char *argv[]) {
        _cleanup_bus_close_unref_ sd_bus *bus = NULL;
        int r;

        log_parse_environment();
        log_open();

        r = parse_argv(argc, argv);
        if (r <= 0)
                goto finish;

        r = sd_bus_new(&bus);
        if (r < 0) {
                log_error_errno(r, "Failed to allocate bus: %m");
                goto finish;
        }

        if (streq_ptr(argv[optind], "monitor") ||
            streq_ptr(argv[optind], "capture")) {

                r = sd_bus_set_monitor(bus, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to set monitor mode: %m");
                        goto finish;
                }

                r = sd_bus_negotiate_creds(bus, true, _SD_BUS_CREDS_ALL);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable credentials: %m");
                        goto finish;
                }

                r = sd_bus_negotiate_timestamp(bus, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable timestamps: %m");
                        goto finish;
                }

                r = sd_bus_negotiate_fds(bus, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to enable fds: %m");
                        goto finish;
                }
        }

        if (arg_address)
                r = sd_bus_set_address(bus, arg_address);
        else {
                r = sd_bus_set_bus_client(bus, true);
                if (r < 0) {
                        log_error_errno(r, "Failed to set bus client: %m");
                        goto finish;
                }

                switch (arg_transport) {

                case BUS_TRANSPORT_LOCAL:
                        if (arg_user) {
                                bus->is_user = true;
                                r = bus_set_address_user(bus);
                        } else {
                                bus->is_system = true;
                                r = bus_set_address_system(bus);
                        }
                        break;

                case BUS_TRANSPORT_REMOTE:
                        r = bus_set_address_system_remote(bus, arg_host);
                        break;

                case BUS_TRANSPORT_MACHINE:
                        r = bus_set_address_system_machine(bus, arg_host);
                        break;

                default:
                        assert_not_reached("Hmm, unknown transport type.");
                }
        }
        if (r < 0) {
                log_error_errno(r, "Failed to set address: %m");
                goto finish;
        }

        r = sd_bus_start(bus);
        if (r < 0) {
                log_error_errno(r, "Failed to connect to bus: %m");
                goto finish;
        }

        r = busctl_main(bus, argc, argv);

finish:
        pager_close();

        strv_free(arg_matches);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
