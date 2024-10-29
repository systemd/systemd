/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <getopt.h>

#include "sd-bus.h"
#include "sd-json.h"

#include "alloc-util.h"
#include "build.h"
#include "bus-dump.h"
#include "bus-internal.h"
#include "bus-message.h"
#include "bus-signature.h"
#include "bus-type.h"
#include "bus-util.h"
#include "busctl-introspect.h"
#include "capsule-util.h"
#include "escape.h"
#include "fd-util.h"
#include "fdset.h"
#include "fileio.h"
#include "format-table.h"
#include "glyph-util.h"
#include "json-util.h"
#include "log.h"
#include "main-func.h"
#include "memstream-util.h"
#include "os-util.h"
#include "pager.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "path-util.h"
#include "pretty-print.h"
#include "runtime-scope.h"
#include "set.h"
#include "sort-util.h"
#include "strv.h"
#include "terminal-util.h"
#include "user-util.h"
#include "verbs.h"
#include "version.h"

static sd_json_format_flags_t arg_json_format_flags = SD_JSON_FORMAT_OFF;
static PagerFlags arg_pager_flags = 0;
static bool arg_legend = true;
static int arg_full = -1;
static const char *arg_address = NULL;
static bool arg_unique = false;
static bool arg_acquired = false;
static bool arg_activatable = false;
static bool arg_show_machine = false;
static char **arg_matches = NULL;
static BusTransport arg_transport = BUS_TRANSPORT_LOCAL;
static const char *arg_host = NULL;
static RuntimeScope arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
static size_t arg_snaplen = 4096;
static bool arg_list = false;
static bool arg_quiet = false;
static bool arg_verbose = false;
static bool arg_xml_interface = false;
static bool arg_expect_reply = true;
static bool arg_auto_start = true;
static bool arg_allow_interactive_authorization = true;
static bool arg_augment_creds = true;
static bool arg_watch_bind = false;
static usec_t arg_timeout = 0;
static const char *arg_destination = NULL;
static uint64_t arg_limit_messages = UINT64_MAX;

STATIC_DESTRUCTOR_REGISTER(arg_matches, strv_freep);

#define NAME_IS_ACQUIRED INT_TO_PTR(1)
#define NAME_IS_ACTIVATABLE INT_TO_PTR(2)

static int json_transform_message(sd_bus_message *m, sd_json_variant **ret);

static int acquire_bus(bool set_monitor, sd_bus **ret) {
        _cleanup_(sd_bus_close_unrefp) sd_bus *bus = NULL;
        _cleanup_close_ int pin_fd = -EBADF;
        int r;

        r = sd_bus_new(&bus);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate bus: %m");

        (void) sd_bus_set_description(bus, "busctl");

        if (set_monitor) {
                r = sd_bus_set_monitor(bus, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to set monitor mode: %m");

                r = sd_bus_negotiate_creds(bus, true, _SD_BUS_CREDS_ALL);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable credentials: %m");

                r = sd_bus_negotiate_timestamp(bus, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable timestamps: %m");

                r = sd_bus_negotiate_fds(bus, true);
                if (r < 0)
                        return log_error_errno(r, "Failed to enable fds: %m");
        }

        r = sd_bus_set_bus_client(bus, true);
        if (r < 0)
                return log_error_errno(r, "Failed to set bus client: %m");

        r = sd_bus_set_watch_bind(bus, arg_watch_bind);
        if (r < 0)
                return log_error_errno(r, "Failed to set watch-bind setting to '%s': %m",
                                       yes_no(arg_watch_bind));

        if (arg_address)
                r = sd_bus_set_address(bus, arg_address);
        else
                switch (arg_transport) {

                case BUS_TRANSPORT_LOCAL:

                        switch (arg_runtime_scope) {

                        case RUNTIME_SCOPE_USER:
                                r = bus_set_address_user(bus);
                                break;

                        case RUNTIME_SCOPE_SYSTEM:
                                r = bus_set_address_system(bus);
                                break;

                        default:
                                assert_not_reached();
                        }

                        break;

                case BUS_TRANSPORT_REMOTE:
                        r = bus_set_address_system_remote(bus, arg_host);
                        break;

                case BUS_TRANSPORT_MACHINE:
                        r = bus_set_address_machine(bus, arg_runtime_scope, arg_host);
                        break;

                case BUS_TRANSPORT_CAPSULE:
                        r = bus_set_address_capsule_bus(bus, arg_host, &pin_fd);
                        break;

                default:
                        assert_not_reached();
                }
        if (r < 0)
                return bus_log_address_error(r, arg_transport);

        r = sd_bus_start(bus);
        if (r < 0)
                return bus_log_connect_error(r, arg_transport, arg_runtime_scope);

        *ret = TAKE_PTR(bus);

        return 0;
}

static void notify_bus_error(const sd_bus_error *error) {

        if (!sd_bus_error_is_set(error))
                return;

        (void) sd_notifyf(/* unset_environment= */ false, "BUSERROR=%s", error->name);
}

static int list_bus_names(int argc, char **argv, void *userdata) {
        _cleanup_strv_free_ char **acquired = NULL, **activatable = NULL;
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_hashmap_free_ Hashmap *names = NULL;
        _cleanup_(table_unrefp) Table *table = NULL;
        char *k;
        void *v;
        int r;

        enum {
                COLUMN_ACTIVATABLE,
                COLUMN_NAME,
                COLUMN_PID,
                COLUMN_PROCESS,
                COLUMN_USER,
                COLUMN_CONNECTION,
                COLUMN_UNIT,
                COLUMN_SESSION,
                COLUMN_DESCRIPTION,
                COLUMN_MACHINE,
        };

        if (!arg_unique && !arg_acquired && !arg_activatable)
                arg_unique = arg_acquired = arg_activatable = true;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        r = sd_bus_list_names(bus,
                              (arg_acquired || arg_unique) ? &acquired : NULL,
                              arg_activatable ? &activatable : NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to list names: %m");

        names = hashmap_new(&string_hash_ops);
        if (!names)
                return log_oom();

        STRV_FOREACH(i, acquired) {
                r = hashmap_put(names, *i, NAME_IS_ACQUIRED);
                if (r < 0)
                        return log_error_errno(r, "Failed to add to hashmap: %m");
        }

        STRV_FOREACH(i, activatable) {
                r = hashmap_put(names, *i, NAME_IS_ACTIVATABLE);
                if (r < 0 && r != -EEXIST)
                        return log_error_errno(r, "Failed to add to hashmap: %m");
        }

        table = table_new("activatable",
                          "name",
                          "pid",
                          "process",
                          "user",
                          "connection",
                          "unit",
                          "session",
                          "description",
                          "machine");
        if (!table)
                return log_oom();

        if (arg_full > 0)
                table_set_width(table, 0);

        r = table_set_align_percent(table, table_get_cell(table, 0, COLUMN_PID), 100);
        if (r < 0)
                return log_error_errno(r, "Failed to set alignment: %m");

        table_set_ersatz_string(table, TABLE_ERSATZ_DASH);

        r = table_set_sort(table, (size_t) COLUMN_NAME);
        if (r < 0)
                return log_error_errno(r, "Failed to set sort column: %m");

        if (arg_show_machine)
                r = table_set_display(table, (size_t) COLUMN_NAME,
                                             (size_t) COLUMN_PID,
                                             (size_t) COLUMN_PROCESS,
                                             (size_t) COLUMN_USER,
                                             (size_t) COLUMN_CONNECTION,
                                             (size_t) COLUMN_UNIT,
                                             (size_t) COLUMN_SESSION,
                                             (size_t) COLUMN_DESCRIPTION,
                                             (size_t) COLUMN_MACHINE);
        else
                r = table_set_display(table, (size_t) COLUMN_NAME,
                                             (size_t) COLUMN_PID,
                                             (size_t) COLUMN_PROCESS,
                                             (size_t) COLUMN_USER,
                                             (size_t) COLUMN_CONNECTION,
                                             (size_t) COLUMN_UNIT,
                                             (size_t) COLUMN_SESSION,
                                             (size_t) COLUMN_DESCRIPTION);

        if (r < 0)
                return log_error_errno(r, "Failed to set columns to display: %m");

        HASHMAP_FOREACH_KEY(v, k, names) {
                _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;

                if (v == NAME_IS_ACTIVATABLE) {
                        r = table_add_many(
                                        table,
                                        TABLE_INT, PTR_TO_INT(v),
                                        TABLE_STRING, k,
                                        TABLE_EMPTY,
                                        TABLE_EMPTY,
                                        TABLE_EMPTY,
                                        TABLE_STRING, "(activatable)", TABLE_SET_COLOR, ansi_grey(),
                                        TABLE_EMPTY,
                                        TABLE_EMPTY,
                                        TABLE_EMPTY,
                                        TABLE_EMPTY);
                        if (r < 0)
                                return table_log_add_error(r);

                        continue;
                }

                assert(v == NAME_IS_ACQUIRED);

                if (!arg_unique && k[0] == ':')
                        continue;

                if (!arg_acquired && k[0] != ':')
                        continue;

                r = table_add_many(table,
                                   TABLE_INT, PTR_TO_INT(v),
                                   TABLE_STRING, k);
                if (r < 0)
                        return table_log_add_error(r);

                r = sd_bus_get_name_creds(
                                bus, k,
                                (arg_augment_creds ? SD_BUS_CREDS_AUGMENT : 0) |
                                SD_BUS_CREDS_EUID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|
                                SD_BUS_CREDS_UNIQUE_NAME|SD_BUS_CREDS_UNIT|SD_BUS_CREDS_SESSION|
                                SD_BUS_CREDS_DESCRIPTION, &creds);
                if (r < 0) {
                        log_debug_errno(r, "Failed to acquire credentials of service %s, ignoring: %m", k);

                        r = table_fill_empty(table, COLUMN_MACHINE);
                } else {
                        const char *unique = NULL, *session = NULL, *unit = NULL, *cn = NULL;
                        pid_t pid;
                        uid_t uid;

                        r = sd_bus_creds_get_pid(creds, &pid);
                        if (r >= 0) {
                                const char *comm = NULL;

                                (void) sd_bus_creds_get_comm(creds, &comm);

                                r = table_add_many(table,
                                                   TABLE_PID, pid,
                                                   TABLE_STRING, strna(comm));
                        } else
                                r = table_add_many(table, TABLE_EMPTY, TABLE_EMPTY);
                        if (r < 0)
                                return table_log_add_error(r);

                        r = sd_bus_creds_get_euid(creds, &uid);
                        if (r >= 0) {
                                _cleanup_free_ char *u = NULL;

                                u = uid_to_name(uid);
                                if (!u)
                                        return log_oom();

                                r = table_add_cell(table, NULL, TABLE_STRING, u);
                        } else
                                r = table_add_cell(table, NULL, TABLE_EMPTY, NULL);
                        if (r < 0)
                                return table_log_add_error(r);

                        (void) sd_bus_creds_get_unique_name(creds, &unique);
                        (void) sd_bus_creds_get_unit(creds, &unit);
                        (void) sd_bus_creds_get_session(creds, &session);
                        (void) sd_bus_creds_get_description(creds, &cn);

                        r = table_add_many(
                                        table,
                                        TABLE_STRING, unique,
                                        TABLE_STRING, unit,
                                        TABLE_STRING, session,
                                        TABLE_STRING, cn);
                }
                if (r < 0)
                        return table_log_add_error(r);

                if (arg_show_machine) {
                        sd_id128_t mid;

                        r = sd_bus_get_name_machine_id(bus, k, &mid);
                        if (r < 0)
                                log_debug_errno(r, "Failed to acquire credentials of service %s, ignoring: %m", k);
                        else {
                                r = table_add_cell(table, NULL, TABLE_ID128, &mid);
                                if (r < 0)
                                        return table_log_add_error(r);

                                continue; /* line fully filled, no need to fill the remainder below */
                        }
                }

                r = table_fill_empty(table, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to fill line: %m");
        }

        return table_print_with_pager(table, arg_json_format_flags, arg_pager_flags, arg_legend);
}

static void print_subtree(const char *prefix, const char *path, char **l) {
        /* We assume the list is sorted. Let's first skip over the
         * entry we are looking at. */
        for (;;) {
                if (!*l)
                        return;

                if (!streq(*l, path))
                        break;

                l++;
        }

        const char
                *vertical = strjoina(prefix, special_glyph(SPECIAL_GLYPH_TREE_VERTICAL)),
                *space = strjoina(prefix, special_glyph(SPECIAL_GLYPH_TREE_SPACE));

        for (;;) {
                bool has_more = false;
                char **n;

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

                printf("%s%s %s\n",
                       prefix,
                       special_glyph(has_more ? SPECIAL_GLYPH_TREE_BRANCH : SPECIAL_GLYPH_TREE_RIGHT),
                       *l);

                print_subtree(has_more ? vertical : space, *l, l);
                l = n;
        }
}

static void print_tree(char **l) {
        if (arg_list)
                strv_print(l);
        else if (strv_isempty(l))
                printf("No objects discovered.\n");
        else if (streq(l[0], "/") && !l[1])
                printf("Only root object discovered.\n");
        else
                print_subtree("", "/", l);
}

static int on_path(const char *path, void *userdata) {
        Set *paths = ASSERT_PTR(userdata);
        int r;

        r = set_put_strdup(&paths, path);
        if (r < 0)
                return log_oom();

        return 0;
}

static int find_nodes(sd_bus *bus, const char *service, const char *path, Set *paths) {
        static const XMLIntrospectOps ops = {
                .on_path = on_path,
        };

        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *xml;
        int r;

        r = sd_bus_call_method(bus, service, path,
                               "org.freedesktop.DBus.Introspectable", "Introspect",
                               &error, &reply, NULL);
        if (r < 0) {
                notify_bus_error(&error);
                printf("%sFailed to introspect object %s of service %s: %s%s\n",
                       ansi_highlight_red(),
                       path, service, bus_error_message(&error, r),
                       ansi_normal());
                return r;
        }

        r = sd_bus_message_read(reply, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        return parse_xml_introspect(path, xml, &ops, paths);
}

static int tree_one(sd_bus *bus, const char *service) {
        _cleanup_set_free_ Set *paths = NULL, *done = NULL, *failed = NULL;
        _cleanup_free_ char **l = NULL;
        int r;

        r = set_put_strdup(&paths, "/");
        if (r < 0)
                return log_oom();

        for (;;) {
                _cleanup_free_ char *p = NULL;
                int q;

                p = set_steal_first(paths);
                if (!p)
                        break;

                if (set_contains(done, p) ||
                    set_contains(failed, p))
                        continue;

                q = find_nodes(bus, service, p, paths);
                if (q < 0 && r >= 0)
                        r = q;

                q = set_ensure_consume(q < 0 ? &failed : &done, &string_hash_ops_free, TAKE_PTR(p));
                assert(q != 0);
                if (q < 0)
                        return log_oom();
        }

        pager_open(arg_pager_flags);

        l = set_get_strv(done);
        if (!l)
                return log_oom();

        strv_sort(l);
        print_tree(l);

        fflush(stdout);

        return r;
}

static int tree(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        int r;

        /* Do superficial verification of arguments before even opening the bus */
        STRV_FOREACH(i, strv_skip(argv, 1))
                if (!sd_bus_service_name_is_valid(*i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Invalid bus service name: %s", *i);

        if (!arg_unique && !arg_acquired)
                arg_acquired = true;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        if (argc <= 1) {
                _cleanup_strv_free_ char **names = NULL;
                bool not_first = false;

                r = sd_bus_list_names(bus, &names, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to get name list: %m");

                pager_open(arg_pager_flags);

                STRV_FOREACH(i, names) {
                        int q;

                        if (!arg_unique && (*i)[0] == ':')
                                continue;

                        if (!arg_acquired && (*i)[0] == ':')
                                continue;

                        if (not_first)
                                printf("\n");

                        printf("Service %s%s%s:\n", ansi_highlight(), *i, ansi_normal());

                        q = tree_one(bus, *i);
                        if (q < 0 && r >= 0)
                                r = q;

                        not_first = true;
                }
        } else
                STRV_FOREACH(i, strv_skip(argv, 1)) {
                        int q;

                        if (i > argv+1)
                                printf("\n");

                        if (argv[2]) {
                                pager_open(arg_pager_flags);
                                printf("Service %s%s%s:\n", ansi_highlight(), *i, ansi_normal());
                        }

                        q = tree_one(bus, *i);
                        if (q < 0 && r >= 0)
                                r = q;
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
                if (r < 0)
                        return r;
                if (r == 0)
                        return needs_space;

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
                                needs_space = true;

                        } else if (type == SD_BUS_TYPE_VARIANT) {

                                if (needs_space)
                                        fputc(' ', f);

                                fprintf(f, "%s", contents);
                                needs_space = true;
                        }

                        r = format_cmdline(m, f, needs_space);
                        if (r < 0)
                                return r;

                        needs_space = r > 0;

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
                        assert_not_reached();
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

static void member_hash_func(const Member *m, struct siphash *state) {
        uint64_t arity = 1;

        assert(m);
        assert(m->type);

        string_hash_func(m->type, state);

        arity += !!m->name + !!m->interface;

        uint64_hash_func(&arity, state);

        if (m->name)
                string_hash_func(m->name, state);

        if (m->signature)
                string_hash_func(m->signature, state);

        if (m->interface)
                string_hash_func(m->interface, state);
}

static int member_compare_func(const Member *x, const Member *y) {
        int d;

        assert(x);
        assert(y);
        assert(x->type);
        assert(y->type);

        d = strcmp_ptr(x->interface, y->interface);
        if (d != 0)
                return d;

        d = strcmp(x->type, y->type);
        if (d != 0)
                return d;

        d = strcmp_ptr(x->name, y->name);
        if (d != 0)
                return d;

        return strcmp_ptr(x->signature, y->signature);
}

static int member_compare_funcp(Member * const *a, Member * const *b) {
        return member_compare_func(*a, *b);
}

static Member* member_free(Member *m) {
        if (!m)
                return NULL;

        free(m->interface);
        free(m->name);
        free(m->signature);
        free(m->result);
        free(m->value);
        return mfree(m);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(Member*, member_free);

static Set* member_set_free(Set *s) {
        return set_free_with_destructor(s, member_free);
}
DEFINE_TRIVIAL_CLEANUP_FUNC(Set*, member_set_free);

static int on_interface(const char *interface, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m = NULL;
        Set *members = ASSERT_PTR(userdata);
        int r;

        assert(interface);

        m = new(Member, 1);
        if (!m)
                return log_oom();

        *m = (Member) {
                .type = "interface",
                .flags = flags,
        };

        r = free_and_strdup(&m->interface, interface);
        if (r < 0)
                return log_oom();

        r = set_put(members, m);
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Invalid introspection data: duplicate interface '%s'.", interface);
        if (r < 0)
                return log_oom();

        m = NULL;
        return 0;
}

static int on_method(const char *interface, const char *name, const char *signature, const char *result, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m = NULL;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new(Member, 1);
        if (!m)
                return log_oom();

        *m = (Member) {
                .type = "method",
                .flags = flags,
        };

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
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Invalid introspection data: duplicate method '%s' on interface '%s'.", name, interface);
        if (r < 0)
                return log_oom();

        m = NULL;
        return 0;
}

static int on_signal(const char *interface, const char *name, const char *signature, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m = NULL;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new(Member, 1);
        if (!m)
                return log_oom();

        *m = (Member) {
                .type = "signal",
                .flags = flags,
        };

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
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Invalid introspection data: duplicate signal '%s' on interface '%s'.", name, interface);
        if (r < 0)
                return log_oom();

        m = NULL;
        return 0;
}

static int on_property(const char *interface, const char *name, const char *signature, bool writable, uint64_t flags, void *userdata) {
        _cleanup_(member_freep) Member *m = NULL;
        Set *members = userdata;
        int r;

        assert(interface);
        assert(name);

        m = new(Member, 1);
        if (!m)
                return log_oom();

        *m = (Member) {
                .type = "property",
                .flags = flags,
                .writable = writable,
        };

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
        if (r == 0)
                return log_error_errno(SYNTHETIC_ERRNO(EEXIST),
                                       "Invalid introspection data: duplicate property '%s' on interface '%s'.", name, interface);
        if (r < 0)
                return log_oom();

        m = NULL;
        return 0;
}

DEFINE_PRIVATE_HASH_OPS(member_hash_ops, Member, member_hash_func, member_compare_func);

static int introspect(int argc, char **argv, void *userdata) {
        static const XMLIntrospectOps ops = {
                .on_interface = on_interface,
                .on_method = on_method,
                .on_signal = on_signal,
                .on_property = on_property,
        };

        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply_xml = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(member_set_freep) Set *members = NULL;
        unsigned name_width, type_width, signature_width, result_width;
        Member *m;
        const char *xml;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        members = set_new(&member_hash_ops);
        if (!members)
                return log_oom();

        r = sd_bus_call_method(bus, argv[1], argv[2],
                               "org.freedesktop.DBus.Introspectable", "Introspect",
                               &error, &reply_xml, NULL);
        if (r < 0) {
                notify_bus_error(&error);
                return log_error_errno(r, "Failed to introspect object %s of service %s: %s",
                                       argv[2], argv[1], bus_error_message(&error, r));
        }

        r = sd_bus_message_read(reply_xml, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        if (arg_xml_interface) {
                /* Just dump the received XML and finish */
                pager_open(arg_pager_flags);
                puts(xml);
                return 0;
        }

        /* First, get list of all properties */
        r = parse_xml_introspect(argv[2], xml, &ops, members);
        if (r < 0)
                return r;

        /* Second, find the current values for them */
        SET_FOREACH(m, members) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;

                if (!streq(m->type, "property"))
                        continue;

                if (m->value)
                        continue;

                if (argv[3] && !streq(argv[3], m->interface))
                        continue;

                r = sd_bus_call_method(bus, argv[1], argv[2],
                                       "org.freedesktop.DBus.Properties", "GetAll",
                                       &error, &reply, "s", m->interface);
                if (r < 0) {
                        notify_bus_error(&error);
                        return log_error_errno(r, "Failed to get all properties on interface %s: %s",
                                               m->interface, bus_error_message(&error, r));
                }

                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                if (r < 0)
                        return bus_log_parse_error(r);

                for (;;) {
                        _cleanup_(memstream_done) MemStream ms = {};
                        _cleanup_free_ char *buf = NULL;
                        const char *name, *contents;
                        Member *z;
                        char type;
                        FILE *mf;

                        r = sd_bus_message_enter_container(reply, 'e', "sv");
                        if (r < 0)
                                return bus_log_parse_error(r);
                        if (r == 0)
                                break;

                        r = sd_bus_message_read(reply, "s", &name);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_peek_type(reply, &type, &contents);
                        if (r < 0)
                                return bus_log_parse_error(r);
                        if (type != 'v')
                                return bus_log_parse_error(EINVAL);

                        r = sd_bus_message_enter_container(reply, 'v', contents);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        mf = memstream_init(&ms);
                        if (!mf)
                                return log_oom();

                        r = format_cmdline(reply, mf, false);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = memstream_finalize(&ms, &buf, NULL);
                        if (r < 0)
                                return log_error_errno(r, "Failed to flush and close memstream: %m");

                        z = set_get(members, &((Member) {
                                                .type = "property",
                                                .interface = m->interface,
                                                .signature = (char*) contents,
                                                .name = (char*) name }));
                        if (z)
                                free_and_replace(z->value, buf);

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

        name_width = strlen("NAME");
        type_width = strlen("TYPE");
        signature_width = strlen("SIGNATURE");
        result_width = strlen("RESULT/VALUE");

        Member **sorted = newa(Member*, set_size(members));
        size_t k = 0;

        SET_FOREACH(m, members) {
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

        if (result_width > 40 && arg_full <= 0)
                result_width = 40;

        typesafe_qsort(sorted, k, member_compare_funcp);

        pager_open(arg_pager_flags);

        if (arg_legend)
                printf("%-*s %-*s %-*s %-*s %s\n",
                       (int) name_width, "NAME",
                       (int) type_width, "TYPE",
                       (int) signature_width, "SIGNATURE",
                       (int) result_width, "RESULT/VALUE",
                       "FLAGS");

        for (size_t j = 0; j < k; j++) {
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
                        rv = empty_to_dash(m->result);

                printf("%s%s%-*s%s %-*s %-*s %-*s%s%s%s%s%s%s\n",
                       is_interface ? ansi_highlight() : "",
                       is_interface ? "" : ".",
                       - !is_interface + (int) name_width,
                       empty_to_dash(streq_ptr(m->type, "interface") ? m->interface : m->name),
                       is_interface ? ansi_normal() : "",
                       (int) type_width, empty_to_dash(m->type),
                       (int) signature_width, empty_to_dash(m->signature),
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
        return sd_bus_message_dump(m, f, SD_BUS_MESSAGE_DUMP_WITH_HEADER);
}

static int message_pcap(sd_bus_message *m, FILE *f) {
        return bus_message_pcap_frame(m, arg_snaplen, f);
}

static int message_json(sd_bus_message *m, FILE *f) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *w = NULL;
        char e[2];
        int r;
        usec_t ts;

        r = json_transform_message(m, &v);
        if (r < 0)
                return r;

        e[0] = m->header->endian;
        e[1] = 0;

        ts = m->realtime;
        if (ts == 0)
                ts = now(CLOCK_REALTIME);

        r = sd_json_buildo(&w,
                SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(bus_message_type_to_string(m->header->type))),
                SD_JSON_BUILD_PAIR("endian", SD_JSON_BUILD_STRING(e)),
                SD_JSON_BUILD_PAIR("flags", SD_JSON_BUILD_INTEGER(m->header->flags)),
                SD_JSON_BUILD_PAIR("version", SD_JSON_BUILD_INTEGER(m->header->version)),
                SD_JSON_BUILD_PAIR("cookie", SD_JSON_BUILD_INTEGER(BUS_MESSAGE_COOKIE(m))),
                SD_JSON_BUILD_PAIR_CONDITION(m->reply_cookie != 0, "reply_cookie", SD_JSON_BUILD_INTEGER(m->reply_cookie)),
                SD_JSON_BUILD_PAIR("timestamp-realtime", SD_JSON_BUILD_UNSIGNED(ts)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->sender, "sender", SD_JSON_BUILD_STRING(m->sender)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->destination, "destination", SD_JSON_BUILD_STRING(m->destination)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->path, "path", SD_JSON_BUILD_STRING(m->path)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->interface, "interface", SD_JSON_BUILD_STRING(m->interface)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->member, "member", SD_JSON_BUILD_STRING(m->member)),
                SD_JSON_BUILD_PAIR_CONDITION(m->monotonic != 0, "monotonic", SD_JSON_BUILD_INTEGER(m->monotonic)),
                SD_JSON_BUILD_PAIR_CONDITION(m->realtime != 0, "realtime", SD_JSON_BUILD_INTEGER(m->realtime)),
                SD_JSON_BUILD_PAIR_CONDITION(m->seqnum != 0, "seqnum", SD_JSON_BUILD_INTEGER(m->seqnum)),
                SD_JSON_BUILD_PAIR_CONDITION(!!m->error.name, "error_name", SD_JSON_BUILD_STRING(m->error.name)),
                SD_JSON_BUILD_PAIR("payload", SD_JSON_BUILD_VARIANT(v)));
        if (r < 0)
                return log_error_errno(r, "Failed to build JSON object: %m");

        sd_json_variant_dump(w, arg_json_format_flags, f, NULL);
        return 0;
}

static int monitor(int argc, char **argv, int (*dump)(sd_bus_message *m, FILE *f)) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *message = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        uint32_t flags = 0;
        const char *unique_name;
        bool is_monitor = false;
        int r;

        r = acquire_bus(true, &bus);
        if (r < 0)
                return r;

        usec_t end = arg_timeout > 0 ?
                usec_add(now(CLOCK_MONOTONIC), arg_timeout) : USEC_INFINITY;

        /* upgrade connection; it's not used for anything else after this call */
        r = sd_bus_message_new_method_call(bus,
                                           &message,
                                           "org.freedesktop.DBus",
                                           "/org/freedesktop/DBus",
                                           "org.freedesktop.DBus.Monitoring",
                                           "BecomeMonitor");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(message, 'a', "s");
        if (r < 0)
                return bus_log_create_error(r);

        STRV_FOREACH(i, argv+1) {
                _cleanup_free_ char *m = NULL;

                if (!sd_bus_service_name_is_valid(*i))
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid service name '%s'", *i);

                m = strjoin("sender='", *i, "'");
                if (!m)
                        return log_oom();

                r = sd_bus_message_append_basic(message, 's', m);
                if (r < 0)
                        return bus_log_create_error(r);

                free(m);
                m = strjoin("destination='", *i, "'");
                if (!m)
                        return log_oom();

                r = sd_bus_message_append_basic(message, 's', m);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        STRV_FOREACH(i, arg_matches) {
                r = sd_bus_message_append_basic(message, 's', *i);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_close_container(message);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append_basic(message, 'u', &flags);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_call(bus, message, arg_timeout, &error, NULL);
        if (r < 0) {
                notify_bus_error(&error);
                return log_error_errno(r, "Call to org.freedesktop.DBus.Monitoring.BecomeMonitor failed: %s",
                                       bus_error_message(&error, r));
        }

        r = sd_bus_get_unique_name(bus, &unique_name);
        if (r < 0)
                return log_error_errno(r, "Failed to get unique name: %m");

        if (!arg_quiet && !sd_json_format_enabled(arg_json_format_flags))
                log_info("Monitoring bus message stream.");

        (void) sd_notify(/* unset_environment=false */ false, "READY=1");

        for (;;) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0)
                        return log_error_errno(r, "Failed to process bus: %m");

                if (m) {
                        if (!is_monitor) {
                                const char *name;

                                /* wait until we lose our unique name */
                                if (sd_bus_message_is_signal(m, "org.freedesktop.DBus", "NameLost") <= 0)
                                        continue;

                                r = sd_bus_message_read(m, "s", &name);
                                if (r < 0)
                                        return bus_log_parse_error(r);

                                if (streq(name, unique_name))
                                        is_monitor = true;

                                continue;
                        }

                        dump(m, stdout);
                        fflush(stdout);

                        if (arg_limit_messages != UINT64_MAX) {
                                arg_limit_messages--;

                                if (arg_limit_messages == 0) {
                                        if (!arg_quiet && !sd_json_format_enabled(arg_json_format_flags))
                                                log_info("Received requested maximum number of messages, exiting.");
                                        return 0;
                                }
                        }

                        if (sd_bus_message_is_signal(m, "org.freedesktop.DBus.Local", "Disconnected") > 0) {
                                if (!arg_quiet && !sd_json_format_enabled(arg_json_format_flags))
                                        log_info("Connection terminated, exiting.");
                                return 0;
                        }

                        continue;
                }

                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, arg_timeout > 0 ? usec_sub_unsigned(end, now(CLOCK_MONOTONIC)) : UINT64_MAX);
                if (r == 0 && arg_timeout > 0 && now(CLOCK_MONOTONIC) >= end) {
                        if (!arg_quiet && !sd_json_format_enabled(arg_json_format_flags))
                                log_info("Timed out waiting for messages, exiting.");
                        return 0;
                }
                if (r < 0)
                        return log_error_errno(r, "Failed to wait for bus: %m");
        }
}

static int verb_monitor(int argc, char **argv, void *userdata) {
        return monitor(argc, argv, sd_json_format_enabled(arg_json_format_flags) ? message_json : message_dump);
}

static int verb_capture(int argc, char **argv, void *userdata) {
        _cleanup_free_ char *osname = NULL;
        static const char info[] =
                "busctl (systemd) " PROJECT_VERSION_FULL " (Git " GIT_VERSION ")";
        int r;

        if (isatty_safe(STDOUT_FILENO))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                       "Refusing to write message data to console, please redirect output to a file.");

        r = parse_os_release(NULL, "PRETTY_NAME", &osname);
        if (r < 0)
                log_full_errno(r == -ENOENT ? LOG_DEBUG : LOG_INFO, r,
                               "Failed to read os-release file, ignoring: %m");
        bus_pcap_header(arg_snaplen, osname, info, stdout);

        r = monitor(argc, argv, message_pcap);
        if (r < 0)
                return r;

        r = fflush_and_check(stdout);
        if (r < 0)
                return log_error_errno(r, "Couldn't write capture file: %m");

        return r;
}

static int status(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_creds_unrefp) sd_bus_creds *creds = NULL;
        pid_t pid;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        pager_open(arg_pager_flags);

        if (!isempty(argv[1])) {
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
                        printf("BusAddress=%s%s%s\n", ansi_highlight(), address, ansi_normal());

                r = sd_bus_get_scope(bus, &scope);
                if (r >= 0)
                        printf("BusScope=%s%s%s\n", ansi_highlight(), scope, ansi_normal());

                r = sd_bus_get_bus_id(bus, &bus_id);
                if (r >= 0)
                        printf("BusID=%s" SD_ID128_FORMAT_STR "%s\n",
                               ansi_highlight(), SD_ID128_FORMAT_VAL(bus_id), ansi_normal());

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

static int message_append_cmdline(sd_bus_message *m, const char *signature, FDSet **passed_fdset, char ***x) {
        char **p;
        int r;

        assert(m);
        assert(signature);
        assert(passed_fdset);
        assert(x);

        p = *x;

        for (;;) {
                const char *v;
                char t;

                t = *signature;
                v = *p;

                if (t == 0)
                        break;
                if (!v)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Too few parameters for signature.");

                signature++;
                p++;

                switch (t) {

                case SD_BUS_TYPE_BOOLEAN:

                        r = parse_boolean(v);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as boolean: %m", v);

                        r = sd_bus_message_append_basic(m, t, &r);
                        break;

                case SD_BUS_TYPE_BYTE: {
                        uint8_t z;

                        r = safe_atou8(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as byte (unsigned 8-bit integer): %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT16: {
                        int16_t z;

                        r = safe_atoi16(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as signed 16-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT16: {
                        uint16_t z;

                        r = safe_atou16(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as unsigned 16-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT32: {
                        int32_t z;

                        r = safe_atoi32(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as signed 32-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT32: {
                        uint32_t z;

                        r = safe_atou32(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as unsigned 32-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_INT64: {
                        int64_t z;

                        r = safe_atoi64(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as signed 64-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_UINT64: {
                        uint64_t z;

                        r = safe_atou64(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as unsigned 64-bit integer: %m", v);

                        r = sd_bus_message_append_basic(m, t, &z);
                        break;
                }

                case SD_BUS_TYPE_DOUBLE: {
                        double z;

                        r = safe_atod(v, &z);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' as double precision floating point: %m", v);

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
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse '%s' number of array entries: %m", v);

                        r = signature_element_length(signature, &k);
                        if (r < 0)
                                return log_error_errno(r, "Invalid array signature: %m");

                        {
                                char s[k + 1];
                                memcpy(s, signature, k);
                                s[k] = 0;

                                r = sd_bus_message_open_container(m, SD_BUS_TYPE_ARRAY, s);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                for (unsigned i = 0; i < n; i++) {
                                        r = message_append_cmdline(m, s, passed_fdset, &p);
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

                        r = message_append_cmdline(m, v, passed_fdset, &p);
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
                        if (r < 0 || k < 2) {
                                if (r >= 0 && k < 2)
                                        r = -ERANGE;
                                return log_error_errno(r, "Invalid struct/dict entry signature: %m");
                        }

                        {
                                char s[k-1];
                                memcpy(s, signature + 1, k - 2);
                                s[k - 2] = 0;

                                const char ctype = t == SD_BUS_TYPE_STRUCT_BEGIN ?
                                        SD_BUS_TYPE_STRUCT : SD_BUS_TYPE_DICT_ENTRY;
                                r = sd_bus_message_open_container(m, ctype, s);
                                if (r < 0)
                                        return bus_log_create_error(r);

                                r = message_append_cmdline(m, s, passed_fdset, &p);
                                if (r < 0)
                                        return r;
                        }

                        signature += k;

                        r = sd_bus_message_close_container(m);
                        break;
                }

                case SD_BUS_TYPE_UNIX_FD: {
                        int fd;

                        fd = parse_fd(v);
                        if (fd < 0)
                                return log_error_errno(fd, "Failed to parse '%s' as a file descriptor: %m", v);

                        if (!*passed_fdset) {
                                r = fdset_new_fill(/* filter_cloexec= */ 0, passed_fdset);
                                if (r < 0)
                                        return log_error_errno(r, "Failed to create fd set: %m");
                        }

                        if (!fdset_contains(*passed_fdset, fd))
                                return log_error_errno(SYNTHETIC_ERRNO(EBADF), "Failed to find file descriptor '%s' among passed file descriptors.", v);

                        r = sd_bus_message_append_basic(m, t, &fd);
                        break;
                }

                default:
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Unknown signature type %c.", t);
                }

                if (r < 0)
                        return bus_log_create_error(r);
        }

        *x = p;
        return 0;
}

static int json_transform_one(sd_bus_message *m, sd_json_variant **ret);

static int json_transform_and_append(sd_bus_message *m, sd_json_variant **array) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *element = NULL;
        int r;

        assert(m);
        assert(array);

        r = json_transform_one(m, &element);
        if (r < 0)
                return r;

        r = sd_json_variant_append_array(array, element);
        if (r < 0)
                return log_error_errno(r, "Failed to append json element to array: %m");

        return 0;
}

static int json_transform_array_or_struct(sd_bus_message *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *array = NULL;
        int r;

        assert(m);
        assert(ret);

        r = sd_json_variant_new_array(&array, NULL, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate json empty array: %m");

        for (;;) {
                r = sd_bus_message_at_end(m, false);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r > 0)
                        break;

                r = json_transform_and_append(m, &array);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(array);
        return 0;
}

static int json_transform_variant(sd_bus_message *m, const char *contents, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *value = NULL;
        int r;

        assert(m);
        assert(contents);
        assert(ret);

        r = json_transform_one(m, &value);
        if (r < 0)
                return r;

        r = sd_json_buildo(ret,
                          SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(contents)),
                          SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_VARIANT(value)));
        if (r < 0)
                return log_error_errno(r, "Failed to build json object: %m");

        return r;
}

static int json_transform_dict_array(sd_bus_message *m, sd_json_variant **ret) {
        sd_json_variant **elements = NULL;
        size_t n_elements = 0;
        int r;

        assert(m);
        assert(ret);

        CLEANUP_ARRAY(elements, n_elements, sd_json_variant_unref_many);

        for (;;) {
                const char *contents;
                char type;

                r = sd_bus_message_at_end(m, false);
                if (r < 0)
                        return bus_log_parse_error(r);
                if (r > 0)
                        break;

                r = sd_bus_message_peek_type(m, &type, &contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                assert(type == 'e');

                if (!GREEDY_REALLOC(elements, n_elements + 2))
                        return log_oom();

                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        return r;

                n_elements++;

                r = json_transform_one(m, elements + n_elements);
                if (r < 0)
                        return r;

                n_elements++;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error(r);
        }

        r = sd_json_variant_new_object(ret, elements, n_elements);
        if (r < 0)
                return log_error_errno(r, "Failed to create new json object: %m");

        return 0;
}

static int json_transform_one(sd_bus_message *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *contents;
        char type;
        int r;

        assert(m);
        assert(ret);

        r = sd_bus_message_peek_type(m, &type, &contents);
        if (r < 0)
                return bus_log_parse_error(r);

        switch (type) {

        case SD_BUS_TYPE_BYTE: {
                uint8_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform byte: %m");

                break;
        }

        case SD_BUS_TYPE_BOOLEAN: {
                int b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_boolean(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform boolean: %m");

                break;
        }

        case SD_BUS_TYPE_INT16: {
                int16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int16: %m");

                break;
        }

        case SD_BUS_TYPE_UINT16: {
                uint16_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint16: %m");

                break;
        }

        case SD_BUS_TYPE_INT32: {
                int32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int32: %m");

                break;
        }

        case SD_BUS_TYPE_UINT32: {
                uint32_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint32: %m");

                break;
        }

        case SD_BUS_TYPE_INT64: {
                int64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_integer(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform int64: %m");

                break;
        }

        case SD_BUS_TYPE_UINT64: {
                uint64_t b;

                r = sd_bus_message_read_basic(m, type, &b);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_unsigned(&v, b);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform uint64: %m");

                break;
        }

        case SD_BUS_TYPE_DOUBLE: {
                double d;

                r = sd_bus_message_read_basic(m, type, &d);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_real(&v, d);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform double: %m");

                break;
        }

        case SD_BUS_TYPE_STRING:
        case SD_BUS_TYPE_OBJECT_PATH:
        case SD_BUS_TYPE_SIGNATURE: {
                const char *s;

                r = sd_bus_message_read_basic(m, type, &s);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_json_variant_new_string(&v, s);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform double: %m");

                break;
        }

        case SD_BUS_TYPE_UNIX_FD: {
                int fd;

                r = sd_bus_message_read_basic(m, type, &fd);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = json_variant_new_fd_info(&v, fd);
                if (r < 0)
                        return log_error_errno(r, "Failed to transform fd: %m");

                break;
        }

        case SD_BUS_TYPE_ARRAY:
        case SD_BUS_TYPE_VARIANT:
        case SD_BUS_TYPE_STRUCT:
                r = sd_bus_message_enter_container(m, type, contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (type == SD_BUS_TYPE_VARIANT)
                        r = json_transform_variant(m, contents, &v);
                else if (type == SD_BUS_TYPE_ARRAY && contents[0] == '{')
                        r = json_transform_dict_array(m, &v);
                else
                        r = json_transform_array_or_struct(m, &v);
                if (r < 0)
                        return r;

                r = sd_bus_message_exit_container(m);
                if (r < 0)
                        return bus_log_parse_error(r);

                break;

        default:
                assert_not_reached();
        }

        *ret = TAKE_PTR(v);
        return 0;
}

static int json_transform_message(sd_bus_message *m, sd_json_variant **ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        const char *type;
        int r;

        assert(m);
        assert(ret);

        assert_se(type = sd_bus_message_get_signature(m, false));

        r = json_transform_array_or_struct(m, &v);
        if (r < 0)
                return r;

        r = sd_json_buildo(ret,
                          SD_JSON_BUILD_PAIR("type", SD_JSON_BUILD_STRING(type)),
                          SD_JSON_BUILD_PAIR("data", SD_JSON_BUILD_VARIANT(v)));
        if (r < 0)
                return log_error_errno(r, "Failed to build json object: %m");

        return 0;
}

static int call(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL, *reply = NULL;
        _cleanup_fdset_free_ FDSet *passed_fdset = NULL;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        if (!service_name_is_valid(argv[1]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid service name: %s", argv[1]);
        if (!object_path_is_valid(argv[2]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid object path: %s", argv[2]);
        if (!interface_name_is_valid(argv[3]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid interface name: %s", argv[3]);
        if (!member_name_is_valid(argv[4]))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid member name: %s", argv[4]);

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

                r = message_append_cmdline(m, argv[5], &passed_fdset, &p);
                if (r < 0)
                        return r;

                if (*p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Too many parameters for signature.");
        }

        if (!arg_expect_reply) {
                r = sd_bus_send(bus, m, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to send message: %m");

                return 0;
        }

        r = sd_bus_call(bus, m, arg_timeout, &error, &reply);
        if (r < 0) {
                notify_bus_error(&error);
                return log_error_errno(r, "Call failed: %s", bus_error_message(&error, r));
        }

        r = sd_bus_message_is_empty(reply);
        if (r < 0)
                return bus_log_parse_error(r);
        if (r > 0 || arg_quiet)
                return 0;

        if (sd_json_format_enabled(arg_json_format_flags)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                        pager_open(arg_pager_flags);

                r = json_transform_message(reply, &v);
                if (r < 0)
                        return r;

                sd_json_variant_dump(v, arg_json_format_flags, NULL, NULL);

        } else if (arg_verbose) {
                pager_open(arg_pager_flags);

                r = sd_bus_message_dump(reply, stdout, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump dbus message: %m");
        } else {

                fputs(sd_bus_message_get_signature(reply, true), stdout);
                fputc(' ', stdout);

                r = format_cmdline(reply, stdout, false);
                if (r < 0)
                        return bus_log_parse_error(r);

                fputc('\n', stdout);
        }

        return 0;
}

static int emit_signal(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_fdset_free_ FDSet *passed_fdset = NULL;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_signal(bus, &m, argv[1], argv[2], argv[3]);
        if (r < 0)
                return bus_log_create_error(r);

        if (arg_destination) {
                r = sd_bus_message_set_destination(m, arg_destination);
                if (r < 0)
                        return bus_log_create_error(r);
        }

        r = sd_bus_message_set_auto_start(m, arg_auto_start);
        if (r < 0)
                return bus_log_create_error(r);

        if (!isempty(argv[4])) {
                char **p;

                p = argv+5;

                r = message_append_cmdline(m, argv[4], &passed_fdset, &p);
                if (r < 0)
                        return r;

                if (*p)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Too many parameters for signature.");
        }

        r = sd_bus_send(bus, m, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to send signal: %m");

        return 0;
}

static int get_property(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        STRV_FOREACH(i, argv + 4) {
                _cleanup_(sd_bus_message_unrefp) sd_bus_message *reply = NULL;
                const char *contents = NULL;
                char type;

                r = sd_bus_call_method(bus, argv[1], argv[2],
                                       "org.freedesktop.DBus.Properties", "Get",
                                       &error, &reply, "ss", argv[3], *i);
                if (r < 0) {
                        notify_bus_error(&error);
                        return log_error_errno(r, "Failed to get property %s on interface %s: %s",
                                               *i, argv[3],
                                               bus_error_message(&error, r));
                }

                r = sd_bus_message_peek_type(reply, &type, &contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                r = sd_bus_message_enter_container(reply, 'v', contents);
                if (r < 0)
                        return bus_log_parse_error(r);

                if (sd_json_format_enabled(arg_json_format_flags)) {
                        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                        if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                                pager_open(arg_pager_flags);

                        r = json_transform_variant(reply, contents, &v);
                        if (r < 0)
                                return r;

                        sd_json_variant_dump(v, arg_json_format_flags, NULL, NULL);

                } else if (arg_verbose) {
                        pager_open(arg_pager_flags);

                        r = sd_bus_message_dump(reply, stdout, SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY);
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

static int on_bus_signal_impl(sd_bus_message *msg) {
        int r;

        assert(msg);

        r = sd_bus_message_is_empty(msg);
        if (r < 0)
                return bus_log_parse_error(r);
        if (r > 0 || arg_quiet)
                return 0;

        if (!FLAGS_SET(arg_json_format_flags, SD_JSON_FORMAT_OFF)) {
                _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;

                if (arg_json_format_flags & (SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_PRETTY_AUTO))
                        pager_open(arg_pager_flags);

                r = json_transform_message(msg, &v);
                if (r < 0)
                        return r;

                sd_json_variant_dump(v, arg_json_format_flags, NULL, NULL);

        } else if (arg_verbose) {
                pager_open(arg_pager_flags);

                r = sd_bus_message_dump(msg, stdout, 0);
                if (r < 0)
                        return log_error_errno(r, "Failed to dump dbus message: %m\n");
        } else {

                fputs(sd_bus_message_get_signature(msg, true), stdout);
                fputc(' ', stdout);

                r = format_cmdline(msg, stdout, false);
                if (r < 0)
                        return bus_log_parse_error(r);

                fputc('\n', stdout);
        }

        return 0;
}

static int on_bus_signal(sd_bus_message *msg, void *userdata, sd_bus_error *ret_error) {
        sd_event *e = sd_bus_get_event(sd_bus_message_get_bus(ASSERT_PTR(msg)));
        return sd_event_exit(e, on_bus_signal_impl(msg));
}

static int wait_signal(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_event_unrefp) sd_event *e = NULL;
        _cleanup_(sd_event_source_unrefp) sd_event_source *timer = NULL;
        int argn = 1, r;

        const char *sender = argc == 5 ? argv[argn++] : NULL;
        const char *path = argv[argn++];
        const char *interface = argv[argn++];
        const char *member = argv[argn++];

        if (sender && !service_name_is_valid(sender))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid service name: %s", sender);
        if (!object_path_is_valid(path))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid object path: %s", path);
        if (!interface_name_is_valid(interface))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid interface name: %s", interface);
        if (!member_name_is_valid(member))
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid member name: %s", member);

        r = acquire_bus(/* set_monitor= */ false, &bus);
        if (r < 0)
                return r;

        r = sd_bus_match_signal(bus, NULL, sender, path, interface, member, on_bus_signal, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to match signal %s on interface %s: %m", member, interface);

        r = sd_event_new(&e);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate event loop: %m\n");

        r = sd_bus_attach_event(bus, e, SD_EVENT_PRIORITY_NORMAL);
        if (r < 0)
                return log_error_errno(r, "Failed to attach bus event: %m\n");

        if (arg_timeout) {
                r = sd_event_add_time_relative(e, &timer, CLOCK_MONOTONIC, arg_timeout, 0, NULL, NULL);
                if (r < 0)
                        return log_error_errno(r, "Failed to schedule timeout: %m\n");
        }

        /* The match is installed and we're ready to observe the signal */
        sd_notify(/* unset_environment= */ false, "READY=1");

        return sd_event_loop(e);
}

static int set_property(int argc, char **argv, void *userdata) {
        _cleanup_(sd_bus_flush_close_unrefp) sd_bus *bus = NULL;
        _cleanup_(sd_bus_message_unrefp) sd_bus_message *m = NULL;
        _cleanup_(sd_bus_error_free) sd_bus_error error = SD_BUS_ERROR_NULL;
        _cleanup_fdset_free_ FDSet *passed_fdset = NULL;
        char **p;
        int r;

        r = acquire_bus(false, &bus);
        if (r < 0)
                return r;

        r = sd_bus_message_new_method_call(bus, &m, argv[1], argv[2],
                                           "org.freedesktop.DBus.Properties", "Set");
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_append(m, "ss", argv[3], argv[4]);
        if (r < 0)
                return bus_log_create_error(r);

        r = sd_bus_message_open_container(m, 'v', argv[5]);
        if (r < 0)
                return bus_log_create_error(r);

        p = argv + 6;
        r = message_append_cmdline(m, argv[5], &passed_fdset, &p);
        if (r < 0)
                return r;

        r = sd_bus_message_close_container(m);
        if (r < 0)
                return bus_log_create_error(r);

        if (*p)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Too many parameters for signature.");

        r = sd_bus_call(bus, m, arg_timeout, &error, NULL);
        if (r < 0) {
                notify_bus_error(&error);
                return log_error_errno(r, "Failed to set property %s on interface %s: %s",
                                       argv[4], argv[3],
                                       bus_error_message(&error, r));
        }

        return 0;
}

static int help(void) {
        _cleanup_free_ char *link = NULL;
        int r;

        r = terminal_urlify_man("busctl", "1", &link);
        if (r < 0)
                return log_oom();

        pager_open(arg_pager_flags);

        printf("%1$s [OPTIONS...] COMMAND ...\n\n"
               "%5$sIntrospect the D-Bus IPC bus.%6$s\n"
               "\n%3$sCommands%4$s:\n"
               "  list                     List bus names\n"
               "  status [SERVICE]         Show bus service, process or bus owner credentials\n"
               "  monitor [SERVICE...]     Show bus traffic\n"
               "  capture [SERVICE...]     Capture bus traffic as pcap\n"
               "  tree [SERVICE...]        Show object tree of service\n"
               "  introspect SERVICE OBJECT [INTERFACE]\n"
               "  call SERVICE OBJECT INTERFACE METHOD [SIGNATURE [ARGUMENT...]]\n"
               "                           Call a method\n"
               "  emit OBJECT INTERFACE SIGNAL [SIGNATURE [ARGUMENT...]]\n"
               "                           Emit a signal\n"
               "  wait OBJECT INTERFACE SIGNAL\n"
               "                           Wait for a signal\n"
               "  get-property SERVICE OBJECT INTERFACE PROPERTY...\n"
               "                           Get property value\n"
               "  set-property SERVICE OBJECT INTERFACE PROPERTY SIGNATURE ARGUMENT...\n"
               "                           Set property value\n"
               "  help                     Show this help\n"
               "\n%3$sOptions:%4$s\n"
               "  -h --help                Show this help\n"
               "     --version             Show package version\n"
               "     --no-pager            Do not pipe output into a pager\n"
               "     --no-legend           Do not show the headers and footers\n"
               "  -l --full                Do not ellipsize output\n"
               "     --system              Connect to system bus\n"
               "     --user                Connect to user bus\n"
               "  -H --host=[USER@]HOST    Operate on remote host\n"
               "  -M --machine=CONTAINER   Operate on local container\n"
               "     --address=ADDRESS     Connect to bus specified by address\n"
               "     --show-machine        Show machine ID column in list\n"
               "     --unique              Only show unique names\n"
               "     --acquired            Only show acquired names\n"
               "     --activatable         Only show activatable names\n"
               "     --match=MATCH         Only show matching messages\n"
               "     --size=SIZE           Maximum length of captured packet\n"
               "     --list                Don't show tree, but simple object path list\n"
               "  -q --quiet               Don't show method call reply\n"
               "     --verbose             Show result values in long format\n"
               "     --json=MODE           Output as JSON\n"
               "  -j                       Same as --json=pretty on tty, --json=short otherwise\n"
               "     --xml-interface       Dump the XML description in introspect command\n"
               "     --expect-reply=BOOL   Expect a method call reply\n"
               "     --auto-start=BOOL     Auto-start destination service\n"
               "     --allow-interactive-authorization=BOOL\n"
               "                           Allow interactive authorization for operation\n"
               "     --timeout=SECS        Maximum time to wait for method call completion\n"
               "     --augment-creds=BOOL  Extend credential data with data read from /proc/$PID\n"
               "     --watch-bind=BOOL     Wait for bus AF_UNIX socket to be bound in the file\n"
               "                           system\n"
               "     --destination=SERVICE Destination service of a signal\n"
               "  -N --limit-messages=NUMBER\n"
               "                           Stop monitoring after receiving the specified number\n"
               "                           of messages\n"
               "\nSee the %2$s for details.\n",
               program_invocation_short_name,
               link,
               ansi_underline(),
               ansi_normal(),
               ansi_highlight(),
               ansi_normal());

        return 0;
}

static int verb_help(int argc, char **argv, void *userdata) {
        return help();
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
                ARG_XML_INTERFACE,
                ARG_EXPECT_REPLY,
                ARG_AUTO_START,
                ARG_ALLOW_INTERACTIVE_AUTHORIZATION,
                ARG_TIMEOUT,
                ARG_AUGMENT_CREDS,
                ARG_WATCH_BIND,
                ARG_JSON,
                ARG_DESTINATION,
        };

        static const struct option options[] = {
                { "help",                            no_argument,       NULL, 'h'                                 },
                { "version",                         no_argument,       NULL, ARG_VERSION                         },
                { "no-pager",                        no_argument,       NULL, ARG_NO_PAGER                        },
                { "no-legend",                       no_argument,       NULL, ARG_NO_LEGEND                       },
                { "full",                            no_argument,       NULL, 'l'                                 },
                { "system",                          no_argument,       NULL, ARG_SYSTEM                          },
                { "user",                            no_argument,       NULL, ARG_USER                            },
                { "address",                         required_argument, NULL, ARG_ADDRESS                         },
                { "show-machine",                    no_argument,       NULL, ARG_SHOW_MACHINE                    },
                { "unique",                          no_argument,       NULL, ARG_UNIQUE                          },
                { "acquired",                        no_argument,       NULL, ARG_ACQUIRED                        },
                { "activatable",                     no_argument,       NULL, ARG_ACTIVATABLE                     },
                { "match",                           required_argument, NULL, ARG_MATCH                           },
                { "host",                            required_argument, NULL, 'H'                                 },
                { "machine",                         required_argument, NULL, 'M'                                 },
                { "capsule",                         required_argument, NULL, 'C'                                 },
                { "size",                            required_argument, NULL, ARG_SIZE                            },
                { "list",                            no_argument,       NULL, ARG_LIST                            },
                { "quiet",                           no_argument,       NULL, 'q'                                 },
                { "verbose",                         no_argument,       NULL, ARG_VERBOSE                         },
                { "xml-interface",                   no_argument,       NULL, ARG_XML_INTERFACE                   },
                { "expect-reply",                    required_argument, NULL, ARG_EXPECT_REPLY                    },
                { "auto-start",                      required_argument, NULL, ARG_AUTO_START                      },
                { "allow-interactive-authorization", required_argument, NULL, ARG_ALLOW_INTERACTIVE_AUTHORIZATION },
                { "timeout",                         required_argument, NULL, ARG_TIMEOUT                         },
                { "augment-creds",                   required_argument, NULL, ARG_AUGMENT_CREDS                   },
                { "watch-bind",                      required_argument, NULL, ARG_WATCH_BIND                      },
                { "json",                            required_argument, NULL, ARG_JSON                            },
                { "destination",                     required_argument, NULL, ARG_DESTINATION                     },
                { "limit-messages",                  required_argument, NULL, 'N'                                 },
                {},
        };

        int c, r;

        assert(argc >= 0);
        assert(argv);

        while ((c = getopt_long(argc, argv, "hH:M:C:J:qjlN:", options, NULL)) >= 0)

                switch (c) {

                case 'h':
                        return help();

                case ARG_VERSION:
                        return version();

                case ARG_NO_PAGER:
                        arg_pager_flags |= PAGER_DISABLE;
                        break;

                case ARG_NO_LEGEND:
                        arg_legend = false;
                        break;

                case 'l':
                        arg_full = true;
                        break;

                case ARG_USER:
                        arg_runtime_scope = RUNTIME_SCOPE_USER;
                        break;

                case ARG_SYSTEM:
                        arg_runtime_scope = RUNTIME_SCOPE_SYSTEM;
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
                        uint64_t sz;

                        r = parse_size(optarg, 1024, &sz);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse size '%s': %m", optarg);

                        if ((uint64_t) (size_t) sz !=  sz)
                                return log_error_errno(SYNTHETIC_ERRNO(E2BIG),
                                                       "Size out of range.");

                        arg_snaplen = (size_t) sz;
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

                case 'C':
                        r = capsule_name_is_valid(optarg);
                        if (r < 0)
                                return log_error_errno(r, "Unable to validate capsule name '%s': %m", optarg);
                        if (r == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Invalid capsule name: %s", optarg);

                        arg_host = optarg;
                        arg_transport = BUS_TRANSPORT_CAPSULE;
                        break;

                case 'q':
                        arg_quiet = true;
                        break;

                case ARG_VERBOSE:
                        arg_verbose = true;
                        break;

                case ARG_XML_INTERFACE:
                        arg_xml_interface = true;
                        break;

                case ARG_EXPECT_REPLY:
                        r = parse_boolean_argument("--expect-reply=", optarg, &arg_expect_reply);
                        if (r < 0)
                                return r;
                        break;

                case ARG_AUTO_START:
                        r = parse_boolean_argument("--auto-start=", optarg, &arg_auto_start);
                        if (r < 0)
                                return r;
                        break;

                case ARG_ALLOW_INTERACTIVE_AUTHORIZATION:
                        r = parse_boolean_argument("--allow-interactive-authorization=", optarg,
                                                   &arg_allow_interactive_authorization);
                        if (r < 0)
                                return r;
                        break;

                case ARG_TIMEOUT:
                        if (isempty(optarg)) {
                                arg_timeout = 0; /* Reset to default */
                                break;
                        }

                        r = parse_sec(optarg, &arg_timeout);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --timeout= parameter '%s': %m", optarg);

                        break;

                case ARG_AUGMENT_CREDS:
                        r = parse_boolean_argument("--augment-creds=", optarg, &arg_augment_creds);
                        if (r < 0)
                                return r;
                        break;

                case ARG_WATCH_BIND:
                        r = parse_boolean_argument("--watch-bind=", optarg, &arg_watch_bind);
                        if (r < 0)
                                return r;
                        break;

                case 'j':
                        arg_json_format_flags = SD_JSON_FORMAT_PRETTY_AUTO|SD_JSON_FORMAT_COLOR_AUTO;
                        break;

                case ARG_JSON:
                        r = parse_json_argument(optarg, &arg_json_format_flags);
                        if (r <= 0)
                                return r;

                        break;

                case ARG_DESTINATION:
                        arg_destination = optarg;
                        break;

                case 'N':
                        if (isempty(optarg)) {
                                arg_limit_messages = UINT64_MAX; /* Reset to default */
                                break;
                        }

                        r = safe_atou64(optarg, &arg_limit_messages);
                        if (r < 0)
                                return log_error_errno(r, "Failed to parse --limit-messages= parameter: %s", optarg);
                        if (arg_limit_messages == 0)
                                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "--limit-messages= parameter cannot be 0");

                        break;

                case '?':
                        return -EINVAL;

                default:
                        assert_not_reached();
                }

        if (arg_full < 0)
                arg_full = terminal_is_dumb();

        return 1;
}

static int busctl_main(int argc, char *argv[]) {
        static const Verb verbs[] = {
                { "list",         VERB_ANY, 1,        VERB_DEFAULT, list_bus_names },
                { "status",       VERB_ANY, 2,        0,            status         },
                { "monitor",      VERB_ANY, VERB_ANY, 0,            verb_monitor   },
                { "capture",      VERB_ANY, VERB_ANY, 0,            verb_capture   },
                { "tree",         VERB_ANY, VERB_ANY, 0,            tree           },
                { "introspect",   3,        4,        0,            introspect     },
                { "call",         5,        VERB_ANY, 0,            call           },
                { "emit",         4,        VERB_ANY, 0,            emit_signal    },
                { "wait",         4,        5,        0,            wait_signal    },
                { "get-property", 5,        VERB_ANY, 0,            get_property   },
                { "set-property", 6,        VERB_ANY, 0,            set_property   },
                { "help",         VERB_ANY, VERB_ANY, 0,            verb_help      },
                {}
        };

        return dispatch_verb(argc, argv, verbs, NULL);
}

static int run(int argc, char *argv[]) {
        int r;

        log_setup();

        r = parse_argv(argc, argv);
        if (r <= 0)
                return r;

        return busctl_main(argc, argv);
}

DEFINE_MAIN_FUNCTION(run);
