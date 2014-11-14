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
#include "xml.h"
#include "path-util.h"

#include "sd-bus.h"
#include "bus-message.h"
#include "bus-internal.h"
#include "bus-util.h"
#include "bus-dump.h"
#include "bus-signature.h"

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

static void pager_open_if_enabled(void) {

        /* Cache result before we open the pager */
        if (arg_no_pager)
                return;

        pager_open(false);
}

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
        if (r < 0) {
                log_error("Failed to list names: %s", strerror(-r));
                return r;
        }

        pager_open_if_enabled();

        names = hashmap_new(&string_hash_ops);
        if (!names)
                return log_oom();

        STRV_FOREACH(i, acquired) {
                max_i = MAX(max_i, strlen(*i));

                r = hashmap_put(names, *i, INT_TO_PTR(1));
                if (r < 0) {
                        log_error("Failed to add to hashmap: %s", strerror(-r));
                        return r;
                }
        }

        STRV_FOREACH(i, activatable) {
                max_i = MAX(max_i, strlen(*i));

                r = hashmap_put(names, *i, INT_TO_PTR(2));
                if (r < 0 && r != -EEXIST) {
                        log_error("Failed to add to hashmap: %s", strerror(-r));
                        return r;
                }
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

                if (hashmap_get(names, *i) == INT_TO_PTR(2)) {
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

                r = sd_bus_get_name_creds(bus, *i,
                                     SD_BUS_CREDS_UID|SD_BUS_CREDS_PID|SD_BUS_CREDS_COMM|
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

                        r = sd_bus_creds_get_uid(creds, &uid);
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

        vertical = strappenda(prefix, draw_special_char(DRAW_TREE_VERTICAL));
        space = strappenda(prefix, draw_special_char(DRAW_TREE_SPACE));

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

static int parse_xml_annotation(
                const char **p,
                void **xml_state) {


        enum {
                STATE_ANNOTATION,
                STATE_NAME,
                STATE_VALUE
        } state = STATE_ANNOTATION;

        for (;;) {
                _cleanup_free_ char *name = NULL;

                int t;

                t = xml_tokenize(p, &name, xml_state, NULL);
                if (t < 0) {
                        log_error("XML parse error.");
                        return t;
                }

                if (t == XML_END) {
                        log_error("Premature end of XML data.");
                        return -EBADMSG;
                }

                switch (state) {

                case STATE_ANNOTATION:

                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NAME;

                                else if (streq_ptr(name, "value"))
                                        state = STATE_VALUE;

                                else {
                                        log_error("Unexpected <annotation> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "annotation")))

                                return 0;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <annotation>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_ANNOTATION;
                        else {
                                log_error("Unexpected token in <annotation>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_VALUE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_ANNOTATION;
                        else {
                                log_error("Unexpected token in <annotation>. (3)");
                                return -EINVAL;
                        }

                        break;

                default:
                        assert_not_reached("Bad state");
                }
        }
}

static int parse_xml_node(
                const char *prefix,
                Set *paths,
                const char **p,
                void **xml_state) {

        enum {
                STATE_NODE,
                STATE_NODE_NAME,
                STATE_INTERFACE,
                STATE_INTERFACE_NAME,
                STATE_METHOD,
                STATE_METHOD_NAME,
                STATE_METHOD_ARG,
                STATE_METHOD_ARG_NAME,
                STATE_METHOD_ARG_TYPE,
                STATE_METHOD_ARG_DIRECTION,
                STATE_SIGNAL,
                STATE_SIGNAL_NAME,
                STATE_SIGNAL_ARG,
                STATE_SIGNAL_ARG_NAME,
                STATE_SIGNAL_ARG_TYPE,
                STATE_PROPERTY,
                STATE_PROPERTY_NAME,
                STATE_PROPERTY_TYPE,
                STATE_PROPERTY_ACCESS,
        } state = STATE_NODE;

        _cleanup_free_ char *node_path = NULL;
        const char *np = prefix;
        int r;

        for (;;) {
                _cleanup_free_ char *name = NULL;
                int t;

                t = xml_tokenize(p, &name, xml_state, NULL);
                if (t < 0) {
                        log_error("XML parse error.");
                        return t;
                }

                if (t == XML_END) {
                        log_error("Premature end of XML data.");
                        return -EBADMSG;
                }

                switch (state) {

                case STATE_NODE:
                        if (t == XML_ATTRIBUTE_NAME) {

                                if (streq_ptr(name, "name"))
                                        state = STATE_NODE_NAME;
                                else {
                                        log_error("Unexpected <node> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "interface"))
                                        state = STATE_INTERFACE;

                                else if (streq_ptr(name, "node")) {

                                        r = parse_xml_node(np, paths, p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <node> tag %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "node"))) {

                                if (paths) {
                                        if (!node_path) {
                                                node_path = strdup(np);
                                                if (!node_path)
                                                        return log_oom();
                                        }

                                        r = set_put(paths, node_path);
                                        if (r < 0)
                                                return log_oom();
                                        else if (r > 0)
                                                node_path = NULL;
                                }

                                return 0;

                        } else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <node>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_NODE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE) {

                                free(node_path);

                                if (name[0] == '/') {
                                        node_path = name;
                                        name = NULL;
                                } else {

                                        if (endswith(prefix, "/"))
                                                node_path = strappend(prefix, name);
                                        else
                                                node_path = strjoin(prefix, "/", name, NULL);
                                        if (!node_path)
                                                return log_oom();
                                }

                                np = node_path;
                                state = STATE_NODE;
                        } else {
                                log_error("Unexpected token in <node>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_INTERFACE:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_INTERFACE_NAME;
                                else {
                                        log_error("Unexpected <interface> attribute %s.", name);
                                        return -EBADMSG;
                                }

                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "method"))
                                        state = STATE_METHOD;
                                else if (streq_ptr(name, "signal"))
                                        state = STATE_SIGNAL;
                                else if (streq_ptr(name, "property"))
                                        state = STATE_PROPERTY;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <interface> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "interface")))

                                state = STATE_NODE;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <interface>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_INTERFACE_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_INTERFACE;
                        else {
                                log_error("Unexpected token in <interface>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_NAME;
                                else {
                                        log_error("Unexpected <method> attribute %s", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_METHOD_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <method> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "method")))

                                state = STATE_INTERFACE;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <method> (1).");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD;
                        else {
                                log_error("Unexpected token in <method> (2).");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_METHOD_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_METHOD_ARG_TYPE;
                                else if (streq_ptr(name, "direction"))
                                         state = STATE_METHOD_ARG_DIRECTION;
                                else {
                                        log_error("Unexpected method <arg> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected method <arg> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg")))

                                state = STATE_METHOD;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in method <arg>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD_ARG;
                        else {
                                log_error("Unexpected token in method <arg>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD_ARG;
                        else {
                                log_error("Unexpected token in method <arg>. (3)");
                                return -EINVAL;
                        }

                        break;

                case STATE_METHOD_ARG_DIRECTION:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_METHOD_ARG;
                        else {
                                log_error("Unexpected token in method <arg>. (4)");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_NAME;
                                else {
                                        log_error("Unexpected <signal> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "arg"))
                                        state = STATE_SIGNAL_ARG;
                                else if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <signal> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "signal")))

                                state = STATE_INTERFACE;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <signal>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_SIGNAL;
                        else {
                                log_error("Unexpected token in <signal>. (2)");
                                return -EINVAL;
                        }

                        break;


                case STATE_SIGNAL_ARG:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_SIGNAL_ARG_NAME;
                                else if (streq_ptr(name, "type"))
                                        state = STATE_SIGNAL_ARG_TYPE;
                                else {
                                        log_error("Unexpected signal <arg> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {
                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected signal <arg> tag %s.", name);
                                        return -EINVAL;
                                }
                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "arg")))

                                state = STATE_SIGNAL;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in signal <arg> (1).");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_ARG_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_SIGNAL_ARG;
                        else {
                                log_error("Unexpected token in signal <arg> (2).");
                                return -EINVAL;
                        }

                        break;

                case STATE_SIGNAL_ARG_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_SIGNAL_ARG;
                        else {
                                log_error("Unexpected token in signal <arg> (3).");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY:

                        if (t == XML_ATTRIBUTE_NAME) {
                                if (streq_ptr(name, "name"))
                                        state = STATE_PROPERTY_NAME;
                                else if (streq_ptr(name, "type"))
                                        state  = STATE_PROPERTY_TYPE;
                                else if (streq_ptr(name, "access"))
                                        state  = STATE_PROPERTY_ACCESS;
                                else {
                                        log_error("Unexpected <property> attribute %s.", name);
                                        return -EBADMSG;
                                }
                        } else if (t == XML_TAG_OPEN) {

                                if (streq_ptr(name, "annotation")) {
                                        r = parse_xml_annotation(p, xml_state);
                                        if (r < 0)
                                                return r;
                                } else {
                                        log_error("Unexpected <property> tag %s.", name);
                                        return -EINVAL;
                                }

                        } else if (t == XML_TAG_CLOSE_EMPTY ||
                                   (t == XML_TAG_CLOSE && streq_ptr(name, "property")))

                                state = STATE_INTERFACE;

                        else if (t != XML_TEXT || !in_charset(name, WHITESPACE)) {
                                log_error("Unexpected token in <property>. (1)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_NAME:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_PROPERTY;
                        else {
                                log_error("Unexpected token in <property>. (2)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_TYPE:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_PROPERTY;
                        else {
                                log_error("Unexpected token in <property>. (3)");
                                return -EINVAL;
                        }

                        break;

                case STATE_PROPERTY_ACCESS:

                        if (t == XML_ATTRIBUTE_VALUE)
                                state = STATE_PROPERTY;
                        else {
                                log_error("Unexpected token in <property>. (4)");
                                return -EINVAL;
                        }

                        break;
                }
        }
}

static int find_nodes(sd_bus *bus, const char *service, const char *path, Set *paths) {
        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
        _cleanup_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        const char *xml, *p;
        void *xml_state = NULL;
        int r;

        r = sd_bus_call_method(bus, service, path, "org.freedesktop.DBus.Introspectable", "Introspect", &error, &reply, "");
        if (r < 0) {
                log_error("Failed to introspect object %s of service %s: %s", path, service, bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_read(reply, "s", &xml);
        if (r < 0)
                return bus_log_parse_error(r);

        /* fputs(xml, stdout); */

        p = xml;
        for (;;) {
                _cleanup_free_ char *name = NULL;

                r = xml_tokenize(&p, &name, &xml_state, NULL);
                if (r < 0) {
                        log_error("XML parse error");
                        return r;
                }

                if (r == XML_END)
                        break;

                if (r == XML_TAG_OPEN) {

                        if (streq(name, "node")) {
                                r = parse_xml_node(path, paths, &p, &xml_state);
                                if (r < 0)
                                        return r;
                        } else {
                                log_error("Unexpected tag '%s' in introspection data.", name);
                                return -EBADMSG;
                        }
                } else if (r != XML_TEXT || !in_charset(name, WHITESPACE)) {
                        log_error("Unexpected token.");
                        return -EINVAL;
                }
        }

        return 0;
}

static int tree_one(sd_bus *bus, const char *service, const char *prefix) {
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

                q = find_nodes(bus, service, p, paths);
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
                if (r < 0) {
                        log_error("Failed to get name list: %s", strerror(-r));
                        return r;
                }

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

                        q = tree_one(bus, *i, NULL);
                        if (q < 0 && r >= 0)
                                r = q;

                        not_first = true;
                }
        } else {
                pager_open_if_enabled();

                STRV_FOREACH(i, argv+1) {
                        int q;

                        if (i > argv+1)
                                printf("\n");

                        if (argv[2])
                                printf("Service %s%s%s:\n", ansi_highlight(), *i, ansi_highlight_off());

                        q = tree_one(bus, *i, NULL);
                        if (q < 0 && r >= 0)
                                r = q;
                }
        }

        return r;
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
                if (r < 0) {
                        log_error("Failed to add match: %s", strerror(-r));
                        return r;
                }

                added_something = true;
        }

        STRV_FOREACH(i, arg_matches) {
                r = sd_bus_add_match(bus, NULL, *i, NULL, NULL);
                if (r < 0) {
                        log_error("Failed to add match: %s", strerror(-r));
                        return r;
                }

                added_something = true;
        }

        if (!added_something) {
                r = sd_bus_add_match(bus, NULL, "", NULL, NULL);
                if (r < 0) {
                        log_error("Failed to add match: %s", strerror(-r));
                        return r;
                }
        }

        for (;;) {
                _cleanup_bus_message_unref_ sd_bus_message *m = NULL;

                r = sd_bus_process(bus, &m);
                if (r < 0) {
                        log_error("Failed to process bus: %s", strerror(-r));
                        return r;
                }

                if (m) {
                        dump(m, stdout);
                        continue;
                }

                if (r > 0)
                        continue;

                r = sd_bus_wait(bus, (uint64_t) -1);
                if (r < 0) {
                        log_error("Failed to wait for bus: %s", strerror(-r));
                        return r;
                }
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

        if (strv_length(argv) != 2) {
                log_error("Expects one argument.");
                return -EINVAL;
        }

        r = parse_pid(argv[1], &pid);
        if (r < 0)
                r = sd_bus_get_name_creds(bus, argv[1], _SD_BUS_CREDS_ALL, &creds);
        else
                r = sd_bus_creds_new_from_pid(&creds, pid, _SD_BUS_CREDS_ALL);

        if (r < 0) {
                log_error("Failed to get credentials: %s", strerror(-r));
                return r;
        }

        bus_creds_dump(creds, NULL);
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
        if (r < 0) {
                log_error("Failed to prepare bus message: %s", strerror(-r));
                return r;
        }

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

        r = sd_bus_call(bus, m, 0, &error, &reply);
        if (r < 0) {
                log_error("%s", bus_error_message(&error, r));
                return r;
        }

        r = sd_bus_message_is_empty(reply);
        if (r < 0)
                return bus_log_parse_error(r);
        if (r == 0 && !arg_quiet) {
                pager_open_if_enabled();
                bus_message_dump(reply, stdout, 0);
        }

        return 0;
}

static int get_property(sd_bus *bus, char *argv[]) {
        _cleanup_bus_error_free_ sd_bus_error error = SD_BUS_ERROR_NULL;
        unsigned n;
        int r;

        assert(bus);

        n = strv_length(argv);
        if (n < 3) {
                log_error("Expects at least three arguments.");
                return -EINVAL;
        }

        if (n < 5) {
                _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;
                bool not_first = false;

                r = sd_bus_call_method(bus, argv[1], argv[2], "org.freedesktop.DBus.Properties", "GetAll", &error, &reply, "s", strempty(argv[3]));
                if (r < 0) {
                        log_error("%s", bus_error_message(&error, r));
                        return r;
                }

                r = sd_bus_message_enter_container(reply, 'a', "{sv}");
                if (r < 0)
                        return bus_log_parse_error(r);

                for (;;) {
                        const char *name;

                        r = sd_bus_message_enter_container(reply, 'e', "sv");
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (r == 0)
                                break;

                        r = sd_bus_message_read(reply, "s", &name);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (not_first)
                                printf("\n");

                        printf("Property %s:\n", name);

                        r = sd_bus_message_enter_container(reply, 'v', NULL);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        pager_open_if_enabled();
                        bus_message_dump(reply, stdout, BUS_MESSAGE_DUMP_SUBTREE_ONLY);

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        not_first = true;
                }

                r = sd_bus_message_exit_container(reply);
                if (r < 0)
                        return bus_log_parse_error(r);
        } else {
                char **i;

                STRV_FOREACH(i, argv + 4) {
                        _cleanup_bus_message_unref_ sd_bus_message *reply = NULL;

                        r = sd_bus_call_method(bus, argv[1], argv[2], "org.freedesktop.DBus.Properties", "Get", &error, &reply, "ss", argv[3], *i);
                        if (r < 0) {
                                log_error("%s", bus_error_message(&error, r));
                                return r;
                        }

                        r = sd_bus_message_enter_container(reply, 'v', NULL);
                        if (r < 0)
                                return bus_log_parse_error(r);

                        if (i > argv + 4)
                                printf("\n");

                        if (argv[5])
                                printf("Property %s:\n", *i);

                        pager_open_if_enabled();
                        bus_message_dump(reply, stdout, BUS_MESSAGE_DUMP_SUBTREE_ONLY);

                        r = sd_bus_message_exit_container(reply);
                        if (r < 0)
                                return bus_log_parse_error(r);
                }
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
               "     --quiet              Don't show method call reply\n\n"
               "Commands:\n"
               "  list                    List bus names\n"
               "  tree [SERVICE...]       Show object tree of service\n"
               "  monitor [SERVICE...]    Show bus traffic\n"
               "  capture [SERVICE...]    Capture bus traffic as pcap\n"
               "  status SERVICE          Show service name status\n"
               "  call SERVICE PATH INTERFACE METHOD [SIGNATURE [ARGUMENTS...]]\n"
               "                          Call a method\n"
               "  get-property SERVICE PATH [INTERFACE [PROPERTY...]]\n"
               "                          Get property value\n"
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
                        arg_transport = BUS_TRANSPORT_CONTAINER;
                        arg_host = optarg;
                        break;

                case 'q':
                        arg_quiet = true;
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

        if (streq(argv[optind], "call"))
                return call(bus, argv + optind);

        if (streq(argv[optind], "get-property"))
                return get_property(bus, argv + optind);

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
                log_error("Failed to allocate bus: %s", strerror(-r));
                goto finish;
        }

        if (streq_ptr(argv[optind], "monitor") ||
            streq_ptr(argv[optind], "capture")) {

                r = sd_bus_set_monitor(bus, true);
                if (r < 0) {
                        log_error("Failed to set monitor mode: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_negotiate_creds(bus, _SD_BUS_CREDS_ALL);
                if (r < 0) {
                        log_error("Failed to enable credentials: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_negotiate_timestamp(bus, true);
                if (r < 0) {
                        log_error("Failed to enable timestamps: %s", strerror(-r));
                        goto finish;
                }

                r = sd_bus_negotiate_fds(bus, true);
                if (r < 0) {
                        log_error("Failed to enable fds: %s", strerror(-r));
                        goto finish;
                }
        }

        if (arg_address)
                r = sd_bus_set_address(bus, arg_address);
        else {
                switch (arg_transport) {

                case BUS_TRANSPORT_LOCAL:
                        if (arg_user)
                                r = bus_set_address_user(bus);
                        else
                                r = bus_set_address_system(bus);
                        break;

                case BUS_TRANSPORT_REMOTE:
                        r = bus_set_address_system_remote(bus, arg_host);
                        break;

                case BUS_TRANSPORT_CONTAINER:
                        r = bus_set_address_system_container(bus, arg_host);
                        break;

                default:
                        assert_not_reached("Hmm, unknown transport type.");
                }
        }
        if (r < 0) {
                log_error("Failed to set address: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_set_bus_client(bus, true);
        if (r < 0) {
                log_error("Failed to set bus client: %s", strerror(-r));
                goto finish;
        }

        r = sd_bus_start(bus);
        if (r < 0) {
                log_error("Failed to connect to bus: %s", strerror(-r));
                goto finish;
        }

        r = busctl_main(bus, argc, argv);

finish:
        pager_close();

        strv_free(arg_matches);

        return r < 0 ? EXIT_FAILURE : EXIT_SUCCESS;
}
