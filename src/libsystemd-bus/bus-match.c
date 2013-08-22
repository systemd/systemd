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

#include "bus-internal.h"
#include "bus-message.h"
#include "bus-match.h"

/* Example:
 *
 *  A: type=signal,sender=foo,interface=bar
 *  B: type=signal,sender=quux,interface=fips
 *  C: type=signal,sender=quux,interface=waldo
 *  D: type=signal,member=test
 *  E: sender=miau
 *  F: type=signal
 *  G: type=signal
 *
 *  results in this tree:
 *
 *  BUS_MATCH_ROOT
 *  + BUS_MATCH_MESSAGE_TYPE
 *  | ` BUS_MATCH_VALUE: value == signal
 *  |   + DBUS_MATCH_SENDER
 *  |   | + BUS_MATCH_VALUE: value == foo
 *  |   | | ` DBUS_MATCH_INTERFACE
 *  |   | |   ` BUS_MATCH_VALUE: value == bar
 *  |   | |     ` BUS_MATCH_LEAF: A
 *  |   | ` BUS_MATCH_VALUE: value == quux
 *  |   |   ` DBUS_MATCH_INTERFACE
 *  |   |     | BUS_MATCH_VALUE: value == fips
 *  |   |     | ` BUS_MATCH_LEAF: B
 *  |   |     ` BUS_MATCH_VALUE: value == waldo
 *  |   |       ` BUS_MATCH_LEAF: C
 *  |   + DBUS_MATCH_MEMBER
 *  |   | ` BUS_MATCH_VALUE: value == test
 *  |   |   ` BUS_MATCH_LEAF: D
 *  |   + BUS_MATCH_LEAF: F
 *  |   ` BUS_MATCH_LEAF: G
 *  ` BUS_MATCH_SENDER
 *    ` BUS_MATCH_VALUE: value == miau
 *      ` BUS_MATCH_LEAF: E
 */

static inline bool BUS_MATCH_IS_COMPARE(enum bus_match_node_type t) {
        return t >= BUS_MATCH_MESSAGE_TYPE && t <= BUS_MATCH_ARG_NAMESPACE_LAST;
}

static inline bool BUS_MATCH_CAN_HASH(enum bus_match_node_type t) {
        return (t >= BUS_MATCH_MESSAGE_TYPE && t <= BUS_MATCH_PATH) ||
                (t >= BUS_MATCH_ARG && t <= BUS_MATCH_ARG_LAST);
}

static void bus_match_node_free(struct bus_match_node *node) {
        assert(node);
        assert(node->parent);
        assert(!node->child);
        assert(node->type != BUS_MATCH_ROOT);
        assert(node->type < _BUS_MATCH_NODE_TYPE_MAX);

        if (node->parent->child) {
                /* We are apparently linked into the parent's child
                 * list. Let's remove us from there. */
                if (node->prev) {
                        assert(node->prev->next == node);
                        node->prev->next = node->next;
                } else {
                        assert(node->parent->child == node);
                        node->parent->child = node->next;
                }

                if (node->next)
                        node->next->prev = node->prev;
        }

        if (node->type == BUS_MATCH_VALUE) {
                /* We might be in the parent's hash table, so clean
                 * this up */

                if (node->parent->type == BUS_MATCH_MESSAGE_TYPE)
                        hashmap_remove(node->parent->compare.children, UINT_TO_PTR(node->value.u8));
                else if (BUS_MATCH_CAN_HASH(node->parent->type) && node->value.str)
                        hashmap_remove(node->parent->compare.children, node->value.str);

                free(node->value.str);
        }

        if (BUS_MATCH_IS_COMPARE(node->type)) {
                assert(hashmap_isempty(node->compare.children));
                hashmap_free(node->compare.children);
        }

        free(node);
}

static bool bus_match_node_maybe_free(struct bus_match_node *node) {
        assert(node);

        if (node->child)
                return false;

        if (BUS_MATCH_IS_COMPARE(node->type) && !hashmap_isempty(node->compare.children))
                return true;

        bus_match_node_free(node);
        return true;
}

static bool value_node_test(
                struct bus_match_node *node,
                enum bus_match_node_type parent_type,
                uint8_t value_u8,
                const char *value_str) {

        assert(node);
        assert(node->type == BUS_MATCH_VALUE);

        /* Tests parameters against this value node, doing prefix
         * magic and stuff. */

        switch (parent_type) {

        case BUS_MATCH_MESSAGE_TYPE:
                return node->value.u8 == value_u8;

        case BUS_MATCH_SENDER:
        case BUS_MATCH_DESTINATION:
        case BUS_MATCH_INTERFACE:
        case BUS_MATCH_MEMBER:
        case BUS_MATCH_PATH:
        case BUS_MATCH_ARG ... BUS_MATCH_ARG_LAST:
                return streq_ptr(node->value.str, value_str);

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                return namespace_simple_pattern(node->value.str, value_str);

        case BUS_MATCH_PATH_NAMESPACE:
                return path_simple_pattern(node->value.str, value_str);

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                return path_complex_pattern(node->value.str, value_str);

        default:
                assert_not_reached("Invalid node type");
        }
}

static bool value_node_same(
                struct bus_match_node *node,
                enum bus_match_node_type parent_type,
                uint8_t value_u8,
                const char *value_str) {

        /* Tests parameters against this value node, not doing prefix
         * magic and stuff, i.e. this one actually compares the match
         * itself.*/

        assert(node);
        assert(node->type == BUS_MATCH_VALUE);

        switch (parent_type) {

        case BUS_MATCH_MESSAGE_TYPE:
                return node->value.u8 == value_u8;

        case BUS_MATCH_SENDER:
        case BUS_MATCH_DESTINATION:
        case BUS_MATCH_INTERFACE:
        case BUS_MATCH_MEMBER:
        case BUS_MATCH_PATH:
        case BUS_MATCH_ARG ... BUS_MATCH_ARG_LAST:
        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
        case BUS_MATCH_PATH_NAMESPACE:
        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                return streq(node->value.str, value_str);

        default:
                assert_not_reached("Invalid node type");
        }
}

int bus_match_run(
                sd_bus *bus,
                struct bus_match_node *node,
                sd_bus_message *m) {


        const char *test_str = NULL;
        uint8_t test_u8 = 0;
        int r;

        assert(m);

        if (!node)
                return 0;

        if (bus && bus->match_callbacks_modified)
                return 0;

        /* Not these special semantics: when traversing the tree we
         * usually let bus_match_run() when called for a node
         * recursively invoke bus_match_run(). There's are two
         * exceptions here though, which are BUS_NODE_ROOT (which
         * cannot have a sibling), and BUS_NODE_VALUE (whose siblings
         * are invoked anyway by its parent. */

        switch (node->type) {

        case BUS_MATCH_ROOT:

                /* Run all children. Since we cannot have any siblings
                 * we won't call any. The children of the root node
                 * are compares or leaves, they will automatically
                 * call their siblings. */
                return bus_match_run(bus, node->child, m);

        case BUS_MATCH_VALUE:

                /* Run all children. We don't execute any siblings, we
                 * assume our caller does that. The children of value
                 * nodes are compares or leaves, they will
                 * automatically call their siblings */

                assert(node->child);
                return bus_match_run(bus, node->child, m);

        case BUS_MATCH_LEAF:

                if (bus) {
                        if (node->leaf.last_iteration == bus->iteration_counter)
                                return 0;

                        node->leaf.last_iteration = bus->iteration_counter;
                }

                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;

                /* Run the callback. And then invoke siblings. */
                if (node->leaf.callback) {
                        r = node->leaf.callback(bus, m, node->leaf.userdata);
                        if (r != 0)
                                return r;
                }

                return bus_match_run(bus, node->next, m);

        case BUS_MATCH_MESSAGE_TYPE:
                test_u8 = m->header->type;
                break;

        case BUS_MATCH_SENDER:
                test_str = m->sender;
                /* FIXME: resolve test_str from a well-known to a unique name first */
                break;

        case BUS_MATCH_DESTINATION:
                test_str = m->destination;
                break;

        case BUS_MATCH_INTERFACE:
                test_str = m->interface;
                break;

        case BUS_MATCH_MEMBER:
                test_str = m->member;
                break;

        case BUS_MATCH_PATH:
        case BUS_MATCH_PATH_NAMESPACE:
                test_str = m->path;
                break;

        case BUS_MATCH_ARG ... BUS_MATCH_ARG_LAST:
                test_str = bus_message_get_arg(m, node->type - BUS_MATCH_ARG);
                break;

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                test_str = bus_message_get_arg(m, node->type - BUS_MATCH_ARG_PATH);
                break;

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                test_str = bus_message_get_arg(m, node->type - BUS_MATCH_ARG_NAMESPACE);
                break;

        default:
                assert_not_reached("Unknown match type.");
        }

        if (BUS_MATCH_CAN_HASH(node->type)) {
                struct bus_match_node *found;

                /* Lookup via hash table, nice! So let's jump directly. */

                if (test_str)
                        found = hashmap_get(node->compare.children, test_str);
                else if (node->type == BUS_MATCH_MESSAGE_TYPE)
                        found = hashmap_get(node->compare.children, UINT_TO_PTR(test_u8));
                else
                        found = NULL;

                if (found) {
                        r = bus_match_run(bus, found, m);
                        if (r != 0)
                                return r;
                }
        } else {
                struct bus_match_node *c;

                /* No hash table, so let's iterate manually... */

                for (c = node->child; c; c = c->next) {
                        if (!value_node_test(c, node->type, test_u8, test_str))
                                continue;

                        r = bus_match_run(bus, c, m);
                        if (r != 0)
                                return r;
                }
        }

        if (bus && bus->match_callbacks_modified)
                return 0;

        /* And now, let's invoke our siblings */
        return bus_match_run(bus, node->next, m);
}

static int bus_match_add_compare_value(
                struct bus_match_node *where,
                enum bus_match_node_type t,
                uint8_t value_u8,
                const char *value_str,
                struct bus_match_node **ret) {

        struct bus_match_node *c = NULL, *n = NULL;
        int r;

        assert(where);
        assert(where->type == BUS_MATCH_ROOT || where->type == BUS_MATCH_VALUE);
        assert(BUS_MATCH_IS_COMPARE(t));
        assert(ret);

        for (c = where->child; c && c->type != t; c = c->next)
                ;

        if (c) {
                /* Comparison node already exists? Then let's see if
                 * the value node exists too. */

                if (t == BUS_MATCH_MESSAGE_TYPE)
                        n = hashmap_get(c->compare.children, UINT_TO_PTR(value_u8));
                else if (BUS_MATCH_CAN_HASH(t))
                        n = hashmap_get(c->compare.children, value_str);
                else {
                        for (n = c->child; n && !value_node_same(n, t, value_u8, value_str); n = n->next)
                                ;
                }

                if (n) {
                        *ret = n;
                        return 0;
                }
        } else {
                /* Comparison node, doesn't exist yet? Then let's
                 * create it. */

                c = new0(struct bus_match_node, 1);
                if (!c) {
                        r = -ENOMEM;
                        goto fail;
                }

                c->type = t;
                c->parent = where;
                c->next = where->child;
                if (c->next)
                        c->next->prev = c;
                where->child = c;

                if (t == BUS_MATCH_MESSAGE_TYPE) {
                        c->compare.children = hashmap_new(trivial_hash_func, trivial_compare_func);
                        if (!c->compare.children) {
                                r = -ENOMEM;
                                goto fail;
                        }
                } else if (BUS_MATCH_CAN_HASH(t)) {
                        c->compare.children = hashmap_new(string_hash_func, string_compare_func);
                        if (!c->compare.children) {
                                r = -ENOMEM;
                                goto fail;
                        }
                }
        }

        n = new0(struct bus_match_node, 1);
        if (!n) {
                r = -ENOMEM;
                goto fail;
        }

        n->type = BUS_MATCH_VALUE;
        n->value.u8 = value_u8;
        if (value_str) {
                n->value.str = strdup(value_str);
                if (!n->value.str) {
                        r = -ENOMEM;
                        goto fail;
                }
        }

        n->parent = c;
        if (c->compare.children) {

                if (t == BUS_MATCH_MESSAGE_TYPE)
                        r = hashmap_put(c->compare.children, UINT_TO_PTR(value_u8), n);
                else
                        r = hashmap_put(c->compare.children, n->value.str, n);

                if (r < 0)
                        goto fail;
        } else {
                n->next = c->child;
                if (n->next)
                        n->next->prev = n;
                c->child = n;
        }

        *ret = n;
        return 1;

fail:
        if (c)
                bus_match_node_maybe_free(c);

        if (n) {
                free(n->value.str);
                free(n);
        }

        return r;
}

static int bus_match_find_compare_value(
                struct bus_match_node *where,
                enum bus_match_node_type t,
                uint8_t value_u8,
                const char *value_str,
                struct bus_match_node **ret) {

        struct bus_match_node *c, *n;

        assert(where);
        assert(where->type == BUS_MATCH_ROOT || where->type == BUS_MATCH_VALUE);
        assert(BUS_MATCH_IS_COMPARE(t));
        assert(ret);

        for (c = where->child; c && c->type != t; c = c->next)
                ;

        if (!c)
                return 0;

        if (t == BUS_MATCH_MESSAGE_TYPE)
                n = hashmap_get(c->compare.children, UINT_TO_PTR(value_u8));
        else if (BUS_MATCH_CAN_HASH(t))
                n = hashmap_get(c->compare.children, value_str);
        else {
                for (n = c->child; !value_node_same(n, t, value_u8, value_str); n = n->next)
                        ;
        }

        if (n) {
                *ret = n;
                return 1;
        }

        return 0;
}

static int bus_match_add_leaf(
                struct bus_match_node *where,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t cookie,
                struct bus_match_node **ret) {

        struct bus_match_node *n;

        assert(where);
        assert(where->type == BUS_MATCH_ROOT || where->type == BUS_MATCH_VALUE);
        assert(ret);

        n = new0(struct bus_match_node, 1);
        if (!n)
                return -ENOMEM;

        n->type = BUS_MATCH_LEAF;
        n->parent = where;
        n->next = where->child;
        if (n->next)
                n->next->prev = n;
        n->leaf.callback = callback;
        n->leaf.userdata = userdata;
        n->leaf.cookie = cookie;

        where->child = n;

        *ret = n;
        return 1;
}

static int bus_match_find_leaf(
                struct bus_match_node *where,
                sd_bus_message_handler_t callback,
                void *userdata,
                struct bus_match_node **ret) {

        struct bus_match_node *c;

        assert(where);
        assert(where->type == BUS_MATCH_ROOT || where->type == BUS_MATCH_VALUE);
        assert(ret);

        for (c = where->child; c; c = c->next) {
                if (c->type == BUS_MATCH_LEAF &&
                    c->leaf.callback == callback &&
                    c->leaf.userdata == userdata) {
                        *ret = c;
                        return 1;
                }
        }

        return 0;
}

enum bus_match_node_type bus_match_node_type_from_string(const char *k, size_t n) {
        assert(k);

        if (n == 4 && startswith(k, "type"))
                return BUS_MATCH_MESSAGE_TYPE;
        if (n == 6 && startswith(k, "sender"))
                return BUS_MATCH_SENDER;
        if (n == 11 && startswith(k, "destination"))
                return BUS_MATCH_DESTINATION;
        if (n == 9 && startswith(k, "interface"))
                return BUS_MATCH_INTERFACE;
        if (n == 6 && startswith(k, "member"))
                return BUS_MATCH_MEMBER;
        if (n == 4 && startswith(k, "path"))
                return BUS_MATCH_PATH;
        if (n == 14 && startswith(k, "path_namespace"))
                return BUS_MATCH_PATH_NAMESPACE;

        if (n == 4 && startswith(k, "arg")) {
                int j;

                j = undecchar(k[3]);
                if (j < 0)
                        return -EINVAL;

                return BUS_MATCH_ARG + j;
        }

        if (n == 5 && startswith(k, "arg")) {
                int a, b;
                enum bus_match_node_type t;

                a = undecchar(k[3]);
                b = undecchar(k[4]);
                if (a <= 0 || b < 0)
                        return -EINVAL;

                t = BUS_MATCH_ARG + a * 10 + b;
                if (t > BUS_MATCH_ARG_LAST)
                        return -EINVAL;

                return t;
        }

        if (n == 8 && startswith(k, "arg") && startswith(k + 4, "path")) {
                int j;

                j = undecchar(k[3]);
                if (j < 0)
                        return -EINVAL;

                return BUS_MATCH_ARG_PATH + j;
        }

        if (n == 9 && startswith(k, "arg") && startswith(k + 5, "path")) {
                enum bus_match_node_type t;
                int a, b;

                a = undecchar(k[3]);
                b = undecchar(k[4]);
                if (a <= 0 || b < 0)
                        return -EINVAL;

                t = BUS_MATCH_ARG_PATH + a * 10 + b;
                if (t > BUS_MATCH_ARG_PATH_LAST)
                        return -EINVAL;

                return t;
        }

        if (n == 13 && startswith(k, "arg") && startswith(k + 4, "namespace")) {
                int j;

                j = undecchar(k[3]);
                if (j < 0)
                        return -EINVAL;

                return BUS_MATCH_ARG_NAMESPACE + j;
        }

        if (n == 14 && startswith(k, "arg") && startswith(k + 5, "namespace")) {
                enum bus_match_node_type t;
                int a, b;

                a = undecchar(k[3]);
                b = undecchar(k[4]);
                if (a <= 0 || b < 0)
                        return -EINVAL;

                t = BUS_MATCH_ARG_NAMESPACE + a * 10 + b;
                if (t > BUS_MATCH_ARG_NAMESPACE_LAST)
                        return -EINVAL;

                return t;
        }

        return -EINVAL;
}

static int match_component_compare(const void *a, const void *b) {
        const struct bus_match_component *x = a, *y = b;

        if (x->type < y->type)
                return -1;
        if (x->type > y->type)
                return 1;

        return 0;
}

void bus_match_parse_free(struct bus_match_component *components, unsigned n_components) {
        unsigned i;

        for (i = 0; i < n_components; i++)
                free(components[i].value_str);

        free(components);
}

int bus_match_parse(
                const char *match,
                struct bus_match_component **_components,
                unsigned *_n_components) {

        const char *p = match;
        struct bus_match_component *components = NULL;
        size_t components_allocated = 0;
        unsigned n_components = 0, i;
        _cleanup_free_ char *value = NULL;
        int r;

        assert(match);
        assert(_components);
        assert(_n_components);

        while (*p != 0) {
                const char *eq, *q;
                enum bus_match_node_type t;
                unsigned j = 0;
                size_t value_allocated = 0;
                bool escaped = false;
                uint8_t u;

                eq = strchr(p, '=');
                if (!eq)
                        return -EINVAL;

                if (eq[1] != '\'')
                        return -EINVAL;

                t = bus_match_node_type_from_string(p, eq - p);
                if (t < 0)
                        return -EINVAL;

                for (q = eq + 2;; q++) {

                        if (*q == 0) {
                                r = -EINVAL;
                                goto fail;
                        }

                        if (!escaped) {
                                if (*q == '\\') {
                                        escaped = true;
                                        continue;
                                }
                                if (*q == '\'') {
                                        if (value)
                                                value[j] = 0;
                                        break;
                                }
                        }

                        if (!GREEDY_REALLOC(value, value_allocated, j + 2)) {
                                r = -ENOMEM;
                                goto fail;
                        }

                        value[j++] = *q;
                        escaped = false;
                }

                if (t == BUS_MATCH_MESSAGE_TYPE) {
                        r = bus_message_type_from_string(value, &u);
                        if (r < 0)
                                goto fail;

                        free(value);
                        value = NULL;
                } else
                        u = 0;

                if (!GREEDY_REALLOC(components, components_allocated, n_components + 1)) {
                        r = -ENOMEM;
                        goto fail;
                }

                components[n_components].type = t;
                components[n_components].value_str = value;
                components[n_components].value_u8 = u;
                n_components++;

                value = NULL;

                if (q[1] == 0)
                        break;

                if (q[1] != ',') {
                        r = -EINVAL;
                        goto fail;
                }

                p = q + 2;
        }

        /* Order the whole thing, so that we always generate the same tree */
        qsort(components, n_components, sizeof(struct bus_match_component), match_component_compare);

        /* Check for duplicates */
        for (i = 0; i+1 < n_components; i++)
                if (components[i].type == components[i+1].type) {
                        r = -EINVAL;
                        goto fail;
                }

        *_components = components;
        *_n_components = n_components;

        return 0;

fail:
        bus_match_parse_free(components, n_components);
        return r;
}

int bus_match_add(
                struct bus_match_node *root,
                struct bus_match_component *components,
                unsigned n_components,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t cookie,
                struct bus_match_node **ret) {

        unsigned i;
        struct bus_match_node *n;
        int r;

        assert(root);

        n = root;
        for (i = 0; i < n_components; i++) {
                r = bus_match_add_compare_value(
                                n, components[i].type,
                                components[i].value_u8, components[i].value_str, &n);
                if (r < 0)
                        return r;
        }

        r = bus_match_add_leaf(n, callback, userdata, cookie, &n);
        if (r < 0)
                return r;

        if (ret)
                *ret = n;

        return 0;
}

int bus_match_remove(
                struct bus_match_node *root,
                struct bus_match_component *components,
                unsigned n_components,
                sd_bus_message_handler_t callback,
                void *userdata,
                uint64_t *cookie) {

        unsigned i;
        struct bus_match_node *n, **gc;
        int r;

        assert(root);

        gc = newa(struct bus_match_node*, n_components);

        n = root;
        for (i = 0; i < n_components; i++) {
                r = bus_match_find_compare_value(
                                n, components[i].type,
                                components[i].value_u8, components[i].value_str,
                                &n);
                if (r <= 0)
                        return r;

                gc[i] = n;
        }

        r = bus_match_find_leaf(n, callback, userdata, &n);
        if (r <= 0)
                return r;

        if (cookie)
                *cookie = n->leaf.cookie;

        /* Free the leaf */
        bus_match_node_free(n);

        /* Prune the tree above */
        for (i = n_components; i > 0; i --) {
                struct bus_match_node *p = gc[i-1]->parent;

                if (!bus_match_node_maybe_free(gc[i-1]))
                        break;

                if (!bus_match_node_maybe_free(p))
                        break;
        }

        return r;
}

void bus_match_free(struct bus_match_node *node) {
        struct bus_match_node *c;

        if (!node)
                return;

        if (BUS_MATCH_CAN_HASH(node->type)) {
                Iterator i;

                HASHMAP_FOREACH(c, node->compare.children, i)
                        bus_match_free(c);

                assert(hashmap_isempty(node->compare.children));
        }

        while ((c = node->child))
                bus_match_free(c);

        if (node->type != BUS_MATCH_ROOT)
                bus_match_node_free(node);
}

const char* bus_match_node_type_to_string(enum bus_match_node_type t, char buf[], size_t l) {
        switch (t) {

        case BUS_MATCH_ROOT:
                return "root";

        case BUS_MATCH_VALUE:
                return "value";

        case BUS_MATCH_LEAF:
                return "leaf";

        case BUS_MATCH_MESSAGE_TYPE:
                return "type";

        case BUS_MATCH_SENDER:
                return "sender";

        case BUS_MATCH_DESTINATION:
                return "destination";

        case BUS_MATCH_INTERFACE:
                return "interface";

        case BUS_MATCH_MEMBER:
                return "member";

        case BUS_MATCH_PATH:
                return "path";

        case BUS_MATCH_PATH_NAMESPACE:
                return "path_namespace";

        case BUS_MATCH_ARG ... BUS_MATCH_ARG_LAST:
                snprintf(buf, l, "arg%i", t - BUS_MATCH_ARG);
                return buf;

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                snprintf(buf, l, "arg%ipath", t - BUS_MATCH_ARG_PATH);
                return buf;

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                snprintf(buf, l, "arg%inamespace", t - BUS_MATCH_ARG_NAMESPACE);
                return buf;

        default:
                return NULL;
        }
}

void bus_match_dump(struct bus_match_node *node, unsigned level) {
        struct bus_match_node *c;
        _cleanup_free_ char *pfx = NULL;
        char buf[32];

        if (!node)
                return;

        pfx = strrep("  ", level);
        printf("%s[%s]", strempty(pfx), bus_match_node_type_to_string(node->type, buf, sizeof(buf)));

        if (node->type == BUS_MATCH_VALUE) {
                if (node->parent->type == BUS_MATCH_MESSAGE_TYPE)
                        printf(" <%u>\n", node->value.u8);
                else
                        printf(" <%s>\n", node->value.str);
        } else if (node->type == BUS_MATCH_ROOT)
                puts(" root");
        else if (node->type == BUS_MATCH_LEAF)
                printf(" %p/%p\n", node->leaf.callback, node->leaf.userdata);
        else
                putchar('\n');

        if (BUS_MATCH_CAN_HASH(node->type)) {
                Iterator i;

                HASHMAP_FOREACH(c, node->compare.children, i)
                        bus_match_dump(c, level + 1);
        }

        for (c = node->child; c; c = c->next)
                bus_match_dump(c, level + 1);
}
