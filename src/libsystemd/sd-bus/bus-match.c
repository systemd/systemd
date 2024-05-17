/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "bus-internal.h"
#include "bus-match.h"
#include "bus-message.h"
#include "fd-util.h"
#include "fileio.h"
#include "hexdecoct.h"
#include "memstream-util.h"
#include "sort-util.h"
#include "string-util.h"
#include "strv.h"

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

static bool BUS_MATCH_IS_COMPARE(enum bus_match_node_type t) {
        return t >= BUS_MATCH_SENDER && t <= BUS_MATCH_ARG_HAS_LAST;
}

static bool BUS_MATCH_CAN_HASH(enum bus_match_node_type t) {
        return (t >= BUS_MATCH_MESSAGE_TYPE && t <= BUS_MATCH_PATH) ||
                (t >= BUS_MATCH_ARG && t <= BUS_MATCH_ARG_LAST) ||
                (t >= BUS_MATCH_ARG_HAS && t <= BUS_MATCH_ARG_HAS_LAST);
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

        if (node->type == BUS_MATCH_ROOT)
                return false;

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
                const char *value_str,
                char **value_strv,
                sd_bus_message *m) {

        assert(node);
        assert(node->type == BUS_MATCH_VALUE);

        /* Tests parameters against this value node, doing prefix
         * magic and stuff. */

        switch (parent_type) {

        case BUS_MATCH_MESSAGE_TYPE:
                return node->value.u8 == value_u8;

        case BUS_MATCH_SENDER:
                if (streq_ptr(node->value.str, value_str))
                        return true;

                if (m->creds.mask & SD_BUS_CREDS_WELL_KNOWN_NAMES) {
                        /* on kdbus we have the well known names list
                         * in the credentials, let's make use of that
                         * for an accurate match */

                        STRV_FOREACH(i, m->creds.well_known_names)
                                if (streq_ptr(node->value.str, *i))
                                        return true;

                } else {

                        /* If we don't have kdbus, we don't know the
                         * well-known names of the senders. In that,
                         * let's just hope that dbus-daemon doesn't
                         * send us stuff we didn't want. */

                        if (node->value.str[0] != ':' && value_str && value_str[0] == ':')
                                return true;
                }

                return false;

        case BUS_MATCH_DESTINATION:
        case BUS_MATCH_INTERFACE:
        case BUS_MATCH_MEMBER:
        case BUS_MATCH_PATH:
        case BUS_MATCH_ARG ... BUS_MATCH_ARG_LAST:

                if (value_str)
                        return streq_ptr(node->value.str, value_str);

                return false;

        case BUS_MATCH_ARG_HAS ... BUS_MATCH_ARG_HAS_LAST: {
                STRV_FOREACH(i, value_strv)
                        if (streq_ptr(node->value.str, *i))
                                return true;

                return false;
        }

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                if (value_str)
                        return namespace_simple_pattern(node->value.str, value_str);

                return false;

        case BUS_MATCH_PATH_NAMESPACE:
                return path_simple_pattern(node->value.str, value_str);

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                if (value_str)
                        return path_complex_pattern(node->value.str, value_str);

                return false;

        default:
                assert_not_reached();
        }
}

static bool value_node_same(
                struct bus_match_node *node,
                enum bus_match_node_type parent_type,
                uint8_t value_u8,
                const char *value_str) {

        /* Tests parameters against this value node, not doing prefix
         * magic and stuff, i.e. this one actually compares the match
         * itself. */

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
        case BUS_MATCH_ARG_HAS ... BUS_MATCH_ARG_HAS_LAST:
        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
        case BUS_MATCH_PATH_NAMESPACE:
        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                return streq(node->value.str, value_str);

        default:
                assert_not_reached();
        }
}

int bus_match_run(
                sd_bus *bus,
                struct bus_match_node *node,
                sd_bus_message *m) {

        _cleanup_strv_free_ char **test_strv = NULL;
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
                        /* Don't run this match as long as the AddMatch() call is not complete yet.
                         *
                         * Don't run this match unless the 'after' counter has been reached.
                         *
                         * Don't run this match more than once per iteration */

                        if (node->leaf.callback->install_slot ||
                            m->read_counter <= node->leaf.callback->after ||
                            node->leaf.callback->last_iteration == bus->iteration_counter)
                                return bus_match_run(bus, node->next, m);

                        node->leaf.callback->last_iteration = bus->iteration_counter;
                }

                r = sd_bus_message_rewind(m, true);
                if (r < 0)
                        return r;

                /* Run the callback. And then invoke siblings. */
                if (node->leaf.callback->callback) {
                        _cleanup_(sd_bus_error_free) sd_bus_error error_buffer = SD_BUS_ERROR_NULL;
                        sd_bus_slot *slot;

                        slot = container_of(node->leaf.callback, sd_bus_slot, match_callback);
                        if (bus) {
                                bus->current_slot = sd_bus_slot_ref(slot);
                                bus->current_handler = node->leaf.callback->callback;
                                bus->current_userdata = slot->userdata;
                        }
                        r = node->leaf.callback->callback(m, slot->userdata, &error_buffer);
                        if (bus) {
                                bus->current_userdata = NULL;
                                bus->current_handler = NULL;
                                bus->current_slot = sd_bus_slot_unref(slot);
                        }

                        r = bus_maybe_reply_error(m, r, &error_buffer);
                        if (r != 0)
                                return r;

                        if (bus && bus->match_callbacks_modified)
                                return 0;
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
                (void) bus_message_get_arg(m, node->type - BUS_MATCH_ARG, &test_str);
                break;

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                (void) bus_message_get_arg(m, node->type - BUS_MATCH_ARG_PATH, &test_str);
                break;

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                (void) bus_message_get_arg(m, node->type - BUS_MATCH_ARG_NAMESPACE, &test_str);
                break;

        case BUS_MATCH_ARG_HAS ... BUS_MATCH_ARG_HAS_LAST:
                (void) bus_message_get_arg_strv(m, node->type - BUS_MATCH_ARG_HAS, &test_strv);
                break;

        default:
                assert_not_reached();
        }

        if (BUS_MATCH_CAN_HASH(node->type)) {
                struct bus_match_node *found;

                /* Lookup via hash table, nice! So let's jump directly. */

                if (test_str)
                        found = hashmap_get(node->compare.children, test_str);
                else if (test_strv) {
                        STRV_FOREACH(i, test_strv) {
                                found = hashmap_get(node->compare.children, *i);
                                if (found) {
                                        r = bus_match_run(bus, found, m);
                                        if (r != 0)
                                                return r;
                                }
                        }

                        found = NULL;
                } else if (node->type == BUS_MATCH_MESSAGE_TYPE)
                        found = hashmap_get(node->compare.children, UINT_TO_PTR(test_u8));
                else
                        found = NULL;

                if (found) {
                        r = bus_match_run(bus, found, m);
                        if (r != 0)
                                return r;
                }
        } else
                /* No hash table, so let's iterate manually... */
                for (struct bus_match_node *c = node->child; c; c = c->next) {
                        if (!value_node_test(c, node->type, test_u8, test_str, test_strv, m))
                                continue;

                        r = bus_match_run(bus, c, m);
                        if (r != 0)
                                return r;

                        if (bus && bus->match_callbacks_modified)
                                return 0;
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

        struct bus_match_node *c, *n = NULL;
        int r;

        assert(where);
        assert(IN_SET(where->type, BUS_MATCH_ROOT, BUS_MATCH_VALUE));
        assert(BUS_MATCH_IS_COMPARE(t));
        assert(ret);

        for (c = where->child; c && c->type != t; c = c->next)
                ;

        if (c) {
                /* Comparison node already exists? Then let's see if the value node exists too. */

                if (t == BUS_MATCH_MESSAGE_TYPE)
                        n = hashmap_get(c->compare.children, UINT_TO_PTR(value_u8));
                else if (BUS_MATCH_CAN_HASH(t))
                        n = hashmap_get(c->compare.children, value_str);
                else
                        for (n = c->child; n && !value_node_same(n, t, value_u8, value_str); n = n->next)
                                ;

                if (n) {
                        *ret = n;
                        return 0;
                }
        } else {
                /* Comparison node, doesn't exist yet? Then let's create it. */

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
                        c->compare.children = hashmap_new(NULL);
                        if (!c->compare.children) {
                                r = -ENOMEM;
                                goto fail;
                        }
                } else if (BUS_MATCH_CAN_HASH(t)) {
                        c->compare.children = hashmap_new(&string_hash_ops);
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

static int bus_match_add_leaf(
                struct bus_match_node *where,
                struct match_callback *callback) {

        struct bus_match_node *n;

        assert(where);
        assert(IN_SET(where->type, BUS_MATCH_ROOT, BUS_MATCH_VALUE));
        assert(callback);

        n = new0(struct bus_match_node, 1);
        if (!n)
                return -ENOMEM;

        n->type = BUS_MATCH_LEAF;
        n->parent = where;
        n->next = where->child;
        if (n->next)
                n->next->prev = n;

        n->leaf.callback = callback;
        callback->match_node = n;

        where->child = n;

        return 1;
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

        if (n == 7 && startswith(k, "arg") && startswith(k + 4, "has")) {
                int j;

                j = undecchar(k[3]);
                if (j < 0)
                        return -EINVAL;

                return BUS_MATCH_ARG_HAS + j;
        }

        if (n == 8 && startswith(k, "arg") && startswith(k + 5, "has")) {
                enum bus_match_node_type t;
                int a, b;

                a = undecchar(k[3]);
                b = undecchar(k[4]);
                if (a <= 0 || b < 0)
                        return -EINVAL;

                t = BUS_MATCH_ARG_HAS + a * 10 + b;
                if (t > BUS_MATCH_ARG_HAS_LAST)
                        return -EINVAL;

                return t;
        }

        return -EINVAL;
}

static int match_component_compare(const struct bus_match_component *a, const struct bus_match_component *b) {
        return CMP(a->type, b->type);
}

void bus_match_parse_free(struct bus_match_component *components, size_t n_components) {
        for (size_t i = 0; i < n_components; i++)
                free(components[i].value_str);

        free(components);
}

int bus_match_parse(
                const char *match,
                struct bus_match_component **ret_components,
                size_t *ret_n_components) {

        struct bus_match_component *components = NULL;
        size_t n_components = 0;
        int r;

        assert(match);
        assert(ret_components);
        assert(ret_n_components);

        CLEANUP_ARRAY(components, n_components, bus_match_parse_free);

        while (*match != '\0') {
                const char *eq, *q;
                enum bus_match_node_type t;
                size_t j = 0;
                _cleanup_free_ char *value = NULL;
                bool escaped = false, quoted;
                uint8_t u;

                /* Avahi's match rules appear to include whitespace, skip over it */
                match += strspn(match, " ");

                eq = strchr(match, '=');
                if (!eq)
                        return -EINVAL;

                t = bus_match_node_type_from_string(match, eq - match);
                if (t < 0)
                        return -EINVAL;

                quoted = eq[1] == '\'';

                for (q = eq + 1 + quoted;; q++) {

                        if (*q == '\0') {

                                if (quoted)
                                        return -EINVAL;

                                if (value)
                                        value[j] = '\0';
                                break;
                        }

                        if (!escaped) {
                                if (*q == '\\') {
                                        escaped = true;
                                        continue;
                                }

                                if (quoted) {
                                        if (*q == '\'') {
                                                if (value)
                                                        value[j] = '\0';
                                                break;
                                        }
                                } else {
                                        if (*q == ',') {
                                                if (value)
                                                        value[j] = '\0';
                                                break;
                                        }
                                }
                        }

                        if (!GREEDY_REALLOC(value, j + 2))
                                return -ENOMEM;

                        value[j++] = *q;
                        escaped = false;
                }

                if (!value) {
                        value = strdup("");
                        if (!value)
                                return -ENOMEM;
                }

                if (t == BUS_MATCH_MESSAGE_TYPE) {
                        r = bus_message_type_from_string(value, &u);
                        if (r < 0)
                                return r;

                        value = mfree(value);
                } else
                        u = 0;

                if (!GREEDY_REALLOC(components, n_components + 1))
                        return -ENOMEM;

                components[n_components++] = (struct bus_match_component) {
                        .type = t,
                        .value_str = TAKE_PTR(value),
                        .value_u8 = u,
                };

                if (q[quoted] == 0)
                        break;

                if (q[quoted] != ',')
                        return -EINVAL;

                match = q + 1 + quoted;
        }

        /* Order the whole thing, so that we always generate the same tree */
        typesafe_qsort(components, n_components, match_component_compare);

        /* Check for duplicates */
        for (size_t i = 0; i+1 < n_components; i++)
                if (components[i].type == components[i+1].type)
                        return -EINVAL;

        *ret_components = TAKE_PTR(components);
        *ret_n_components = n_components;

        return 0;
}

char* bus_match_to_string(struct bus_match_component *components, size_t n_components) {
        _cleanup_(memstream_done) MemStream m = {};
        FILE *f;
        int r;

        if (n_components <= 0)
                return strdup("");

        assert(components);

        f = memstream_init(&m);
        if (!f)
                return NULL;

        for (size_t i = 0; i < n_components; i++) {
                char buf[32];

                if (i != 0)
                        fputc(',', f);

                fputs(bus_match_node_type_to_string(components[i].type, buf, sizeof(buf)), f);
                fputc('=', f);
                fputc('\'', f);

                if (components[i].type == BUS_MATCH_MESSAGE_TYPE)
                        fputs(bus_message_type_to_string(components[i].value_u8), f);
                else
                        fputs(components[i].value_str, f);

                fputc('\'', f);
        }

        char *buffer;
        r = memstream_finalize(&m, &buffer, NULL);
        if (r < 0)
                return NULL;

        return buffer;
}

int bus_match_add(
                struct bus_match_node *root,
                struct bus_match_component *components,
                size_t n_components,
                struct match_callback *callback) {

        int r;

        assert(root);
        assert(callback);

        for (size_t i = 0; i < n_components; i++) {
                r = bus_match_add_compare_value(root,
                                                components[i].type,
                                                components[i].value_u8,
                                                components[i].value_str,
                                                &root);
                if (r < 0)
                        return r;
        }

        return bus_match_add_leaf(root, callback);
}

int bus_match_remove(
                struct bus_match_node *root,
                struct match_callback *callback) {

        struct bus_match_node *node, *pp;

        assert(root);
        assert(callback);

        node = callback->match_node;
        if (!node)
                return 0;

        assert(node->type == BUS_MATCH_LEAF);

        callback->match_node = NULL;

        /* Free the leaf */
        pp = node->parent;
        bus_match_node_free(node);

        /* Prune the tree above */
        while (pp) {
                node = pp;
                pp = node->parent;

                if (!bus_match_node_maybe_free(node))
                        break;
        }

        return 1;
}

void bus_match_free(struct bus_match_node *node) {
        struct bus_match_node *c;

        if (!node)
                return;

        if (BUS_MATCH_CAN_HASH(node->type)) {

                HASHMAP_FOREACH(c, node->compare.children)
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
                return snprintf_ok(buf, l, "arg%i", t - BUS_MATCH_ARG);

        case BUS_MATCH_ARG_PATH ... BUS_MATCH_ARG_PATH_LAST:
                return snprintf_ok(buf, l, "arg%ipath", t - BUS_MATCH_ARG_PATH);

        case BUS_MATCH_ARG_NAMESPACE ... BUS_MATCH_ARG_NAMESPACE_LAST:
                return snprintf_ok(buf, l, "arg%inamespace", t - BUS_MATCH_ARG_NAMESPACE);

        case BUS_MATCH_ARG_HAS ... BUS_MATCH_ARG_HAS_LAST:
                return snprintf_ok(buf, l, "arg%ihas", t - BUS_MATCH_ARG_HAS);

        default:
                return NULL;
        }
}

void bus_match_dump(FILE *out, struct bus_match_node *node, unsigned level) {
        char buf[32];

        if (!node)
                return;

        fprintf(out, "%*s[%s]", 2 * (int) level, "", bus_match_node_type_to_string(node->type, buf, sizeof(buf)));

        if (node->type == BUS_MATCH_VALUE) {
                if (node->parent->type == BUS_MATCH_MESSAGE_TYPE)
                        fprintf(out, " <%u>\n", node->value.u8);
                else
                        fprintf(out, " <%s>\n", node->value.str);
        } else if (node->type == BUS_MATCH_ROOT)
                fputs(" root\n", out);
        else if (node->type == BUS_MATCH_LEAF)
                fprintf(out, " %p/%p\n", node->leaf.callback->callback,
                        container_of(node->leaf.callback, sd_bus_slot, match_callback)->userdata);
        else
                putc('\n', out);

        if (BUS_MATCH_CAN_HASH(node->type)) {
                struct bus_match_node *c;
                HASHMAP_FOREACH(c, node->compare.children)
                        bus_match_dump(out, c, level + 1);
        }

        for (struct bus_match_node *c = node->child; c; c = c->next)
                bus_match_dump(out, c, level + 1);
}

enum bus_match_scope bus_match_get_scope(const struct bus_match_component *components, size_t n_components) {
        bool found_driver = false;

        if (n_components <= 0)
                return BUS_MATCH_GENERIC;

        assert(components);

        /* Checks whether the specified match can only match the
         * pseudo-service for local messages, which we detect by
         * sender, interface or path. If a match is not restricted to
         * local messages, then we check if it only matches on the
         * driver. */

        for (size_t i = 0; i < n_components; i++) {
                const struct bus_match_component *c = components + i;

                if (c->type == BUS_MATCH_SENDER) {
                        if (streq_ptr(c->value_str, "org.freedesktop.DBus.Local"))
                                return BUS_MATCH_LOCAL;

                        if (streq_ptr(c->value_str, "org.freedesktop.DBus"))
                                found_driver = true;
                }

                if (c->type == BUS_MATCH_INTERFACE && streq_ptr(c->value_str, "org.freedesktop.DBus.Local"))
                        return BUS_MATCH_LOCAL;

                if (c->type == BUS_MATCH_PATH && streq_ptr(c->value_str, "/org/freedesktop/DBus/Local"))
                        return BUS_MATCH_LOCAL;
        }

        return found_driver ? BUS_MATCH_DRIVER : BUS_MATCH_GENERIC;
}
