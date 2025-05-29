/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "bus-forward.h"

typedef enum BusMatchNodeType {
        BUS_MATCH_ROOT,
        BUS_MATCH_VALUE,
        BUS_MATCH_LEAF,

        /* The following are all different kinds of compare nodes */
        BUS_MATCH_SENDER,
        BUS_MATCH_MESSAGE_TYPE,
        BUS_MATCH_DESTINATION,
        BUS_MATCH_INTERFACE,
        BUS_MATCH_MEMBER,
        BUS_MATCH_PATH,
        BUS_MATCH_PATH_NAMESPACE,
        BUS_MATCH_ARG,
        BUS_MATCH_ARG_LAST = BUS_MATCH_ARG + 63,
        BUS_MATCH_ARG_PATH,
        BUS_MATCH_ARG_PATH_LAST = BUS_MATCH_ARG_PATH + 63,
        BUS_MATCH_ARG_NAMESPACE,
        BUS_MATCH_ARG_NAMESPACE_LAST = BUS_MATCH_ARG_NAMESPACE + 63,
        BUS_MATCH_ARG_HAS,
        BUS_MATCH_ARG_HAS_LAST = BUS_MATCH_ARG_HAS + 63,
        _BUS_MATCH_NODE_TYPE_MAX,
        _BUS_MATCH_NODE_TYPE_INVALID = -EINVAL,
} BusMatchNodeType;

typedef struct BusMatchCallback {
        sd_bus_message_handler_t callback;
        sd_bus_message_handler_t install_callback;

        sd_bus_slot *install_slot; /* The AddMatch() call */

        unsigned last_iteration;

        /* Don't dispatch this slot with messages that arrived in any iteration before or at the this
         * one. We use this to ensure that matches don't apply "retroactively" and confuse the caller:
         * only messages received after the match was installed will be considered. */
        uint64_t after;

        char *match_string;

        BusMatchNode *match_node;
} BusMatchCallback;

typedef struct BusMatchNode {
        BusMatchNodeType type;
        BusMatchNode *parent, *next, *prev, *child;

        union {
                struct {
                        char *str;
                        uint8_t u8;
                } value;
                struct {
                        BusMatchCallback *callback;
                } leaf;
                struct {
                        /* If this is set, then the child is NULL */
                        Hashmap *children;
                } compare;
        };
} BusMatchNode;

typedef struct BusMatchComponent {
        BusMatchNodeType type;
        uint8_t value_u8;
        char *value_str;
} BusMatchComponent;

typedef enum BusMatchScope {
        BUS_MATCH_GENERIC,
        BUS_MATCH_LOCAL,
        BUS_MATCH_DRIVER,
} BusMatchScope;

int bus_match_run(sd_bus *bus, BusMatchNode *root, sd_bus_message *m);

int bus_match_add(BusMatchNode *root, BusMatchComponent *components, size_t n_components, BusMatchCallback *callback);
int bus_match_remove(BusMatchNode *root, BusMatchCallback *callback);

void bus_match_free(BusMatchNode *node);

void bus_match_dump(FILE *out, BusMatchNode *node, unsigned level);

const char* bus_match_node_type_to_string(BusMatchNodeType t, char buf[], size_t l);
BusMatchNodeType bus_match_node_type_from_string(const char *k, size_t n);

int bus_match_parse(const char *match, BusMatchComponent **ret_components, size_t *ret_n_components);
void bus_match_parse_free(BusMatchComponent *components, size_t n_components);
char* bus_match_to_string(BusMatchComponent *components, size_t n_components);

BusMatchScope bus_match_get_scope(const BusMatchComponent *components, size_t n_components);
