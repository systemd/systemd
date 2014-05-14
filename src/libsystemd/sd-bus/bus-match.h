/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "hashmap.h"

#include "sd-bus.h"

enum bus_match_node_type {
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
        _BUS_MATCH_NODE_TYPE_MAX,
        _BUS_MATCH_NODE_TYPE_INVALID = -1
};

struct bus_match_node {
        enum bus_match_node_type type;
        struct bus_match_node *parent, *next, *prev, *child;

        union {
                struct {
                        char *str;
                        uint8_t u8;
                } value;
                struct {
                        struct match_callback *callback;
                } leaf;
                struct {
                        /* If this is set, then the child is NULL */
                        Hashmap *children;
                } compare;
        };
};

struct bus_match_component {
        enum bus_match_node_type type;
        uint8_t value_u8;
        char *value_str;
};

int bus_match_run(sd_bus *bus, struct bus_match_node *root, sd_bus_message *m);

int bus_match_add(struct bus_match_node *root, struct bus_match_component *components, unsigned n_components, struct match_callback *callback);
int bus_match_remove(struct bus_match_node *root, struct match_callback *callback);

int bus_match_find(struct bus_match_node *root, struct bus_match_component *components, unsigned n_components, sd_bus_message_handler_t callback, void *userdata, struct match_callback **ret);

void bus_match_free(struct bus_match_node *node);

void bus_match_dump(struct bus_match_node *node, unsigned level);

const char* bus_match_node_type_to_string(enum bus_match_node_type t, char buf[], size_t l);
enum bus_match_node_type bus_match_node_type_from_string(const char *k, size_t n);

int bus_match_parse(const char *match, struct bus_match_component **_components, unsigned *_n_components);
void bus_match_parse_free(struct bus_match_component *components, unsigned n_components);
char *bus_match_to_string(struct bus_match_component *components, unsigned n_components);
