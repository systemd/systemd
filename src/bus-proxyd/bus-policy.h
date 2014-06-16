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

#include <inttypes.h>

#include "list.h"
#include "hashmap.h"

typedef enum PolicyItemType {
        _POLICY_ITEM_TYPE_UNSET = 0,
        POLICY_ITEM_ALLOW,
        POLICY_ITEM_DENY,
        _POLICY_ITEM_TYPE_MAX,
        _POLICY_ITEM_TYPE_INVALID = -1,
} PolicyItemType;

typedef enum PolicyItemClass {
        _POLICY_ITEM_CLASS_UNSET = 0,
        POLICY_ITEM_SEND,
        POLICY_ITEM_RECV,
        POLICY_ITEM_OWN,
        POLICY_ITEM_OWN_PREFIX,
        POLICY_ITEM_USER,
        POLICY_ITEM_GROUP,
        POLICY_ITEM_IGNORE,
        _POLICY_ITEM_CLASS_MAX,
        _POLICY_ITEM_CLASS_INVALID = -1,
} PolicyItemClass;

typedef struct PolicyItem PolicyItem;

struct PolicyItem {
        PolicyItemType type;
        PolicyItemClass class;
        char *interface;
        char *member;
        char *error;
        char *path;
        char *name;
        uint8_t message_type;
        uid_t uid;
        gid_t gid;

        bool uid_valid, gid_valid;

        LIST_FIELDS(PolicyItem, items);
};

typedef struct Policy {
        LIST_HEAD(PolicyItem, default_items);
        LIST_HEAD(PolicyItem, mandatory_items);
        Hashmap *user_items;
        Hashmap *group_items;
} Policy;

int policy_load(Policy *p, char **files);
void policy_free(Policy *p);

void policy_dump(Policy *p);

const char* policy_item_type_to_string(PolicyItemType t) _const_;
PolicyItemType policy_item_type_from_string(const char *s) _pure_;

const char* policy_item_class_to_string(PolicyItemClass t) _const_;
PolicyItemClass policy_item_class_from_string(const char *s) _pure_;
