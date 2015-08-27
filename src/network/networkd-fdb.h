/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2014 Intel Corporation. All rights reserved.

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

typedef struct FdbEntry FdbEntry;

#include "networkd.h"
#include "networkd-network.h"

struct FdbEntry {
        Network *network;
        unsigned section;

        struct ether_addr *mac_addr;
        uint16_t vlan_id;

        LIST_FIELDS(FdbEntry, static_fdb_entries);
};

int fdb_entry_new_static(Network *const network, const unsigned section, FdbEntry **ret);
void fdb_entry_free(FdbEntry *fdb_entry);
int fdb_entry_configure(Link *const link, FdbEntry *const fdb_entry);

DEFINE_TRIVIAL_CLEANUP_FUNC(FdbEntry*, fdb_entry_free);
#define _cleanup_fdbentry_free_ _cleanup_(fdb_entry_freep)

int config_parse_fdb_hwaddr(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_fdb_vlan_id(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
