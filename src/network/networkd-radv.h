/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Intel Corporation. All rights reserved.
***/

#include "networkd-address.h"
#include "networkd-link.h"

typedef struct Prefix Prefix;

struct Prefix {
        Network *network;
        NetworkConfigSection *section;

        sd_radv_prefix *radv_prefix;

        LIST_FIELDS(Prefix, prefixes);
};

int prefix_new(Prefix **ret);
void prefix_free(Prefix *prefix);
int prefix_new_static(Network *network, const char *filename, unsigned section,
                      Prefix **ret);

DEFINE_TRIVIAL_CLEANUP_FUNC(Prefix*, prefix_free);

int config_parse_router_prefix_delegation(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_router_preference(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix_flags(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_prefix_lifetime(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);

int radv_emit_dns(Link *link);
int radv_configure(Link *link);
