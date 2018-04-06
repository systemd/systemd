/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright (C) 2016 BISDN GmbH. All rights reserved.
***/

#include <stdint.h>

typedef struct Link Link;

int br_vlan_configure(Link *link, uint16_t pvid, uint32_t *br_vid_bitmap, uint32_t *br_untagged_bitmap);

int config_parse_brvlan_pvid(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_brvlan_vlan(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_brvlan_untagged(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
