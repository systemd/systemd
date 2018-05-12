/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

/***
  This file is part of systemd.

  Copyright 2016 Lennart Poettering
***/

#include <stdbool.h>
#include <inttypes.h>

#define VLANID_MAX 4094
#define VLANID_INVALID UINT16_MAX

/* Note that we permit VLAN Id 0 here, as that is apparently OK by the Linux kernel */
static inline bool vlanid_is_valid(uint16_t id) {
        return id <= VLANID_MAX;
}

int parse_vlanid(const char *p, uint16_t *ret);

int config_parse_default_port_vlanid(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
int config_parse_vlanid(const char *unit, const char *filename, unsigned line, const char *section, unsigned section_line, const char *lvalue, int ltype, const char *rvalue, void *data, void *userdata);
