#pragma once

/***
  This file is part of systemd.

  Copyright 2017 Susant Sahani

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

typedef struct Geneve Geneve;

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-link.h"
#include "networkd-network.h"

#define GENEVE_VID_MAX (1u << 24) - 1

struct Geneve {
        NetDev meta;

        uint32_t id;
        uint32_t flow_label;

        int remote_family;

        uint8_t tos;
        uint8_t ttl;

        uint16_t dest_port;

        bool udpcsum;
        bool udp6zerocsumtx;
        bool udp6zerocsumrx;

        union in_addr_union remote;
};

DEFINE_NETDEV_CAST(GENEVE, Geneve);
extern const NetDevVTable geneve_vtable;

int config_parse_geneve_vni(const char *unit,
                            const char *filename,
                            unsigned line,
                            const char *section,
                            unsigned section_line,
                            const char *lvalue,
                            int ltype,
                            const char *rvalue,
                            void *data,
                            void *userdata);

int config_parse_geneve_address(const char *unit,
                               const char *filename,
                               unsigned line,
                               const char *section,
                               unsigned section_line,
                               const char *lvalue,
                               int ltype,
                               const char *rvalue,
                               void *data,
                               void *userdata);

int config_parse_geneve_flow_label(const char *unit,
                                   const char *filename,
                                   unsigned line,
                                   const char *section,
                                   unsigned section_line,
                                   const char *lvalue,
                                   int ltype,
                                   const char *rvalue,
                                   void *data,
                                   void *userdata);
