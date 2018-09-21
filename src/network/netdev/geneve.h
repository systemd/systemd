/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

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
