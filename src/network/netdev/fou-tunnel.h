/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#if HAVE_LINUX_FOU_H
#include <linux/fou.h>
#endif

#include "in-addr-util.h"
#include "missing.h"
#include "netdev/netdev.h"

typedef enum FooOverUDPEncapType {
        NETDEV_FOO_OVER_UDP_ENCAP_UNSPEC = FOU_ENCAP_UNSPEC,
        NETDEV_FOO_OVER_UDP_ENCAP_DIRECT = FOU_ENCAP_DIRECT,
        NETDEV_FOO_OVER_UDP_ENCAP_GUE = FOU_ENCAP_GUE,
        _NETDEV_FOO_OVER_UDP_ENCAP_MAX,
        _NETDEV_FOO_OVER_UDP_ENCAP_INVALID = -1,
} FooOverUDPEncapType;

typedef struct FouTunnel {
        NetDev meta;

        uint8_t fou_protocol;

        uint16_t port;

        FooOverUDPEncapType fou_encap_type;
} FouTunnel;

DEFINE_NETDEV_CAST(FOU, FouTunnel);
extern const NetDevVTable foutnl_vtable;

const char *fou_encap_type_to_string(FooOverUDPEncapType d) _const_;
FooOverUDPEncapType fou_encap_type_from_string(const char *d) _pure_;

int config_parse_fou_encap_type(const char *unit, const char *filename,
                                unsigned line, const char *section,
                                unsigned section_line, const char *lvalue,
                                int ltype, const char *rvalue, void *data,
                                void *userdata);
