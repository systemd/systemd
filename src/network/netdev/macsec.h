/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/if_macsec.h>

#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-util.h"

typedef struct MACsec MACsec;

typedef struct ReceiveChannel {
        MACsec *mac_sec;
        NetworkConfigSection *section;

        uint16_t port;
        struct ether_addr mac;
} ReceiveChannel;

typedef struct TransmitAssociation {
        MACsec *mac_sec;
        NetworkConfigSection *section;

        uint8_t an;
        uint8_t active;
        uint8_t key_id[MACSEC_KEYID_LEN];
        uint8_t key[MACSEC_MAX_KEY_LEN];

        uint32_t pn;
        uint32_t key_len;
} TransmitAssociation;

typedef struct ReceiveAssociation {
        MACsec *mac_sec;
        NetworkConfigSection *section;

        TransmitAssociation sa;
        ReceiveChannel rx;

} ReceiveAssociation;

struct MACsec {
        NetDev meta;

        uint16_t port;
        int encrypt;

        OrderedHashmap *rx_channel_by_section;
        OrderedHashmap *transmit_association_by_section;
        OrderedHashmap *receive_association_by_section;
};

DEFINE_NETDEV_CAST(MACSEC, MACsec);
extern const NetDevVTable macsec_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_macsec_port);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_hw_address);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_pn);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_key_id);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_key);
