/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <netinet/in.h>
#include <linux/if_macsec.h>

#include "ether-addr-util.h"
#include "in-addr-util.h"
#include "netdev.h"
#include "networkd-util.h"
#include "sparse-endian.h"

/* See the definition of MACSEC_NUM_AN in kernel's drivers/net/macsec.c */
#define MACSEC_MAX_ASSOCIATION_NUMBER 4

typedef struct MACsec MACsec;

typedef union MACsecSCI {
        uint64_t as_uint64;

        struct {
                struct ether_addr mac;
                be16_t port;
        } _packed_;
} MACsecSCI;

assert_cc(sizeof(MACsecSCI) == sizeof(uint64_t));

typedef struct SecurityAssociation {
        uint8_t association_number;
        uint32_t packet_number;
        uint8_t key_id[MACSEC_KEYID_LEN];
        uint8_t *key;
        uint32_t key_len;
        char *key_file;
        int activate;
        int use_for_encoding;
} SecurityAssociation;

typedef struct TransmitAssociation {
        MACsec *macsec;
        ConfigSection *section;

        SecurityAssociation sa;
} TransmitAssociation;

typedef struct ReceiveAssociation {
        MACsec *macsec;
        ConfigSection *section;

        MACsecSCI sci;
        SecurityAssociation sa;
} ReceiveAssociation;

typedef struct ReceiveChannel {
        MACsec *macsec;
        ConfigSection *section;

        MACsecSCI sci;
        ReceiveAssociation *rxsa[MACSEC_MAX_ASSOCIATION_NUMBER];
        unsigned n_rxsa;
} ReceiveChannel;

struct MACsec {
        NetDev meta;

        uint16_t port;
        int encrypt;
        uint8_t encoding_an;

        OrderedHashmap *receive_channels;
        OrderedHashmap *receive_channels_by_section;
        OrderedHashmap *transmit_associations_by_section;
        OrderedHashmap *receive_associations_by_section;
};

DEFINE_NETDEV_CAST(MACSEC, MACsec);
extern const NetDevVTable macsec_vtable;

CONFIG_PARSER_PROTOTYPE(config_parse_macsec_port);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_hw_address);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_packet_number);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_key_id);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_key);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_key_file);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_sa_activate);
CONFIG_PARSER_PROTOTYPE(config_parse_macsec_use_for_encoding);
