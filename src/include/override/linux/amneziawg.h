/* SPDX-License-Identifier: (GPL-2.0 WITH Linux-syscall-note) OR MIT */
/* Copyright (C) 2015-2019 Jason A. Donenfeld <Jason@zx2c4.com>. All Rights Reserved. */
#pragma once

/* From amnezia-vpn/amneziawg-linux-kernel-module, tag v3.1.20260906,
 * src/uapi/wireguard.h. Names are prefixed with AWG to coexist with <linux/wireguard.h>. */

#define AWG_GENL_NAME "amneziawg"
#define AWG_GENL_VERSION 3

#define AWG_KEY_LEN 32

#define AWG_MULTICAST_GROUP_AUTH "auth"

enum awg_cmd {
        AWG_CMD_GET_DEVICE,
        AWG_CMD_SET_DEVICE,
        AWG_CMD_UNKNOWN_PEER,
        __AWG_CMD_MAX
};
#define AWG_CMD_MAX (__AWG_CMD_MAX - 1)

enum awgdevice_flag {
        AWGDEVICE_F_REPLACE_PEERS = 1U << 0,
        __AWGDEVICE_F_ALL = AWGDEVICE_F_REPLACE_PEERS
};
enum awgdevice_attribute {
        AWGDEVICE_A_UNSPEC,
        AWGDEVICE_A_IFINDEX,
        AWGDEVICE_A_IFNAME,
        AWGDEVICE_A_PRIVATE_KEY,
        AWGDEVICE_A_PUBLIC_KEY,
        AWGDEVICE_A_FLAGS,
        AWGDEVICE_A_LISTEN_PORT,
        AWGDEVICE_A_FWMARK,
        AWGDEVICE_A_PEERS,
        AWGDEVICE_A_JC,
        AWGDEVICE_A_JMIN,
        AWGDEVICE_A_JMAX,
        AWGDEVICE_A_S1,
        AWGDEVICE_A_S2,
        AWGDEVICE_A_H1,
        AWGDEVICE_A_H2,
        AWGDEVICE_A_H3,
        AWGDEVICE_A_H4,
        AWGDEVICE_A_PEER,
        AWGDEVICE_A_S3,
        AWGDEVICE_A_S4,
        AWGDEVICE_A_I1,
        AWGDEVICE_A_I2,
        AWGDEVICE_A_I3,
        AWGDEVICE_A_I4,
        AWGDEVICE_A_I5,
        AWGDEVICE_A_HEADER_PROTECTION_KEY,
        AWGDEVICE_A_CONTENT_PADDING_ADDITION,
        AWGDEVICE_A_REKEY_AFTER_TIME,
        AWGDEVICE_A_REKEY_TIMEOUT,
        AWGDEVICE_A_REJECT_AFTER_TIME,
        AWGDEVICE_A_KEEPALIVE_TIMEOUT,
        AWGDEVICE_A_MAX_HANDSHAKE_ATTEMPTS,
        AWGDEVICE_A_RANDOM_TRAILERS,
        AWGDEVICE_A_DISABLE_COOKIES,
        __AWGDEVICE_A_LAST
};
#define AWGDEVICE_A_MAX (__AWGDEVICE_A_LAST - 1)

enum awgpeer_flag {
        AWGPEER_F_REMOVE_ME = 1U << 0,
        AWGPEER_F_REPLACE_ALLOWEDIPS = 1U << 1,
        AWGPEER_F_UPDATE_ONLY = 1U << 2,
        AWGPEER_F_HAS_ADVANCED_SECURITY = 1U << 3,
        __AWGPEER_F_ALL = AWGPEER_F_REMOVE_ME | AWGPEER_F_REPLACE_ALLOWEDIPS |
                         AWGPEER_F_UPDATE_ONLY | AWGPEER_F_HAS_ADVANCED_SECURITY
};
enum awgpeer_attribute {
        AWGPEER_A_UNSPEC,
        AWGPEER_A_PUBLIC_KEY,
        AWGPEER_A_PRESHARED_KEY,
        AWGPEER_A_FLAGS,
        AWGPEER_A_ENDPOINT,
        AWGPEER_A_PERSISTENT_KEEPALIVE_INTERVAL,
        AWGPEER_A_LAST_HANDSHAKE_TIME,
        AWGPEER_A_RX_BYTES,
        AWGPEER_A_TX_BYTES,
        AWGPEER_A_ALLOWEDIPS,
        AWGPEER_A_PROTOCOL_VERSION,
        AWGPEER_A_ADVANCED_SECURITY,
        __AWGPEER_A_LAST
};
#define AWGPEER_A_MAX (__AWGPEER_A_LAST - 1)

enum awgallowedip_flag {
        AWGALLOWEDIP_F_REMOVE_ME = 1U << 0,
        __AWGALLOWEDIP_F_ALL = AWGALLOWEDIP_F_REMOVE_ME
};
enum awgallowedip_attribute {
        AWGALLOWEDIP_A_UNSPEC,
        AWGALLOWEDIP_A_FAMILY,
        AWGALLOWEDIP_A_IPADDR,
        AWGALLOWEDIP_A_CIDR_MASK,
        AWGALLOWEDIP_A_FLAGS,
        __AWGALLOWEDIP_A_LAST
};
#define AWGALLOWEDIP_A_MAX (__AWGALLOWEDIP_A_LAST - 1)
