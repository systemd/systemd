/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-id128.h"

#include "ether-addr-util.h"
#include "macro.h"
#include "sparse-endian.h"
#include "time-util.h"
#include "unaligned.h"

#define SYSTEMD_PEN    43793

typedef enum DUIDType {
        DUID_TYPE_LLT       = 1,
        DUID_TYPE_EN        = 2,
        DUID_TYPE_LL        = 3,
        DUID_TYPE_UUID      = 4,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID  = -EINVAL,
} DUIDType;

/* RFC 3315 section 9.1:
 *      A DUID can be no more than 128 octets long (not including the type code).
 */
#define MAX_DUID_LEN 128

/* https://tools.ietf.org/html/rfc3315#section-9.1 */
struct duid {
        be16_t type;
        union {
                struct {
                        /* DUID_TYPE_LLT */
                        be16_t htype;
                        be32_t time;
                        uint8_t haddr[0];
                } _packed_ llt;
                struct {
                        /* DUID_TYPE_EN */
                        be32_t pen;
                        uint8_t id[8];
                } _packed_ en;
                struct {
                        /* DUID_TYPE_LL */
                        be16_t htype;
                        uint8_t haddr[0];
                } _packed_ ll;
                struct {
                        /* DUID_TYPE_UUID */
                        sd_id128_t uuid;
                } _packed_ uuid;
                struct {
                        uint8_t data[MAX_DUID_LEN];
                } _packed_ raw;
        };
} _packed_;

int dhcp_validate_duid_len(DUIDType duid_type, size_t duid_len, bool strict);
int dhcp_identifier_set_duid_en(bool test_mode, struct duid *ret_duid, size_t *ret_len);
int dhcp_identifier_set_duid(
                DUIDType duid_type,
                const struct hw_addr_data *hw_addr,
                uint16_t arp_type,
                usec_t llt_time,
                bool test_mode,
                struct duid *ret_duid,
                size_t *ret_len);
int dhcp_identifier_set_iaid(
                int ifindex,
                const struct hw_addr_data *hw_addr,
                bool legacy_unstable_byteorder,
                bool use_mac,
                void *ret);

const char *duid_type_to_string(DUIDType t) _const_;
