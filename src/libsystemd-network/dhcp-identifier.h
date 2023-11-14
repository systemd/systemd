/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
#include "sd-id128.h"

#include "ether-addr-util.h"
#include "macro.h"
#include "sparse-endian.h"
#include "time-util.h"

#define SYSTEMD_PEN    43793

typedef enum DUIDType {
        DUID_TYPE_LLT       = 1,
        DUID_TYPE_EN        = 2,
        DUID_TYPE_LL        = 3,
        DUID_TYPE_UUID      = 4,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID  = -EINVAL,
        _DUID_TYPE_FORCE_U16 = UINT16_MAX,
} DUIDType;

/* RFC 8415 section 11.1:
 * A DUID consists of a 2-octet type code represented in network byte order, followed by a variable number of
 * octets that make up the actual identifier. The length of the DUID (not including the type code) is at
 * least 1 octet and at most 128 octets. */
#define MAX_DUID_DATA_LEN 128
#define MAX_DUID_LEN (sizeof(be16_t) + MAX_DUID_DATA_LEN)

/* https://tools.ietf.org/html/rfc3315#section-9.1 */
struct duid {
        be16_t type;
        union {
                struct {
                        /* DUID_TYPE_LLT */
                        be16_t htype;
                        be32_t time;
                        uint8_t haddr[];
                } _packed_ llt;
                struct {
                        /* DUID_TYPE_EN */
                        be32_t pen;
                        uint8_t id[];
                } _packed_ en;
                struct {
                        /* DUID_TYPE_LL */
                        be16_t htype;
                        uint8_t haddr[];
                } _packed_ ll;
                struct {
                        /* DUID_TYPE_UUID */
                        sd_id128_t uuid;
                } _packed_ uuid;
                struct {
                        uint8_t data[MAX_DUID_DATA_LEN];
                } _packed_ raw;
        };
} _packed_;

int dhcp_identifier_set_duid_llt(
                const struct hw_addr_data *hw_addr,
                uint16_t arp_type,
                usec_t t,
                struct duid *ret_duid,
                size_t *ret_len);
int dhcp_identifier_set_duid_ll(
                const struct hw_addr_data *hw_addr,
                uint16_t arp_type,
                struct duid *ret_duid,
                size_t *ret_len);
int dhcp_identifier_set_duid_en(struct duid *ret_duid, size_t *ret_len);
int dhcp_identifier_set_duid_uuid(struct duid *ret_duid, size_t *ret_len);
int dhcp_identifier_set_duid_raw(
                DUIDType duid_type,
                const uint8_t *buf,
                size_t buf_len,
                struct duid *ret_duid,
                size_t *ret_len);
int dhcp_identifier_set_iaid(
                sd_device *dev,
                const struct hw_addr_data *hw_addr,
                bool legacy_unstable_byteorder,
                void *ret);

const char *duid_type_to_string(DUIDType t) _const_;
