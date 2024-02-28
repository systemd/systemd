/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-device.h"
#include "sd-dhcp-duid.h"
#include "sd-id128.h"

#include "ether-addr-util.h"
#include "macro.h"
#include "sparse-endian.h"

#define SYSTEMD_PEN    43793

typedef enum DUIDType {
        DUID_TYPE_LLT      = SD_DUID_TYPE_LLT,
        DUID_TYPE_EN       = SD_DUID_TYPE_EN,
        DUID_TYPE_LL       = SD_DUID_TYPE_LL,
        DUID_TYPE_UUID     = SD_DUID_TYPE_UUID,
        _DUID_TYPE_MAX,
        _DUID_TYPE_INVALID = -EINVAL,
} DUIDType;

/* RFC 8415 section 11.1:
 * A DUID consists of a 2-octet type code represented in network byte order, followed by a variable number of
 * octets that make up the actual identifier. The length of the DUID (not including the type code) is at
 * least 1 octet and at most 128 octets. */
#define MIN_DUID_DATA_LEN 1
#define MAX_DUID_DATA_LEN 128
#define MIN_DUID_LEN (sizeof(be16_t) + MIN_DUID_DATA_LEN)
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
                uint8_t data[MAX_DUID_DATA_LEN];
        };
} _packed_;

typedef struct sd_dhcp_duid {
        size_t size;
        union {
                struct duid duid;
                uint8_t raw[MAX_DUID_LEN];
        };
} sd_dhcp_duid;

static inline bool duid_size_is_valid(size_t size) {
        return size >= MIN_DUID_LEN && size <= MAX_DUID_LEN;
}

static inline bool duid_data_size_is_valid(size_t size) {
        return size >= MIN_DUID_DATA_LEN && size <= MAX_DUID_DATA_LEN;
}

const char *duid_type_to_string(DUIDType t) _const_;
int dhcp_duid_to_string_internal(uint16_t type, const void *data, size_t data_size, char **ret);

int dhcp_identifier_set_iaid(
                sd_device *dev,
                const struct hw_addr_data *hw_addr,
                bool legacy_unstable_byteorder,
                void *ret);
