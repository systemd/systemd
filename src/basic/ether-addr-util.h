/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/if_infiniband.h>
#include <net/ethernet.h>
#include <stdbool.h>

#include "hash-funcs.h"
#include "in-addr-util.h"
#include "macro.h"
#include "memory-util.h"

/* This is MAX_ADDR_LEN as defined in linux/netdevice.h, but net/if_arp.h
 * defines a macro of the same name with a much lower size. */
#define HW_ADDR_MAX_SIZE 32

struct hw_addr_data {
        size_t length;
        union {
                struct ether_addr ether;
                uint8_t infiniband[INFINIBAND_ALEN];
                struct in_addr in;
                struct in6_addr in6;
                uint8_t bytes[HW_ADDR_MAX_SIZE];
        };
};

int parse_hw_addr_full(const char *s, size_t expected_len, struct hw_addr_data *ret);
static inline int parse_hw_addr(const char *s, struct hw_addr_data *ret) {
        return parse_hw_addr_full(s, 0, ret);
}
int parse_ether_addr(const char *s, struct ether_addr *ret);

typedef enum HardwareAddressToStringFlags {
        HW_ADDR_TO_STRING_NO_COLON = 1 << 0,
} HardwareAddressToStringFlags;

#define HW_ADDR_TO_STRING_MAX (3*HW_ADDR_MAX_SIZE)
char* hw_addr_to_string_full(
                const struct hw_addr_data *addr,
                HardwareAddressToStringFlags flags,
                char buffer[static HW_ADDR_TO_STRING_MAX]);
static inline char* hw_addr_to_string(const struct hw_addr_data *addr, char buffer[static HW_ADDR_TO_STRING_MAX]) {
        return hw_addr_to_string_full(addr, 0, buffer);
}

/* Note: the lifetime of the compound literal is the immediately surrounding block,
 * see C11 §6.5.2.5, and
 * https://stackoverflow.com/questions/34880638/compound-literal-lifetime-and-if-blocks */
#define HW_ADDR_TO_STR_FULL(hw_addr, flags) hw_addr_to_string_full((hw_addr), flags, (char[HW_ADDR_TO_STRING_MAX]){})
#define HW_ADDR_TO_STR(hw_addr) HW_ADDR_TO_STR_FULL(hw_addr, 0)

#define HW_ADDR_NULL ((const struct hw_addr_data){})

struct hw_addr_data *hw_addr_set(struct hw_addr_data *addr, const uint8_t *bytes, size_t length);

void hw_addr_hash_func(const struct hw_addr_data *p, struct siphash *state);
int hw_addr_compare(const struct hw_addr_data *a, const struct hw_addr_data *b);
static inline bool hw_addr_equal(const struct hw_addr_data *a, const struct hw_addr_data *b) {
        return hw_addr_compare(a, b) == 0;
}
static inline bool hw_addr_is_null(const struct hw_addr_data *addr) {
        assert(addr);
        return addr->length == 0 || memeqzero(addr->bytes, addr->length);
}

extern const struct hash_ops hw_addr_hash_ops;
extern const struct hash_ops hw_addr_hash_ops_free;

#define ETHER_ADDR_FORMAT_STR "%02X%02X%02X%02X%02X%02X"
#define ETHER_ADDR_FORMAT_VAL(x) (x).ether_addr_octet[0], (x).ether_addr_octet[1], (x).ether_addr_octet[2], (x).ether_addr_octet[3], (x).ether_addr_octet[4], (x).ether_addr_octet[5]

#define ETHER_ADDR_TO_STRING_MAX (3*6)
char* ether_addr_to_string(const struct ether_addr *addr, char buffer[ETHER_ADDR_TO_STRING_MAX]);
int ether_addr_to_string_alloc(const struct ether_addr *addr, char **ret);
/* Use only as function argument, never stand-alone! */
#define ETHER_ADDR_TO_STR(addr) ether_addr_to_string((addr), (char[ETHER_ADDR_TO_STRING_MAX]){})

int ether_addr_compare(const struct ether_addr *a, const struct ether_addr *b);
static inline bool ether_addr_equal(const struct ether_addr *a, const struct ether_addr *b) {
        return ether_addr_compare(a, b) == 0;
}

#define ETHER_ADDR_NULL ((const struct ether_addr){})

static inline bool ether_addr_is_null(const struct ether_addr *addr) {
        return ether_addr_equal(addr, &ETHER_ADDR_NULL);
}

static inline bool ether_addr_is_broadcast(const struct ether_addr *addr) {
        assert(addr);
        return memeqbyte(0xff, addr->ether_addr_octet, ETH_ALEN);
}

static inline bool ether_addr_is_multicast(const struct ether_addr *addr) {
        assert(addr);
        return FLAGS_SET(addr->ether_addr_octet[0], 0x01);
}

static inline bool ether_addr_is_unicast(const struct ether_addr *addr) {
        return !ether_addr_is_multicast(addr);
}

static inline bool ether_addr_is_local(const struct ether_addr *addr) {
        /* Determine if the Ethernet address is locally-assigned one (IEEE 802) */
        assert(addr);
        return FLAGS_SET(addr->ether_addr_octet[0], 0x02);
}

static inline bool ether_addr_is_global(const struct ether_addr *addr) {
        return !ether_addr_is_local(addr);
}

extern const struct hash_ops ether_addr_hash_ops;
extern const struct hash_ops ether_addr_hash_ops_free;

void ether_addr_mark_random(struct ether_addr *addr);
