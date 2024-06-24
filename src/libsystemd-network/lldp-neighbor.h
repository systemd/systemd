/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <inttypes.h>
#include <stdbool.h>
#include <sys/types.h>

#include "sd-json.h"
#include "sd-lldp-rx.h"

#include "hash-funcs.h"
#include "lldp-rx-internal.h"
#include "time-util.h"

typedef struct LLDPNeighborID {
        /* The spec calls this an "MSAP identifier" */
        void *chassis_id;
        size_t chassis_id_size;

        void *port_id;
        size_t port_id_size;
} LLDPNeighborID;

struct sd_lldp_neighbor {
        /* Neighbor objects stay around as long as they are linked into an "sd_lldp_rx" object or n_ref > 0. */
        sd_lldp_rx *lldp_rx;
        unsigned n_ref;

        triple_timestamp timestamp;

        usec_t until;
        unsigned prioq_idx;

        struct ether_addr source_address;
        struct ether_addr destination_address;

        LLDPNeighborID id;

        /* The raw packet size. The data is appended to the object, accessible via LLDP_NEIGHBOR_RAW() */
        size_t raw_size;

        /* The current read index for the iterative TLV interface */
        size_t rindex;

        /* And a couple of fields parsed out. */
        bool has_ttl:1;
        bool has_capabilities:1;
        bool has_port_vlan_id:1;

        uint16_t ttl;

        uint16_t system_capabilities;
        uint16_t enabled_capabilities;

        char *port_description;
        char *system_name;
        char *system_description;
        char *mud_url;

        uint16_t port_vlan_id;

        char *chassis_id_as_string;
        char *port_id_as_string;
};

static inline void *LLDP_NEIGHBOR_RAW(const sd_lldp_neighbor *n) {
        return (uint8_t*) n + ALIGN(sizeof(sd_lldp_neighbor));
}

static inline uint8_t LLDP_NEIGHBOR_TLV_TYPE(const sd_lldp_neighbor *n) {
        return ((uint8_t*) LLDP_NEIGHBOR_RAW(n))[n->rindex] >> 1;
}

static inline size_t LLDP_NEIGHBOR_TLV_LENGTH(const sd_lldp_neighbor *n) {
        uint8_t *p;

        p = (uint8_t*) LLDP_NEIGHBOR_RAW(n) + n->rindex;
        return p[1] + (((size_t) (p[0] & 1)) << 8);
}

static inline void* LLDP_NEIGHBOR_TLV_DATA(const sd_lldp_neighbor *n) {
        return ((uint8_t*) LLDP_NEIGHBOR_RAW(n)) + n->rindex + 2;
}

extern const struct hash_ops lldp_neighbor_hash_ops;
int lldp_neighbor_id_compare_func(const LLDPNeighborID *x, const LLDPNeighborID *y);
int lldp_neighbor_prioq_compare_func(const void *a, const void *b);

sd_lldp_neighbor *lldp_neighbor_unlink(sd_lldp_neighbor *n);
sd_lldp_neighbor *lldp_neighbor_new(size_t raw_size);
int lldp_neighbor_parse(sd_lldp_neighbor *n);
void lldp_neighbor_start_ttl(sd_lldp_neighbor *n);
bool lldp_neighbor_equal(const sd_lldp_neighbor *a, const sd_lldp_neighbor *b);
int lldp_neighbor_build_json(sd_lldp_neighbor *n, sd_json_variant **ret);
