/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/types.h>

struct stat;
struct iovec;
struct siphash;

typedef void (*free_func_t)(void *p);
typedef void* (*mfree_func_t)(void *p);

typedef void (*hash_func_t)(const void *p, struct siphash *state);
typedef int (*compare_func_t)(const void *a, const void *b);

struct hash_ops;

typedef void* (*hashmap_destroy_t)(void *p);

/* The base type for all hashmap and set types. Many functions in the implementation take (HashmapBase*)
 * parameters and are run-time polymorphic, though the API is not meant to be polymorphic (do not call
 * underscore-prefixed functions directly). */
typedef struct HashmapBase HashmapBase;

/* Specific hashmap/set types */
typedef struct Hashmap Hashmap;               /* Maps keys to values */
typedef struct OrderedHashmap OrderedHashmap; /* Like Hashmap, but also remembers entry insertion order */
typedef struct Set Set;                       /* Stores just keys */
typedef struct OrderedSet OrderedSet;         /* Like Set, but also remembers entry insertion order */

typedef struct IteratedCache IteratedCache;   /* Caches the iterated order of one of the above */
typedef struct Iterator Iterator;

typedef struct Prioq Prioq;

typedef struct FDSet FDSet;

typedef struct PidRef PidRef;

typedef uint64_t usec_t;
typedef uint64_t nsec_t;

typedef struct dual_timestamp dual_timestamp;
typedef struct triple_timestamp triple_timestamp;

union in_addr_union;
struct in_addr_data;

typedef union sd_id128 sd_id128_t;

typedef struct sd_event sd_event;
typedef struct sd_event_source sd_event_source;

typedef struct sd_json_variant sd_json_variant;

typedef struct sd_bus sd_bus;
typedef struct sd_bus_error sd_bus_error;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_track sd_bus_track;

typedef struct sd_device sd_device;

typedef struct sd_netlink sd_netlink;
typedef struct sd_netlink_message sd_netlink_message;
typedef struct sd_netlink_slot sd_netlink_slot;
