/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "hashmap.h"
#include "in-addr-util.h"

/* Length of a single label, with all escaping removed, excluding any trailing dot or NUL byte */
#define DNS_LABEL_MAX 63

/* Worst case length of a single label, with all escaping applied and room for a trailing NUL byte. */
#define DNS_LABEL_ESCAPED_MAX (DNS_LABEL_MAX*4+1)

/* Maximum length of a full hostname, consisting of a series of unescaped labels, and no trailing dot or NUL byte */
#define DNS_HOSTNAME_MAX 253

/* Maximum length of a full hostname, on the wire, including the final NUL byte */
#define DNS_WIRE_FORMAT_HOSTNAME_MAX 255

/* Maximum number of labels per valid hostname */
#define DNS_N_LABELS_MAX 127

int dns_label_unescape(const char **name, char *dest, size_t sz);
int dns_label_unescape_suffix(const char *name, const char **label_end, char *dest, size_t sz);
int dns_label_escape(const char *p, size_t l, char *dest, size_t sz);
int dns_label_escape_new(const char *p, size_t l, char **ret);

static inline int dns_name_parent(const char **name) {
        return dns_label_unescape(name, NULL, DNS_LABEL_MAX);
}

#if HAVE_LIBIDN
int dns_label_apply_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);
int dns_label_undo_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);
#endif

int dns_name_concat(const char *a, const char *b, char **ret);

static inline int dns_name_normalize(const char *s, char **ret) {
        /* dns_name_concat() normalizes as a side-effect */
        return dns_name_concat(s, NULL, ret);
}

static inline int dns_name_is_valid(const char *s) {
        int r;

        /* dns_name_normalize() verifies as a side effect */
        r = dns_name_normalize(s, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

void dns_name_hash_func(const void *s, struct siphash *state);
int dns_name_compare_func(const void *a, const void *b);
extern const struct hash_ops dns_name_hash_ops;

int dns_name_between(const char *a, const char *b, const char *c);
int dns_name_equal(const char *x, const char *y);
int dns_name_endswith(const char *name, const char *suffix);
int dns_name_startswith(const char *name, const char *prefix);

int dns_name_change_suffix(const char *name, const char *old_suffix, const char *new_suffix, char **ret);

int dns_name_reverse(int family, const union in_addr_union *a, char **ret);
int dns_name_address(const char *p, int *family, union in_addr_union *a);

bool dns_name_is_root(const char *name);
bool dns_name_is_single_label(const char *name);

int dns_name_to_wire_format(const char *domain, uint8_t *buffer, size_t len, bool canonical);

bool dns_srv_type_is_valid(const char *name);
bool dnssd_srv_type_is_valid(const char *name);
bool dns_service_name_is_valid(const char *name);

int dns_service_join(const char *name, const char *type, const char *domain, char **ret);
int dns_service_split(const char *joined, char **name, char **type, char **domain);

int dns_name_suffix(const char *name, unsigned n_labels, const char **ret);
int dns_name_count_labels(const char *name);

int dns_name_skip(const char *a, unsigned n_labels, const char **ret);
int dns_name_equal_skip(const char *a, unsigned n_labels, const char *b);

int dns_name_common_suffix(const char *a, const char *b, const char **ret);

int dns_name_apply_idna(const char *name, char **ret);

int dns_name_is_valid_or_address(const char *name);
