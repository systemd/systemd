/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <errno.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

#include "dns-def.h"
#include "hashmap.h"
#include "in-addr-util.h"

typedef enum DNSLabelFlags {
        DNS_LABEL_LDH                = 1 << 0, /* Follow the "LDH" rule — only letters, digits, and internal hyphens. */
        DNS_LABEL_NO_ESCAPES         = 1 << 1, /* Do not treat backslashes specially */
        DNS_LABEL_LEAVE_TRAILING_DOT = 1 << 2, /* Leave trailing dot in place */
} DNSLabelFlags;

int dns_label_unescape(const char **name, char *dest, size_t sz, DNSLabelFlags flags);
int dns_label_unescape_suffix(const char *name, const char **label_end, char *dest, size_t sz);
int dns_label_escape(const char *p, size_t l, char *dest, size_t sz);
int dns_label_escape_new(const char *p, size_t l, char **ret);

static inline int dns_name_parent(const char **name) {
        return dns_label_unescape(name, NULL, DNS_LABEL_MAX, 0);
}

#if HAVE_LIBIDN
int dns_label_apply_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);
int dns_label_undo_idna(const char *encoded, size_t encoded_size, char *decoded, size_t decoded_max);
#endif

int dns_name_concat(const char *a, const char *b, DNSLabelFlags flags, char **ret);

static inline int dns_name_normalize(const char *s, DNSLabelFlags flags, char **ret) {
        /* dns_name_concat() normalizes as a side-effect */
        return dns_name_concat(s, NULL, flags, ret);
}

static inline int dns_name_is_valid(const char *s) {
        int r;

        /* dns_name_concat() verifies as a side effect */
        r = dns_name_concat(s, NULL, 0, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

static inline int dns_name_is_valid_ldh(const char *s) {
        int r;

        r = dns_name_concat(s, NULL, DNS_LABEL_LDH|DNS_LABEL_NO_ESCAPES, NULL);
        if (r == -EINVAL)
                return 0;
        if (r < 0)
                return r;
        return 1;
}

void dns_name_hash_func(const char *s, struct siphash *state);
int dns_name_compare_func(const char *a, const char *b);
extern const struct hash_ops dns_name_hash_ops;
extern const struct hash_ops dns_name_hash_ops_free;

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
bool dns_subtype_name_is_valid(const char *name);

int dns_service_join(const char *name, const char *type, const char *domain, char **ret);
int dns_service_split(const char *joined, char **ret_name, char **ret_type, char **ret_domain);

int dns_name_suffix(const char *name, unsigned n_labels, const char **ret);
int dns_name_count_labels(const char *name);

int dns_name_skip(const char *a, unsigned n_labels, const char **ret);
int dns_name_equal_skip(const char *a, unsigned n_labels, const char *b);

int dns_name_common_suffix(const char *a, const char *b, const char **ret);

int dns_name_apply_idna(const char *name, char **ret);

int dns_name_is_valid_or_address(const char *name);

int dns_name_dot_suffixed(const char *name);

bool dns_name_dont_resolve(const char *name);
