/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-forward.h"

#define TLV_TAG_PAD UINT32_C(0)
#define TLV_TAG_END UINT32_C(0xFF)

typedef enum TLVFlag {
        TLV_TAG_U8       = 1 << 0,
        TLV_TAG_U16      = 1 << 1,
        TLV_TAG_U32      = 1 << 2,
        _TLV_TAG_MASK    = TLV_TAG_U8 | TLV_TAG_U16 | TLV_TAG_U32,
        TLV_LENGTH_U8    = 1 << 3,
        TLV_LENGTH_U16   = 1 << 4,
        TLV_LENGTH_U32   = 1 << 5,
        _TLV_LENGTH_MASK = TLV_LENGTH_U8 | TLV_LENGTH_U16 | TLV_LENGTH_U32,
        TLV_PAD          = 1 << 6,  /* If set, tag == 0 is a pad, and does not have the length field. */
        TLV_END          = 1 << 7,  /* If set, tag == 0xFF is a sign of the end of the sequence. */
        TLV_APPEND_END   = 1 << 8,  /* If set, append the END tag at the end of the sequence on build. */
        TLV_MERGE        = 1 << 9,  /* If set, tlv_get_alloc() merges them, and tlv_append() split long data. */
        TLV_TEMPORARY    = 1 << 10, /* If set, tlv_append() and tlv_parse() do not copy the data. */

        /* DHCPv4 options. */
        TLV_DHCP4        = TLV_TAG_U8 | TLV_LENGTH_U8 | TLV_PAD | TLV_END | TLV_APPEND_END | TLV_MERGE,
        /* Used for DHCPv4 sub-options, e.g.
         * DHCPv4 Vendor Specific Information sub-option (43),
         * DHCPv4 Relay Agent Information sub-option (82), or
         * DHCPv4 Vendor-Identifying Vendor Specific Information sub-sub-option (125).
         * Note that the PAD is not mentioned in RFC, but some implementations use it, hence let's gracefully
         * handle it. Also note that the END tag is prohibited in most options, but we also gracefully handle
         * it on parse, but of course do not append it on build. */
        TLV_DHCP4_SUBOPTION
                         = TLV_TAG_U8 | TLV_LENGTH_U8 | TLV_PAD | TLV_END,
        /* DHCPv4 Vendor-Identifying Vendor Class sub-option (124) and
         * DHCPv4 Vendor-Identifying Vendor Specific Information sub-option (125).
         * The tag is called 'enterprise-number', and in uint32. */
        TLV_DHCP4_VENDOR_IDENTIFYING_OPTION
                         = TLV_TAG_U32 | TLV_LENGTH_U8 | TLV_MERGE,
} TLVFlag;

typedef struct TLV {
        unsigned n_ref;
        TLVFlag flags;
        unsigned n_entries;
        Hashmap *entries;
} TLV;

#define TLV_INIT(f)                             \
        (TLV) {                                 \
                .n_ref = 1,                     \
                .flags = tlv_flags_verify(f),   \
        }

TLVFlag tlv_flags_verify(TLVFlag flags);

void tlv_done(TLV *tlv);
TLV* tlv_ref(TLV *p);
TLV* tlv_unref(TLV *p);
DEFINE_TRIVIAL_CLEANUP_FUNC(TLV*, tlv_unref);
TLV* tlv_new(TLVFlag flags);

bool tlv_isempty(const TLV *tlv);

struct iovec_wrapper* tlv_get_all(const TLV *tlv, uint32_t tag);
static inline bool tlv_contains(const TLV *tlv, uint32_t tag) {
        return tlv_get_all(tlv, tag);
}
int tlv_get_full(const TLV *tlv, uint32_t tag, size_t length, struct iovec *ret);
static inline int tlv_get(const TLV *tlv, uint32_t tag, struct iovec *ret) {
        return tlv_get_full(tlv, tag, SIZE_MAX, ret);
}
int tlv_get_alloc(const TLV *tlv, uint32_t tag, struct iovec *ret);

void tlv_remove(TLV *tlv, uint32_t tag);
int tlv_append(TLV *tlv, uint32_t tag, size_t length, const void *data);
int tlv_append_iov(TLV *tlv, uint32_t tag, const struct iovec *iov);
int tlv_append_tlv(TLV *tlv, const TLV *source);

int tlv_parse(TLV *tlv, const struct iovec *iov);
size_t tlv_size(const TLV *tlv);
int tlv_build(const TLV *tlv, struct iovec *ret);
