// SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause)
/*
 * Adapted from libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 * Copyright 2021 Emil Renner Berthing
 */

#include <stdbool.h>
#include <efi.h>
#include <efilib.h>

#include "fdt.h"

static inline void memcpy(void *restrict dest, const void *restrict src, size_t n)
{
        CopyMem(dest, src, n);
}

static inline void memmove(void *dest, const void *src, size_t n)
{
        CopyMem(dest, src, n);
}

static inline void memset(void *dest, int c, size_t n)
{
        if (c == 0)
                ZeroMem(dest, n);
        else
                SetMem(dest, n, c);
}

static inline int memcmp(const void *a, const void *b, size_t n)
{
        return CompareMem(a, b, n);
}

static inline size_t strlen(const char *s)
{
        return strlena((CHAR8 *)s);
}

static void *memchr(const void *s, int c, size_t n)
{
        if (n > 0) {
                const char *p = s;
                const char *end = p + n;

                do {
                        if (*p == c)
                                return (void *)p;
                        p++;
                } while (p < end);
        }

        return NULL;
}

static char *strrchr(const char *s, int c)
{
        char *ret = NULL;
        int b;

        do {
                b = *s;
                if (b == c)
                        ret = (char *)s;
                s++;
        } while (b != '\0');

        return ret;
}

#define FDT_ALIGN(x, a) (((x) + (a) - 1) & ~((a) - 1))
#define FDT_TAGALIGN(x) (FDT_ALIGN((x), FDT_TAGSIZE))

static inline const void *fdt_offset_ptr_(const void *fdt, int offset)
{
        return (const char *)fdt + fdt_off_dt_struct(fdt) + offset;
}

static inline void *fdt_offset_ptr_w_(void *fdt, int offset)
{
        return (void *)(uintptr_t)fdt_offset_ptr_(fdt, offset);
}

static inline const struct fdt_reserve_entry *fdt_mem_rsv_(const void *fdt, int n)
{
        const struct fdt_reserve_entry *rsv_table =
                (const struct fdt_reserve_entry *)
                ((const char *)fdt + fdt_off_mem_rsvmap(fdt));

        return rsv_table + n;
}

#define FDT_SW_MAGIC (~FDT_MAGIC)

/**********************************************************************/
/* Checking controls                                                  */
/**********************************************************************/

/*
 * Defines assumptions which can be enabled. Each of these can be enabled
 * individually. For maximum safety, don't enable any assumptions!
 *
 * For minimal code size and no safety, use ASSUME_PERFECT at your own risk.
 * You should have another method of validating the device tree, such as a
 * signature or hash check before using libfdt.
 *
 * For situations where security is not a concern it may be safe to enable
 * ASSUME_SANE.
 */
enum {
        /*
         * This does essentially no checks. Only the latest device-tree
         * version is correctly handled. Inconsistencies or errors in the device
         * tree may cause undefined behaviour or crashes. Invalid parameters
         * passed to libfdt may do the same.
         *
         * If an error occurs when modifying the tree it may leave the tree in
         * an intermediate (but valid) state. As an example, adding a property
         * where there is insufficient space may result in the property name
         * being added to the string table even though the property itself is
         * not added to the struct section.
         *
         * Only use this if you have a fully validated device tree with
         * the latest supported version and wish to minimise code size.
         */
        ASSUME_PERFECT = 0xff,

        /*
         * This assumes that the device tree is sane. i.e. header metadata
         * and basic hierarchy are correct.
         *
         * With this assumption enabled, normal device trees produced by libfdt
         * and the compiler should be handled safely. Malicious device trees and
         * complete garbage may cause libfdt to behave badly or crash. Truncated
         * device trees (e.g. those only partially loaded) can also cause
         * problems.
         *
         * Note: Only checks that relate exclusively to the device tree itself
         * (not the parameters passed to libfdt) are disabled by this
         * assumption. This includes checking headers, tags and the like.
         */
        ASSUME_VALID_DTB = 1 << 0,

        /*
         * This builds on ASSUME_VALID_DTB and further assumes that libfdt
         * functions are called with valid parameters, i.e. not trigger
         * FDT_ERR_BADOFFSET or offsets that are out of bounds. It disables any
         * extensive checking of parameters and the device tree, making various
         * assumptions about correctness.
         *
         * It doesn't make sense to enable this assumption unless
         * ASSUME_VALID_DTB is also enabled.
         */
        ASSUME_VALID_INPUT = 1 << 1,

        /*
         * This disables checks for device-tree version and removes all code
         * which handles older versions.
         *
         * Only enable this if you know you have a device tree with the latest
         * version.
         */
        ASSUME_LATEST = 1 << 2,

        /*
         * This assumes that it is OK for a failed addition to the device tree,
         * due to lack of space or some other problem, to skip any rollback
         * steps (such as dropping the property name from the string table).
         * This is safe to enable in most circumstances, even though it may
         * leave the tree in a sub-optimal state.
         */
        ASSUME_NO_ROLLBACK = 1 << 3,

        /*
         * This assumes that the device tree components appear in a 'convenient'
         * order, i.e. the memory reservation block first, then the structure
         * block and finally the string block.
         *
         * This order is not specified by the device-tree specification,
         * but is expected by libfdt. The device-tree compiler always created
         * device trees with this order.
         *
         * This assumption disables a check in fdt_open_into() and removes the
         * ability to fix the problem there. This is safe if you know that the
         * device tree is correctly ordered. See fdt_blocks_misordered_().
         */
        ASSUME_LIBFDT_ORDER = 1 << 4,

        /*
         * This assumes that libfdt itself does not have any internal bugs. It
         * drops certain checks that should never be needed unless libfdt has an
         * undiscovered bug.
         *
         * This can generally be considered safe to enable.
         */
        ASSUME_LIBFDT_FLAWLESS = 1 << 5,
};

#define FDT_ASSUME_MASK 0

/**
 * can_assume_() - check if a particular assumption is enabled
 *
 * @mask: Mask to check (ASSUME_...)
 * @return true if that assumption is enabled, else false
 */
static inline bool can_assume_(int mask)
{
        return FDT_ASSUME_MASK & mask;
}

/** helper macros for checking assumptions */
#define can_assume(_assume) can_assume_(ASSUME_ ## _assume)

/*
 * Minimal sanity check for a read-only tree. fdt_ro_probe_() checks
 * that the given buffer contains what appears to be a flattened
 * device tree with sane information in its header.
 */
static int32_t fdt_ro_probe_(const void *fdt)
{
        uint32_t totalsize = fdt_totalsize(fdt);

        if (can_assume(VALID_DTB))
                return totalsize;

        /* The device tree must be at an 8-byte aligned address */
        if ((uintptr_t)fdt & 7)
                return -FDT_ERR_ALIGNMENT;

        if (fdt_magic(fdt) == FDT_MAGIC) {
                /* Complete tree */
                if (!can_assume(LATEST)) {
                        if (fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
                                return -FDT_ERR_BADVERSION;
                        if (fdt_last_comp_version(fdt) >
                                        FDT_LAST_SUPPORTED_VERSION)
                                return -FDT_ERR_BADVERSION;
                }
        } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
                /* Unfinished sequential-write blob */
                if (!can_assume(VALID_INPUT) && fdt_size_dt_struct(fdt) == 0)
                        return -FDT_ERR_BADSTATE;
        } else {
                return -FDT_ERR_BADMAGIC;
        }

        if (totalsize < INT32_MAX)
                return totalsize;
        else
                return -FDT_ERR_TRUNCATED;
}

#define FDT_RO_PROBE(fdt)                                        \
        {                                                        \
                int32_t totalsize_;                              \
                if ((totalsize_ = fdt_ro_probe_(fdt)) < 0)       \
                        return totalsize_;                       \
        }

static int check_off_(uint32_t hdrsize, uint32_t totalsize, uint32_t off)
{
        return (off >= hdrsize) && (off <= totalsize);
}

static int check_block_(uint32_t hdrsize, uint32_t totalsize,
                uint32_t base, uint32_t size)
{
        if (!check_off_(hdrsize, totalsize, base))
                return 0; /* block start out of bounds */
        if ((base + size) < base)
                return 0; /* overflow */
        if (!check_off_(hdrsize, totalsize, base + size))
                return 0; /* block end out of bounds */
        return 1;
}

static size_t fdt_header_size_(uint32_t version)
{
        if (version <= 1)
                return FDT_V1_SIZE;
        else if (version <= 2)
                return FDT_V2_SIZE;
        else if (version <= 3)
                return FDT_V3_SIZE;
        else if (version <= 16)
                return FDT_V16_SIZE;
        else
                return FDT_V17_SIZE;
}

size_t fdt_header_size(const void *fdt)
{
        return can_assume(LATEST) ? FDT_V17_SIZE :
                fdt_header_size_(fdt_version(fdt));
}

int fdt_check_header(const void *fdt)
{
        size_t hdrsize;

        /* The device tree must be at an 8-byte aligned address */
        if ((uintptr_t)fdt & 7)
                return -FDT_ERR_ALIGNMENT;

        if (fdt_magic(fdt) != FDT_MAGIC)
                return -FDT_ERR_BADMAGIC;
        if (!can_assume(LATEST)) {
                if ((fdt_version(fdt) < FDT_FIRST_SUPPORTED_VERSION)
                                || (fdt_last_comp_version(fdt) >
                                        FDT_LAST_SUPPORTED_VERSION))
                        return -FDT_ERR_BADVERSION;
                if (fdt_version(fdt) < fdt_last_comp_version(fdt))
                        return -FDT_ERR_BADVERSION;
        }
        hdrsize = fdt_header_size(fdt);
        if (!can_assume(VALID_DTB)) {

                if ((fdt_totalsize(fdt) < hdrsize)
                                || (fdt_totalsize(fdt) > INT_MAX))
                        return -FDT_ERR_TRUNCATED;

                /* Bounds check memrsv block */
                if (!check_off_(hdrsize, fdt_totalsize(fdt),
                                        fdt_off_mem_rsvmap(fdt)))
                        return -FDT_ERR_TRUNCATED;
        }

        if (!can_assume(VALID_DTB)) {
                /* Bounds check structure block */
                if (!can_assume(LATEST) && fdt_version(fdt) < 17) {
                        if (!check_off_(hdrsize, fdt_totalsize(fdt),
                                                fdt_off_dt_struct(fdt)))
                                return -FDT_ERR_TRUNCATED;
                } else {
                        if (!check_block_(hdrsize, fdt_totalsize(fdt),
                                                fdt_off_dt_struct(fdt),
                                                fdt_size_dt_struct(fdt)))
                                return -FDT_ERR_TRUNCATED;
                }

                /* Bounds check strings block */
                if (!check_block_(hdrsize, fdt_totalsize(fdt),
                                        fdt_off_dt_strings(fdt),
                                        fdt_size_dt_strings(fdt)))
                        return -FDT_ERR_TRUNCATED;
        }

        return 0;
}

const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int len)
{
        unsigned int uoffset = offset;
        unsigned int absoffset = offset + fdt_off_dt_struct(fdt);

        if (offset < 0)
                return NULL;

        if (!can_assume(VALID_INPUT))
                if ((absoffset < uoffset)
                                || ((absoffset + len) < absoffset)
                                || (absoffset + len) > fdt_totalsize(fdt))
                        return NULL;

        if (can_assume(LATEST) || fdt_version(fdt) >= 0x11)
                if (((uoffset + len) < uoffset)
                                || ((offset + len) > fdt_size_dt_struct(fdt)))
                        return NULL;

        return fdt_offset_ptr_(fdt, offset);
}

uint32_t fdt_next_tag(const void *fdt, int startoffset, int *nextoffset)
{
        const fdt32_t *tagp, *lenp;
        uint32_t tag;
        int offset = startoffset;
        const char *p;

        *nextoffset = -FDT_ERR_TRUNCATED;
        tagp = fdt_offset_ptr(fdt, offset, FDT_TAGSIZE);
        if (!can_assume(VALID_DTB) && !tagp)
                return FDT_END; /* premature end */
        tag = fdt32_ld(tagp);
        offset += FDT_TAGSIZE;

        *nextoffset = -FDT_ERR_BADSTRUCTURE;
        switch (tag) {
        case FDT_BEGIN_NODE:
                /* skip name */
                do {
                        p = fdt_offset_ptr(fdt, offset++, 1);
                } while (p && (*p != '\0'));
                if (!can_assume(VALID_DTB) && !p)
                        return FDT_END; /* premature end */
                break;

        case FDT_PROP:
                lenp = fdt_offset_ptr(fdt, offset, sizeof(*lenp));
                if (!can_assume(VALID_DTB) && !lenp)
                        return FDT_END; /* premature end */
                /* skip-name offset, length and value */
                offset += sizeof(struct fdt_property) - FDT_TAGSIZE
                        + fdt32_ld(lenp);
                if (!can_assume(LATEST) &&
                                fdt_version(fdt) < 0x10 && fdt32_ld(lenp) >= 8 &&
                                ((offset - fdt32_ld(lenp)) % 8) != 0)
                        offset += 4;
                break;

        case FDT_END:
        case FDT_END_NODE:
        case FDT_NOP:
                break;

        default:
                return FDT_END;
        }

        if (!fdt_offset_ptr(fdt, startoffset, offset - startoffset))
                return FDT_END; /* premature end */

        *nextoffset = FDT_TAGALIGN(offset);
        return tag;
}

static int fdt_check_node_offset_(const void *fdt, int offset)
{
        if (!can_assume(VALID_INPUT)
                        && ((offset < 0) || (offset % FDT_TAGSIZE)))
                return -FDT_ERR_BADOFFSET;

        if (fdt_next_tag(fdt, offset, &offset) != FDT_BEGIN_NODE)
                return -FDT_ERR_BADOFFSET;

        return offset;
}

static int fdt_check_prop_offset_(const void *fdt, int offset)
{
        if (!can_assume(VALID_INPUT)
                        && ((offset < 0) || (offset % FDT_TAGSIZE)))
                return -FDT_ERR_BADOFFSET;

        if (fdt_next_tag(fdt, offset, &offset) != FDT_PROP)
                return -FDT_ERR_BADOFFSET;

        return offset;
}

int fdt_next_node(const void *fdt, int offset, int *depth)
{
        int nextoffset = 0;
        uint32_t tag;

        if (offset >= 0)
                if ((nextoffset = fdt_check_node_offset_(fdt, offset)) < 0)
                        return nextoffset;

        do {
                offset = nextoffset;
                tag = fdt_next_tag(fdt, offset, &nextoffset);

                switch (tag) {
                case FDT_PROP:
                case FDT_NOP:
                        break;

                case FDT_BEGIN_NODE:
                        if (depth)
                                (*depth)++;
                        break;

                case FDT_END_NODE:
                        if (depth && ((--(*depth)) < 0))
                                return nextoffset;
                        break;

                case FDT_END:
                        if ((nextoffset >= 0)
                                        || ((nextoffset == -FDT_ERR_TRUNCATED) && !depth))
                                return -FDT_ERR_NOTFOUND;
                        else
                                return nextoffset;
                }
        } while (tag != FDT_BEGIN_NODE);

        return offset;
}

static const char *fdt_find_string_(const char *strtab, int tabsize, const char *s)
{
        int len = strlen(s) + 1;
        const char *last = strtab + tabsize - len;
        const char *p;

        for (p = strtab; p <= last; p++)
                if (memcmp(p, s, len) == 0)
                        return p;
        return NULL;
}

int fdt_move(const void *fdt, void *buf, int bufsize)
{
        if (!can_assume(VALID_INPUT) && bufsize < 0)
                return -FDT_ERR_NOSPACE;

        FDT_RO_PROBE(fdt);

        if (fdt_totalsize(fdt) > (unsigned int)bufsize)
                return -FDT_ERR_NOSPACE;

        memmove(buf, fdt, fdt_totalsize(fdt));
        return 0;
}

static int fdt_nodename_eq_(const void *fdt, int offset,
                const char *s, int len)
{
        int olen;
        const char *p = fdt_get_name(fdt, offset, &olen);

        if (!p || olen < len)
                /* short match */
                return 0;

        if (memcmp(p, s, len) != 0)
                return 0;

        if (p[len] == '\0')
                return 1;
        else if (!memchr(s, '@', len) && (p[len] == '@'))
                return 1;
        else
                return 0;
}

const char *fdt_get_string(const void *fdt, int stroffset, int *lenp)
{
        int32_t totalsize;
        uint32_t absoffset;
        size_t len;
        int err;
        const char *s, *n;

        if (can_assume(VALID_INPUT)) {
                s = (const char *)fdt + fdt_off_dt_strings(fdt) + stroffset;

                if (lenp)
                        *lenp = strlen(s);
                return s;
        }
        totalsize = fdt_ro_probe_(fdt);
        err = totalsize;
        if (totalsize < 0)
                goto fail;

        err = -FDT_ERR_BADOFFSET;
        absoffset = stroffset + fdt_off_dt_strings(fdt);
        if (absoffset >= (unsigned)totalsize)
                goto fail;
        len = totalsize - absoffset;

        if (fdt_magic(fdt) == FDT_MAGIC) {
                if (stroffset < 0)
                        goto fail;
                if (can_assume(LATEST) || fdt_version(fdt) >= 17) {
                        if ((unsigned)stroffset >= fdt_size_dt_strings(fdt))
                                goto fail;
                        if ((fdt_size_dt_strings(fdt) - stroffset) < len)
                                len = fdt_size_dt_strings(fdt) - stroffset;
                }
        } else if (fdt_magic(fdt) == FDT_SW_MAGIC) {
                unsigned int sw_stroffset = -stroffset;

                if ((stroffset >= 0) ||
                                (sw_stroffset > fdt_size_dt_strings(fdt)))
                        goto fail;
                if (sw_stroffset < len)
                        len = sw_stroffset;
        } else {
                err = -FDT_ERR_INTERNAL;
                goto fail;
        }

        s = (const char *)fdt + absoffset;
        n = memchr(s, '\0', len);
        if (!n) {
                /* missing terminating NULL */
                err = -FDT_ERR_TRUNCATED;
                goto fail;
        }

        if (lenp)
                *lenp = n - s;
        return s;

fail:
        if (lenp)
                *lenp = err;
        return NULL;
}

static int fdt_string_eq_(const void *fdt, int stroffset,
                const char *s, int len)
{
        int slen;
        const char *p = fdt_get_string(fdt, stroffset, &slen);

        return p && (slen == len) && (memcmp(p, s, len) == 0);
}

static const struct fdt_reserve_entry *fdt_mem_rsv(const void *fdt, int n)
{
        unsigned int offset = n * sizeof(struct fdt_reserve_entry);
        unsigned int absoffset = fdt_off_mem_rsvmap(fdt) + offset;

        if (!can_assume(VALID_INPUT)) {
                if (absoffset < fdt_off_mem_rsvmap(fdt))
                        return NULL;
                if (absoffset > fdt_totalsize(fdt) -
                                sizeof(struct fdt_reserve_entry))
                        return NULL;
        }
        return fdt_mem_rsv_(fdt, n);
}

int fdt_num_mem_rsv(const void *fdt)
{
        int i;
        const struct fdt_reserve_entry *re;

        for (i = 0; (re = fdt_mem_rsv(fdt, i)) != NULL; i++) {
                if (fdt64_ld(&re->size) == 0)
                        return i;
        }
        return -FDT_ERR_TRUNCATED;
}

static int nextprop_(const void *fdt, int offset)
{
        uint32_t tag;
        int nextoffset;

        do {
                tag = fdt_next_tag(fdt, offset, &nextoffset);

                switch (tag) {
                case FDT_END:
                        if (nextoffset >= 0)
                                return -FDT_ERR_BADSTRUCTURE;
                        else
                                return nextoffset;

                case FDT_PROP:
                        return offset;
                }
                offset = nextoffset;
        } while (tag == FDT_NOP);

        return -FDT_ERR_NOTFOUND;
}

int fdt_subnode_offset_namelen(const void *fdt, int offset,
                const char *name, int namelen)
{
        int depth;

        FDT_RO_PROBE(fdt);

        for (depth = 0;
                        (offset >= 0) && (depth >= 0);
                        offset = fdt_next_node(fdt, offset, &depth))
                if ((depth == 1)
                                && fdt_nodename_eq_(fdt, offset, name, namelen))
                        return offset;

        if (depth < 0)
                return -FDT_ERR_NOTFOUND;
        return offset; /* error */
}

const char *fdt_get_name(const void *fdt, int nodeoffset, int *len)
{
        const struct fdt_node_header *nh = fdt_offset_ptr_(fdt, nodeoffset);
        const char *nameptr;
        int err;

        if (((err = fdt_ro_probe_(fdt)) < 0)
                        || ((err = fdt_check_node_offset_(fdt, nodeoffset)) < 0))
                goto fail;

        nameptr = nh->name;

        if (!can_assume(LATEST) && fdt_version(fdt) < 0x10) {
                /*
                 * For old FDT versions, match the naming conventions of V16:
                 * give only the leaf name (after all /). The actual tree
                 * contents are loosely checked.
                 */
                const char *leaf;
                leaf = strrchr(nameptr, '/');
                if (leaf == NULL) {
                        err = -FDT_ERR_BADSTRUCTURE;
                        goto fail;
                }
                nameptr = leaf+1;
        }

        if (len)
                *len = strlen(nameptr);

        return nameptr;

fail:
        if (len)
                *len = err;
        return NULL;
}

int fdt_first_property_offset(const void *fdt, int nodeoffset)
{
        int offset;

        if ((offset = fdt_check_node_offset_(fdt, nodeoffset)) < 0)
                return offset;

        return nextprop_(fdt, offset);
}

int fdt_next_property_offset(const void *fdt, int offset)
{
        if ((offset = fdt_check_prop_offset_(fdt, offset)) < 0)
                return offset;

        return nextprop_(fdt, offset);
}

static const struct fdt_property *fdt_get_property_by_offset_(const void *fdt,
                int offset,
                int *lenp)
{
        int err;
        const struct fdt_property *prop;

        if (!can_assume(VALID_INPUT) &&
                        (err = fdt_check_prop_offset_(fdt, offset)) < 0) {
                if (lenp)
                        *lenp = err;
                return NULL;
        }

        prop = fdt_offset_ptr_(fdt, offset);

        if (lenp)
                *lenp = fdt32_ld(&prop->len);

        return prop;
}

static const struct fdt_property *fdt_get_property_namelen_(const void *fdt,
                int offset,
                const char *name,
                int namelen,
                int *lenp,
                int *poffset)
{
        for (offset = fdt_first_property_offset(fdt, offset);
                        (offset >= 0);
                        (offset = fdt_next_property_offset(fdt, offset))) {
                const struct fdt_property *prop;

                prop = fdt_get_property_by_offset_(fdt, offset, lenp);
                if (!can_assume(LIBFDT_FLAWLESS) && !prop) {
                        offset = -FDT_ERR_INTERNAL;
                        break;
                }
                if (fdt_string_eq_(fdt, fdt32_ld(&prop->nameoff),
                                        name, namelen)) {
                        if (poffset)
                                *poffset = offset;
                        return prop;
                }
        }

        if (lenp)
                *lenp = offset;
        return NULL;
}

const struct fdt_property *fdt_get_property_namelen(const void *fdt,
                int offset,
                const char *name,
                int namelen, int *lenp)
{
        /* Prior to version 16, properties may need realignment
         * and this API does not work. fdt_getprop_*() will, however. */
        if (!can_assume(LATEST) && fdt_version(fdt) < 0x10) {
                if (lenp)
                        *lenp = -FDT_ERR_BADVERSION;
                return NULL;
        }

        return fdt_get_property_namelen_(fdt, offset, name, namelen, lenp,
                        NULL);
}


const void *fdt_getprop_namelen(const void *fdt, int nodeoffset,
                const char *name, int namelen, int *lenp)
{
        int poffset;
        const struct fdt_property *prop;

        prop = fdt_get_property_namelen_(fdt, nodeoffset, name, namelen, lenp,
                        &poffset);
        if (!prop)
                return NULL;

        /* Handle realignment */
        if (!can_assume(LATEST) && fdt_version(fdt) < 0x10 &&
                        (poffset + sizeof(*prop)) % 8 && fdt32_ld(&prop->len) >= 8)
                return prop->data + 4;
        return prop->data;
}

const void *fdt_getprop_by_offset(const void *fdt, int offset,
                const char **namep, int *lenp)
{
        const struct fdt_property *prop;

        prop = fdt_get_property_by_offset_(fdt, offset, lenp);
        if (!prop)
                return NULL;
        if (namep) {
                const char *name;
                int namelen;

                if (!can_assume(VALID_INPUT)) {
                        name = fdt_get_string(fdt, fdt32_ld(&prop->nameoff),
                                        &namelen);
                        if (!name) {
                                if (lenp)
                                        *lenp = namelen;
                                return NULL;
                        }
                        *namep = name;
                } else {
                        *namep = fdt_string(fdt, fdt32_ld(&prop->nameoff));
                }
        }

        /* Handle realignment */
        if (!can_assume(LATEST) && fdt_version(fdt) < 0x10 &&
                        (offset + sizeof(*prop)) % 8 && fdt32_ld(&prop->len) >= 8)
                return prop->data + 4;
        return prop->data;
}

int fdt_check_full(const void *fdt, size_t bufsize)
{
        int err;
        int num_memrsv;
        int offset, nextoffset = 0;
        uint32_t tag;
        unsigned int depth = 0;
        const void *prop;
        const char *propname;
        bool expect_end = false;

        if (bufsize < FDT_V1_SIZE)
                return -FDT_ERR_TRUNCATED;
        if (bufsize < fdt_header_size(fdt))
                return -FDT_ERR_TRUNCATED;
        err = fdt_check_header(fdt);
        if (err != 0)
                return err;
        if (bufsize < fdt_totalsize(fdt))
                return -FDT_ERR_TRUNCATED;

        num_memrsv = fdt_num_mem_rsv(fdt);
        if (num_memrsv < 0)
                return num_memrsv;

        while (1) {
                offset = nextoffset;
                tag = fdt_next_tag(fdt, offset, &nextoffset);

                if (nextoffset < 0)
                        return nextoffset;

                /* If we see two root nodes, something is wrong */
                if (expect_end && tag != FDT_END)
                        return -FDT_ERR_BADSTRUCTURE;

                switch (tag) {
                case FDT_NOP:
                        break;

                case FDT_END:
                        if (depth != 0)
                                return -FDT_ERR_BADSTRUCTURE;
                        return 0;

                case FDT_BEGIN_NODE:
                        depth++;
                        if (depth > INT_MAX)
                                return -FDT_ERR_BADSTRUCTURE;

                        /* The root node must have an empty name */
                        if (depth == 1) {
                                const char *name;
                                int len;

                                name = fdt_get_name(fdt, offset, &len);
                                if (*name || len)
                                        return -FDT_ERR_BADSTRUCTURE;
                        }
                        break;

                case FDT_END_NODE:
                        if (depth == 0)
                                return -FDT_ERR_BADSTRUCTURE;
                        depth--;
                        if (depth == 0)
                                expect_end = true;
                        break;

                case FDT_PROP:
                        prop = fdt_getprop_by_offset(fdt, offset, &propname,
                                        &err);
                        if (!prop)
                                return err;
                        break;

                default:
                        return -FDT_ERR_INTERNAL;
                }
        }
}

static int fdt_blocks_misordered_(const void *fdt,
                int mem_rsv_size, int struct_size)
{
        return (fdt_off_mem_rsvmap(fdt) < FDT_ALIGN(sizeof(struct fdt_header), 8))
                || (fdt_off_dt_struct(fdt) <
                                (fdt_off_mem_rsvmap(fdt) + mem_rsv_size))
                || (fdt_off_dt_strings(fdt) <
                                (fdt_off_dt_struct(fdt) + struct_size))
                || (fdt_totalsize(fdt) <
                                (fdt_off_dt_strings(fdt) + fdt_size_dt_strings(fdt)));
}

static int fdt_rw_probe_(void *fdt)
{
        if (can_assume(VALID_DTB))
                return 0;
        FDT_RO_PROBE(fdt);

        if (!can_assume(LATEST) && fdt_version(fdt) < 17)
                return -FDT_ERR_BADVERSION;
        if (fdt_blocks_misordered_(fdt, sizeof(struct fdt_reserve_entry),
                                fdt_size_dt_struct(fdt)))
                return -FDT_ERR_BADLAYOUT;
        if (!can_assume(LATEST) && fdt_version(fdt) > 17)
                fdt_set_version(fdt, 17);

        return 0;
}

#define FDT_RW_PROBE(fdt) \
        { \
                int err_; \
                if ((err_ = fdt_rw_probe_(fdt)) != 0) \
                        return err_; \
        }

static inline unsigned int fdt_data_size_(void *fdt)
{
        return fdt_off_dt_strings(fdt) + fdt_size_dt_strings(fdt);
}

static int fdt_splice_(void *fdt, void *splicepoint, int oldlen, int newlen)
{
        char *p = splicepoint;
        unsigned int dsize = fdt_data_size_(fdt);
        size_t soff = p - (char *)fdt;

        if ((oldlen < 0) || (soff + oldlen < soff) || (soff + oldlen > dsize))
                return -FDT_ERR_BADOFFSET;
        if ((p < (char *)fdt) || (dsize + newlen < (unsigned)oldlen))
                return -FDT_ERR_BADOFFSET;
        if (dsize - oldlen + newlen > fdt_totalsize(fdt))
                return -FDT_ERR_NOSPACE;
        memmove(p + newlen, p + oldlen, ((char *)fdt + dsize) - (p + oldlen));
        return 0;
}

static int fdt_splice_struct_(void *fdt, void *p,
                int oldlen, int newlen)
{
        int delta = newlen - oldlen;
        int err;

        if ((err = fdt_splice_(fdt, p, oldlen, newlen)))
                return err;

        fdt_set_size_dt_struct(fdt, fdt_size_dt_struct(fdt) + delta);
        fdt_set_off_dt_strings(fdt, fdt_off_dt_strings(fdt) + delta);
        return 0;
}

/* Must only be used to roll back in case of error */
static void fdt_del_last_string_(void *fdt, const char *s)
{
        int newlen = strlen(s) + 1;

        fdt_set_size_dt_strings(fdt, fdt_size_dt_strings(fdt) - newlen);
}

static int fdt_splice_string_(void *fdt, int newlen)
{
        void *p = (char *)fdt
                + fdt_off_dt_strings(fdt) + fdt_size_dt_strings(fdt);
        int err;

        if ((err = fdt_splice_(fdt, p, 0, newlen)))
                return err;

        fdt_set_size_dt_strings(fdt, fdt_size_dt_strings(fdt) + newlen);
        return 0;
}

/**
 * fdt_find_add_string_() - Find or allocate a string
 *
 * @fdt: pointer to the device tree to check/adjust
 * @s: string to find/add
 * @allocated: Set to 0 if the string was found, 1 if not found and so
 *             allocated. Ignored if can_assume(NO_ROLLBACK)
 * @return offset of string in the string table (whether found or added)
 */
static int fdt_find_add_string_(void *fdt, const char *s, int *allocated)
{
        char *strtab = (char *)fdt + fdt_off_dt_strings(fdt);
        const char *p;
        char *new;
        int len = strlen(s) + 1;
        int err;

        if (!can_assume(NO_ROLLBACK))
                *allocated = 0;

        p = fdt_find_string_(strtab, fdt_size_dt_strings(fdt), s);
        if (p)
                /* found it */
                return (p - strtab);

        new = strtab + fdt_size_dt_strings(fdt);
        err = fdt_splice_string_(fdt, len);
        if (err)
                return err;

        if (!can_assume(NO_ROLLBACK))
                *allocated = 1;

        memcpy(new, s, len);
        return (new - strtab);
}

static int fdt_resize_property_(void *fdt, int nodeoffset, const char *name,
                int len, struct fdt_property **prop)
{
        int oldlen;
        int err;

        *prop = (void *)(uintptr_t)fdt_get_property_namelen(fdt, nodeoffset, name, strlen(name), &oldlen);
        if (!*prop)
                return oldlen;

        if ((err = fdt_splice_struct_(fdt, (*prop)->data, FDT_TAGALIGN(oldlen),
                                        FDT_TAGALIGN(len))))
                return err;

        (*prop)->len = fdt32_from_cpu(len);
        return 0;
}

static int fdt_add_property_(void *fdt, int nodeoffset, const char *name,
                int len, struct fdt_property **prop)
{
        int proplen;
        int nextoffset;
        int namestroff;
        int err;
        int allocated;

        if ((nextoffset = fdt_check_node_offset_(fdt, nodeoffset)) < 0)
                return nextoffset;

        namestroff = fdt_find_add_string_(fdt, name, &allocated);
        if (namestroff < 0)
                return namestroff;

        *prop = fdt_offset_ptr_w_(fdt, nextoffset);
        proplen = sizeof(**prop) + FDT_TAGALIGN(len);

        err = fdt_splice_struct_(fdt, *prop, 0, proplen);
        if (err) {
                /* Delete the string if we failed to add it */
                if (!can_assume(NO_ROLLBACK) && allocated)
                        fdt_del_last_string_(fdt, name);
                return err;
        }

        (*prop)->tag = fdt32_from_cpu(FDT_PROP);
        (*prop)->nameoff = fdt32_from_cpu(namestroff);
        (*prop)->len = fdt32_from_cpu(len);
        return 0;
}

int fdt_setprop_placeholder(void *fdt, int nodeoffset, const char *name,
                int len, void **prop_data)
{
        struct fdt_property *prop;
        int err;

        FDT_RW_PROBE(fdt);

        err = fdt_resize_property_(fdt, nodeoffset, name, len, &prop);
        if (err == -FDT_ERR_NOTFOUND)
                err = fdt_add_property_(fdt, nodeoffset, name, len, &prop);
        if (err)
                return err;

        *prop_data = prop->data;
        return 0;
}

int fdt_setprop(void *fdt, int nodeoffset, const char *name,
                const void *val, int len)
{
        void *prop_data;
        int err;

        err = fdt_setprop_placeholder(fdt, nodeoffset, name, len, &prop_data);
        if (err)
                return err;

        if (len)
                memcpy(prop_data, val, len);
        return 0;
}

int fdt_add_subnode_namelen(void *fdt, int parentoffset,
                const char *name, int namelen)
{
        struct fdt_node_header *nh;
        int offset, nextoffset;
        int nodelen;
        int err;
        uint32_t tag;
        fdt32_t *endtag;

        FDT_RW_PROBE(fdt);

        offset = fdt_subnode_offset_namelen(fdt, parentoffset, name, namelen);
        if (offset >= 0)
                return -FDT_ERR_EXISTS;
        else if (offset != -FDT_ERR_NOTFOUND)
                return offset;

        /* Try to place the new node after the parent's properties */
        tag = fdt_next_tag(fdt, parentoffset, &nextoffset);
        /* the fdt_subnode_offset_namelen() should ensure this never hits */
        if (!can_assume(LIBFDT_FLAWLESS) && (tag != FDT_BEGIN_NODE))
                return -FDT_ERR_INTERNAL;
        do {
                offset = nextoffset;
                tag = fdt_next_tag(fdt, offset, &nextoffset);
        } while ((tag == FDT_PROP) || (tag == FDT_NOP));

        nh = fdt_offset_ptr_w_(fdt, offset);
        nodelen = sizeof(*nh) + FDT_TAGALIGN(namelen+1) + FDT_TAGSIZE;

        err = fdt_splice_struct_(fdt, nh, 0, nodelen);
        if (err)
                return err;

        nh->tag = fdt32_from_cpu(FDT_BEGIN_NODE);
        memset(nh->name, 0, FDT_TAGALIGN(namelen+1));
        memcpy(nh->name, name, namelen);
        endtag = (fdt32_t *)((char *)nh + nodelen - FDT_TAGSIZE);
        *endtag = fdt32_from_cpu(FDT_END_NODE);

        return offset;
}

static void fdt_packblocks_(const char *old, char *new,
                int mem_rsv_size, int struct_size)
{
        int mem_rsv_off, struct_off, strings_off;

        mem_rsv_off = FDT_ALIGN(sizeof(struct fdt_header), 8);
        struct_off = mem_rsv_off + mem_rsv_size;
        strings_off = struct_off + struct_size;

        memmove(new + mem_rsv_off, old + fdt_off_mem_rsvmap(old), mem_rsv_size);
        fdt_set_off_mem_rsvmap(new, mem_rsv_off);

        memmove(new + struct_off, old + fdt_off_dt_struct(old), struct_size);
        fdt_set_off_dt_struct(new, struct_off);
        fdt_set_size_dt_struct(new, struct_size);

        memmove(new + strings_off, old + fdt_off_dt_strings(old),
                        fdt_size_dt_strings(old));
        fdt_set_off_dt_strings(new, strings_off);
        fdt_set_size_dt_strings(new, fdt_size_dt_strings(old));
}

int fdt_open_into(const void *fdt, void *buf, int bufsize)
{
        int err;
        int mem_rsv_size, struct_size;
        int newsize;
        const char *fdtstart = fdt;
        const char *fdtend = fdtstart + fdt_totalsize(fdt);
        char *tmp;

        FDT_RO_PROBE(fdt);

        mem_rsv_size = (fdt_num_mem_rsv(fdt)+1)
                * sizeof(struct fdt_reserve_entry);

        if (can_assume(LATEST) || fdt_version(fdt) >= 17) {
                struct_size = fdt_size_dt_struct(fdt);
        } else if (fdt_version(fdt) == 16) {
                struct_size = 0;
                while (fdt_next_tag(fdt, struct_size, &struct_size) != FDT_END)
                        ;
                if (struct_size < 0)
                        return struct_size;
        } else {
                return -FDT_ERR_BADVERSION;
        }

        if (can_assume(LIBFDT_ORDER) ||
                        !fdt_blocks_misordered_(fdt, mem_rsv_size, struct_size)) {
                /* no further work necessary */
                err = fdt_move(fdt, buf, bufsize);
                if (err)
                        return err;
                fdt_set_version(buf, 17);
                fdt_set_size_dt_struct(buf, struct_size);
                fdt_set_totalsize(buf, bufsize);
                return 0;
        }

        /* Need to reorder */
        newsize = FDT_ALIGN(sizeof(struct fdt_header), 8) + mem_rsv_size
                + struct_size + fdt_size_dt_strings(fdt);

        if (bufsize < newsize)
                return -FDT_ERR_NOSPACE;

        /* First attempt to build converted tree at beginning of buffer */
        tmp = buf;
        /* But if that overlaps with the old tree... */
        if (((tmp + newsize) > fdtstart) && (tmp < fdtend)) {
                /* Try right after the old tree instead */
                tmp = (char *)(uintptr_t)fdtend;
                if ((tmp + newsize) > ((char *)buf + bufsize))
                        return -FDT_ERR_NOSPACE;
        }

        fdt_packblocks_(fdt, tmp, mem_rsv_size, struct_size);
        memmove(buf, tmp, newsize);

        fdt_set_magic(buf, FDT_MAGIC);
        fdt_set_totalsize(buf, bufsize);
        fdt_set_version(buf, 17);
        fdt_set_last_comp_version(buf, 16);
        fdt_set_boot_cpuid_phys(buf, fdt_boot_cpuid_phys(fdt));

        return 0;
}
