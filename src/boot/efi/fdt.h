/* SPDX-License-Identifier: (GPL-2.0-or-later OR BSD-2-Clause) */
#ifndef FDT_H
#define FDT_H
/*
 * Adapted from libfdt - Flat Device Tree manipulation
 * Copyright (C) 2006 David Gibson, IBM Corporation.
 * Copyright 2012 Kim Phillips, Freescale Semiconductor.
 * Copyright 2021 Emil Renner Berthing
 */

#include <stddef.h>
#include <stdint.h>
#include <limits.h>
#include <endian.h>

typedef uint16_t fdt16_t;
typedef uint32_t fdt32_t;
typedef uint64_t fdt64_t;

struct fdt_header {
        fdt32_t magic;                   /* magic word FDT_MAGIC */
        fdt32_t totalsize;               /* total size of DT block */
        fdt32_t off_dt_struct;           /* offset to structure */
        fdt32_t off_dt_strings;          /* offset to strings */
        fdt32_t off_mem_rsvmap;          /* offset to memory reserve map */
        fdt32_t version;                 /* format version */
        fdt32_t last_comp_version;       /* last compatible version */

        /* version 2 fields below */
        fdt32_t boot_cpuid_phys;         /* Which physical CPU id we're
                                            booting on */
        /* version 3 fields below */
        fdt32_t size_dt_strings;         /* size of the strings block */

        /* version 17 fields below */
        fdt32_t size_dt_struct;          /* size of the structure block */
};

struct fdt_reserve_entry {
        fdt64_t address;
        fdt64_t size;
};

struct fdt_node_header {
        fdt32_t tag;
        char name[];
};

struct fdt_property {
        fdt32_t tag;
        fdt32_t len;
        fdt32_t nameoff;
        char data[];
};

#define FDT_MAGIC       0xd00dfeed      /* 4: version, 4: total size */
#define FDT_TAGSIZE     sizeof(fdt32_t)

#define FDT_BEGIN_NODE  0x1             /* Start node: full name */
#define FDT_END_NODE    0x2             /* End node */
#define FDT_PROP        0x3             /* Property: name off,
                                           size, content */
#define FDT_NOP         0x4             /* nop */
#define FDT_END         0x9

#define FDT_V1_SIZE     (7*sizeof(fdt32_t))
#define FDT_V2_SIZE     (FDT_V1_SIZE + sizeof(fdt32_t))
#define FDT_V3_SIZE     (FDT_V2_SIZE + sizeof(fdt32_t))
#define FDT_V16_SIZE    FDT_V3_SIZE
#define FDT_V17_SIZE    (FDT_V16_SIZE + sizeof(fdt32_t))


#define FDT_FIRST_SUPPORTED_VERSION	0x02
#define FDT_LAST_COMPATIBLE_VERSION 0x10
#define FDT_LAST_SUPPORTED_VERSION	0x11

/* Error codes: informative error codes */
#define FDT_ERR_NOTFOUND        1
        /* FDT_ERR_NOTFOUND: The requested node or property does not exist */
#define FDT_ERR_EXISTS          2
        /* FDT_ERR_EXISTS: Attempted to create a node or property which
         * already exists */
#define FDT_ERR_NOSPACE         3
        /* FDT_ERR_NOSPACE: Operation needed to expand the device
         * tree, but its buffer did not have sufficient space to
         * contain the expanded tree. Use fdt_open_into() to move the
         * device tree to a buffer with more space. */

/* Error codes: codes for bad parameters */
#define FDT_ERR_BADOFFSET       4
        /* FDT_ERR_BADOFFSET: Function was passed a structure block
         * offset which is out-of-bounds, or which points to an
         * unsuitable part of the structure for the operation. */
#define FDT_ERR_BADPATH         5
        /* FDT_ERR_BADPATH: Function was passed a badly formatted path
         * (e.g. missing a leading / for a function which requires an
         * absolute path) */
#define FDT_ERR_BADPHANDLE      6
        /* FDT_ERR_BADPHANDLE: Function was passed an invalid phandle.
         * This can be caused either by an invalid phandle property
         * length, or the phandle value was either 0 or -1, which are
         * not permitted. */
#define FDT_ERR_BADSTATE        7
        /* FDT_ERR_BADSTATE: Function was passed an incomplete device
         * tree created by the sequential-write functions, which is
         * not sufficiently complete for the requested operation. */

/* Error codes: codes for bad device tree blobs */
#define FDT_ERR_TRUNCATED       8
        /* FDT_ERR_TRUNCATED: FDT or a sub-block is improperly
         * terminated (overflows, goes outside allowed bounds, or
         * isn't properly terminated).  */
#define FDT_ERR_BADMAGIC        9
        /* FDT_ERR_BADMAGIC: Given "device tree" appears not to be a
         * device tree at all - it is missing the flattened device
         * tree magic number. */
#define FDT_ERR_BADVERSION      10
        /* FDT_ERR_BADVERSION: Given device tree has a version which
         * can't be handled by the requested operation.  For
         * read-write functions, this may mean that fdt_open_into() is
         * required to convert the tree to the expected version. */
#define FDT_ERR_BADSTRUCTURE    11
        /* FDT_ERR_BADSTRUCTURE: Given device tree has a corrupt
         * structure block or other serious error (e.g. misnested
         * nodes, or subnodes preceding properties). */
#define FDT_ERR_BADLAYOUT       12
        /* FDT_ERR_BADLAYOUT: For read-write functions, the given
         * device tree has it's sub-blocks in an order that the
         * function can't handle (memory reserve map, then structure,
         * then strings).  Use fdt_open_into() to reorganize the tree
         * into a form suitable for the read-write operations. */

/* "Can't happen" error indicating a bug in libfdt */
#define FDT_ERR_INTERNAL        13
        /* FDT_ERR_INTERNAL: libfdt has failed an internal assertion.
         * Should never be returned, if it is, it indicates a bug in
         * libfdt itself. */

/* Errors in device tree content */
#define FDT_ERR_BADNCELLS       14
        /* FDT_ERR_BADNCELLS: Device tree has a #address-cells, #size-cells
         * or similar property with a bad format or value */

#define FDT_ERR_BADVALUE        15
        /* FDT_ERR_BADVALUE: Device tree has a property with an unexpected
         * value. For example: a property expected to contain a string list
         * is not NUL-terminated within the length of its value. */

#define FDT_ERR_BADOVERLAY      16
        /* FDT_ERR_BADOVERLAY: The device tree overlay, while
         * correctly structured, cannot be applied due to some
         * unexpected or missing value, property or node. */

#define FDT_ERR_NOPHANDLES      17
        /* FDT_ERR_NOPHANDLES: The device tree doesn't have any
         * phandle available anymore without causing an overflow */

#define FDT_ERR_BADFLAGS        18
        /* FDT_ERR_BADFLAGS: The function was passed a flags field that
         * contains invalid flags or an invalid combination of flags. */

#define FDT_ERR_ALIGNMENT       19
        /* FDT_ERR_ALIGNMENT: The device tree base address is not 8-byte
         * aligned. */

#define FDT_ERR_MAX             19

/**********************************************************************/
/* Low-level functions (you probably don't need these)                */
/**********************************************************************/

const void *fdt_offset_ptr(const void *fdt, int offset, unsigned int checklen);
static inline void *fdt_offset_ptr_w(void *fdt, int offset, int checklen)
{
        return (void *)(uintptr_t)fdt_offset_ptr(fdt, offset, checklen);
}

uint32_t fdt_next_tag(const void *fdt, int offset, int *nextoffset);

/*
 * External helpers to access words from a device tree blob. They're built
 * to work even with unaligned pointers on platforms (such as ARMv5) that don't
 * like unaligned loads and stores.
 */
static inline uint32_t fdt32_ld(const fdt32_t *p)
{
        const uint8_t *bp = (const uint8_t *)p;

        return ((uint32_t)bp[0] << 24)
                | ((uint32_t)bp[1] << 16)
                | ((uint32_t)bp[2] << 8)
                | (uint32_t)bp[3];
}

static inline void fdt32_st(void *property, uint32_t value)
{
        uint8_t *bp = property;

        bp[0] = value >> 24;
        bp[1] = value >> 16;
        bp[2] = value >> 8;
        bp[3] = value;
}

static inline uint64_t fdt64_ld(const fdt64_t *p)
{
        const uint8_t *bp = (const uint8_t *)p;

        return ((uint64_t)bp[0] << 56)
                | ((uint64_t)bp[1] << 48)
                | ((uint64_t)bp[2] << 40)
                | ((uint64_t)bp[3] << 32)
                | ((uint64_t)bp[4] << 24)
                | ((uint64_t)bp[5] << 16)
                | ((uint64_t)bp[6] << 8)
                | (uint64_t)bp[7];
}

static inline void fdt64_st(void *property, uint64_t value)
{
        uint8_t *bp = property;

        bp[0] = value >> 56;
        bp[1] = value >> 48;
        bp[2] = value >> 40;
        bp[3] = value >> 32;
        bp[4] = value >> 24;
        bp[5] = value >> 16;
        bp[6] = value >> 8;
        bp[7] = value;
}

static inline fdt32_t fdt32_from_cpu(uint32_t x)
{
        return htobe32(x);
}

static inline fdt64_t fdt64_from_cpu(uint64_t x)
{
        return htobe64(x);
}

/**********************************************************************/
/* Traversal functions                                                */
/**********************************************************************/

int fdt_next_node(const void *fdt, int offset, int *depth);

/**
 * fdt_first_subnode() - get offset of first direct subnode
 * @fdt:        FDT blob
 * @offset:     Offset of node to check
 *
 * Return: offset of first subnode, or -FDT_ERR_NOTFOUND if there is none
 */
int fdt_first_subnode(const void *fdt, int offset);

/**
 * fdt_next_subnode() - get offset of next direct subnode
 * @fdt:        FDT blob
 * @offset:     Offset of previous subnode
 *
 * After first calling fdt_first_subnode(), call this function repeatedly to
 * get direct subnodes of a parent node.
 *
 * Return: offset of next subnode, or -FDT_ERR_NOTFOUND if there are no more
 *         subnodes
 */
int fdt_next_subnode(const void *fdt, int offset);

/**
 * fdt_for_each_subnode - iterate over all subnodes of a parent
 *
 * @node:       child node (int, lvalue)
 * @fdt:        FDT blob (const void *)
 * @parent:     parent node (int)
 *
 * This is actually a wrapper around a for loop and would be used like so:
 *
 *   fdt_for_each_subnode(node, fdt, parent) {
 *           Use node
 *           ...
 *   }
 *
 *   if ((node < 0) && (node != -FDT_ERR_NOTFOUND)) {
 *           Error handling
 *   }
 *
 * Note that this is implemented as a macro and @node is used as
 * iterator in the loop. The parent variable be constant or even a
 * literal.
 */
#define fdt_for_each_subnode(node, fdt, parent)      \
        for (node = fdt_first_subnode(fdt, parent);  \
             node >= 0;                              \
             node = fdt_next_subnode(fdt, node))

/**********************************************************************/
/* General functions                                                  */
/**********************************************************************/
#define fdt_get_header(fdt, field) \
        (fdt32_ld(&((const struct fdt_header *)(fdt))->field))
#define fdt_magic(fdt)               (fdt_get_header(fdt, magic))
#define fdt_totalsize(fdt)           (fdt_get_header(fdt, totalsize))
#define fdt_off_dt_struct(fdt)       (fdt_get_header(fdt, off_dt_struct))
#define fdt_off_dt_strings(fdt)      (fdt_get_header(fdt, off_dt_strings))
#define fdt_off_mem_rsvmap(fdt)      (fdt_get_header(fdt, off_mem_rsvmap))
#define fdt_version(fdt)             (fdt_get_header(fdt, version))
#define fdt_last_comp_version(fdt)   (fdt_get_header(fdt, last_comp_version))
#define fdt_boot_cpuid_phys(fdt)     (fdt_get_header(fdt, boot_cpuid_phys))
#define fdt_size_dt_strings(fdt)     (fdt_get_header(fdt, size_dt_strings))
#define fdt_size_dt_struct(fdt)      (fdt_get_header(fdt, size_dt_struct))

#define fdt_set_hdr_(name) \
        static inline void fdt_set_##name(void *fdt, uint32_t val) \
        { \
                struct fdt_header *fdth = (struct fdt_header *)fdt; \
                fdth->name = fdt32_from_cpu(val); \
        }
fdt_set_hdr_(magic);
fdt_set_hdr_(totalsize);
fdt_set_hdr_(off_dt_struct);
fdt_set_hdr_(off_dt_strings);
fdt_set_hdr_(off_mem_rsvmap);
fdt_set_hdr_(version);
fdt_set_hdr_(last_comp_version);
fdt_set_hdr_(boot_cpuid_phys);
fdt_set_hdr_(size_dt_strings);
fdt_set_hdr_(size_dt_struct);
#undef fdt_set_hdr_

/**
 * fdt_header_size - return the size of the tree's header
 * @fdt: pointer to a flattened device tree
 *
 * Return: size of DTB header in bytes
 */
size_t fdt_header_size(const void *fdt);

/**
 * fdt_check_header - sanity check a device tree header
 * @fdt: pointer to data which might be a flattened device tree
 *
 * fdt_check_header() checks that the given buffer contains what
 * appears to be a flattened device tree, and that the header contains
 * valid information (to the extent that can be determined from the
 * header alone).
 *
 * returns:
 *     0, if the buffer appears to contain a valid device tree
 *     -FDT_ERR_BADMAGIC,
 *     -FDT_ERR_BADVERSION,
 *     -FDT_ERR_BADSTATE,
 *     -FDT_ERR_TRUNCATED, standard meanings, as above
 */
int fdt_check_header(const void *fdt);

/**
 * fdt_move - move a device tree around in memory
 * @fdt: pointer to the device tree to move
 * @buf: pointer to memory where the device is to be moved
 * @bufsize: size of the memory space at buf
 *
 * fdt_move() relocates, if possible, the device tree blob located at
 * fdt to the buffer at buf of size bufsize.  The buffer may overlap
 * with the existing device tree blob at fdt.  Therefore,
 *     fdt_move(fdt, fdt, fdt_totalsize(fdt))
 * should always succeed.
 *
 * returns:
 *     0, on success
 *     -FDT_ERR_NOSPACE, bufsize is insufficient to contain the device tree
 *     -FDT_ERR_BADMAGIC,
 *     -FDT_ERR_BADVERSION,
 *     -FDT_ERR_BADSTATE, standard meanings
 */
int fdt_move(const void *fdt, void *buf, int bufsize);

/**********************************************************************/
/* Read-only functions                                                */
/**********************************************************************/

int fdt_check_full(const void *fdt, size_t bufsize);

/**
 * fdt_get_string - retrieve a string from the strings block of a device tree
 * @fdt: pointer to the device tree blob
 * @stroffset: offset of the string within the strings block (native endian)
 * @lenp: optional pointer to return the string's length
 *
 * fdt_get_string() retrieves a pointer to a single string from the
 * strings block of the device tree blob at fdt, and optionally also
 * returns the string's length in *lenp.
 *
 * returns:
 *     a pointer to the string, on success
 *     NULL, if stroffset is out of bounds, or doesn't point to a valid string
 */
const char *fdt_get_string(const void *fdt, int stroffset, int *lenp);

/**
 * fdt_string - retrieve a string from the strings block of a device tree
 * @fdt: pointer to the device tree blob
 * @stroffset: offset of the string within the strings block (native endian)
 *
 * fdt_string() retrieves a pointer to a single string from the
 * strings block of the device tree blob at fdt.
 *
 * returns:
 *     a pointer to the string, on success
 *     NULL, if stroffset is out of bounds, or doesn't point to a valid string
 */
static inline const char *fdt_string(const void *fdt, int stroffset)
{
        return fdt_get_string(fdt, stroffset, NULL);
}


/**
 * fdt_num_mem_rsv - retrieve the number of memory reserve map entries
 * @fdt: pointer to the device tree blob
 *
 * Returns the number of entries in the device tree blob's memory
 * reservation map.  This does not include the terminating 0,0 entry
 * or any other (0,0) entries reserved for expansion.
 *
 * returns:
 *     the number of entries
 */
int fdt_num_mem_rsv(const void *fdt);

/**
 * fdt_subnode_offset_namelen - find a subnode based on substring
 * @fdt: pointer to the device tree blob
 * @parentoffset: structure block offset of a node
 * @name: name of the subnode to locate
 * @namelen: number of characters of name to consider
 *
 * Identical to fdt_subnode_offset(), but only examine the first
 * namelen characters of name for matching the subnode name.  This is
 * useful for finding subnodes based on a portion of a larger string,
 * such as a full path.
 *
 * Return: offset of the subnode or -FDT_ERR_NOTFOUND if name not found.
 */
int fdt_subnode_offset_namelen(const void *fdt, int parentoffset,
                const char *name, int namelen);

/**
 * fdt_get_name - retrieve the name of a given node
 * @fdt: pointer to the device tree blob
 * @nodeoffset: structure block offset of the starting node
 * @lenp: pointer to an integer variable (will be overwritten) or NULL
 *
 * fdt_get_name() retrieves the name (including unit address) of the
 * device tree node at structure block offset nodeoffset.  If lenp is
 * non-NULL, the length of this name is also returned, in the integer
 * pointed to by lenp.
 *
 * returns:
 *   pointer to the node's name, on success
 *     If lenp is non-NULL, *lenp contains the length of that name (>=0)
 *   NULL, on error
 *     if lenp is non-NULL *lenp contains an error code (<0):
 *       -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *       -FDT_ERR_BADMAGIC,
 *       -FDT_ERR_BADVERSION,
 *       -FDT_ERR_BADSTATE, standard meanings
 */
const char *fdt_get_name(const void *fdt, int nodeoffset, int *lenp);

/**
 * fdt_first_property_offset - find the offset of a node's first property
 * @fdt: pointer to the device tree blob
 * @nodeoffset: structure block offset of a node
 *
 * fdt_first_property_offset() finds the first property of the node at
 * the given structure block offset.
 *
 * returns:
 *   structure block offset of the property (>=0), on success
 *   -FDT_ERR_NOTFOUND, if the requested node has no properties
 *   -FDT_ERR_BADOFFSET, if nodeoffset did not point to an FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_TRUNCATED, standard meanings.
 */
int fdt_first_property_offset(const void *fdt, int nodeoffset);

/**
 * fdt_next_property_offset - step through a node's properties
 * @fdt: pointer to the device tree blob
 * @offset: structure block offset of a property
 *
 * fdt_next_property_offset() finds the property immediately after the
 * one at the given structure block offset.  This will be a property
 * of the same node as the given property.
 *
 * returns:
 *   structure block offset of the next property (>=0), on success
 *   -FDT_ERR_NOTFOUND, if the given property is the last in its node
 *   -FDT_ERR_BADOFFSET, if nodeoffset did not point to an FDT_PROP tag
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_TRUNCATED, standard meanings.
 */
int fdt_next_property_offset(const void *fdt, int offset);

/**
 * fdt_for_each_property_offset - iterate over all properties of a node
 *
 * @property:   property offset (int, lvalue)
 * @fdt:        FDT blob (const void *)
 * @node:       node offset (int)
 *
 * This is actually a wrapper around a for loop and would be used like so:
 *
 *   fdt_for_each_property_offset(property, fdt, node) {
 *           Use property
 *           ...
 *   }
 *
 *   if ((property < 0) && (property != -FDT_ERR_NOTFOUND)) {
 *           Error handling
 *   }
 *
 * Note that this is implemented as a macro and property is used as
 * iterator in the loop. The node variable can be constant or even a
 * literal.
 */
#define fdt_for_each_property_offset(property, fdt, node)        \
        for (property = fdt_first_property_offset(fdt, node);    \
             property >= 0;                                      \
             property = fdt_next_property_offset(fdt, property))


/**
 * fdt_get_property_namelen - find a property based on substring
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to find
 * @name: name of the property to find
 * @namelen: number of characters of name to consider
 * @lenp: pointer to an integer variable (will be overwritten) or NULL
 *
 * Identical to fdt_get_property(), but only examine the first namelen
 * characters of name for matching the property name.
 *
 * Return: pointer to the structure representing the property, or NULL
 *         if not found
 */
const struct fdt_property *fdt_get_property_namelen(const void *fdt,
                int nodeoffset,
                const char *name,
                int namelen, int *lenp);

/**
 * fdt_getprop_by_offset - retrieve the value of a property at a given offset
 * @fdt: pointer to the device tree blob
 * @offset: offset of the property to read
 * @namep: pointer to a string variable (will be overwritten) or NULL
 * @lenp: pointer to an integer variable (will be overwritten) or NULL
 *
 * fdt_getprop_by_offset() retrieves a pointer to the value of the
 * property at structure block offset 'offset' (this will be a pointer
 * to within the device blob itself, not a copy of the value).  If
 * lenp is non-NULL, the length of the property value is also
 * returned, in the integer pointed to by lenp.  If namep is non-NULL,
 * the property's namne will also be returned in the char * pointed to
 * by namep (this will be a pointer to within the device tree's string
 * block, not a new copy of the name).
 *
 * returns:
 *   pointer to the property's value
 *     if lenp is non-NULL, *lenp contains the length of the property value (>=0)
 *     if namep is non-NULL *namep contiains a pointer to the property name.
 *   NULL, on error
 *     if lenp is non-NULL, *lenp contains an error code (<0):
 *       -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_PROP tag
 *       -FDT_ERR_BADMAGIC,
 *       -FDT_ERR_BADVERSION,
 *       -FDT_ERR_BADSTATE,
 *       -FDT_ERR_BADSTRUCTURE,
 *       -FDT_ERR_TRUNCATED, standard meanings
 */
const void *fdt_getprop_by_offset(const void *fdt, int offset,
                const char **namep, int *lenp);

/**
 * fdt_getprop_namelen - get property value based on substring
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to find
 * @name: name of the property to find
 * @namelen: number of characters of name to consider
 * @lenp: pointer to an integer variable (will be overwritten) or NULL
 *
 * Identical to fdt_getprop(), but only examine the first namelen
 * characters of name for matching the property name.
 *
 * Return: pointer to the property's value or NULL on error
 */
const void *fdt_getprop_namelen(const void *fdt, int nodeoffset,
                const char *name, int namelen, int *lenp);

static inline void *fdt_getprop_namelen_w(void *fdt, int nodeoffset,
                const char *name, int namelen,
                int *lenp)
{
        return (void *)(uintptr_t)fdt_getprop_namelen(fdt, nodeoffset, name,
                        namelen, lenp);
}

/**********************************************************************/
/* Read-write functions                                               */
/**********************************************************************/

int fdt_open_into(const void *fdt, void *buf, int bufsize);

/**
 * fdt_setprop - create or change a property
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 * @val: pointer to data to set the property value to
 * @len: length of the property value
 *
 * fdt_setprop() sets the value of the named property in the given
 * node to the given value and length, creating the property if it
 * does not already exist.
 *
 * This function may insert or delete data from the blob, and will
 * therefore change the offsets of some existing nodes.
 *
 * returns:
 *   0, on success
 *   -FDT_ERR_NOSPACE, there is insufficient free space in the blob to
 *     contain the new property value
 *   -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_TRUNCATED, standard meanings
 */
int fdt_setprop(void *fdt, int nodeoffset, const char *name,
                const void *val, int len);

/**
 * fdt_setprop_placeholder - allocate space for a property
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 * @len: length of the property value
 * @prop_data: return pointer to property data
 *
 * fdt_setprop_placeholer() allocates the named property in the given node.
 * If the property exists it is resized. In either case a pointer to the
 * property data is returned.
 *
 * This function may insert or delete data from the blob, and will
 * therefore change the offsets of some existing nodes.
 *
 * returns:
 *   0, on success
 *   -FDT_ERR_NOSPACE, there is insufficient free space in the blob to
 *     contain the new property value
 *   -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_TRUNCATED, standard meanings
 */
int fdt_setprop_placeholder(void *fdt, int nodeoffset, const char *name,
                int len, void **prop_data);

/**
 * fdt_setprop_u32 - set a property to a 32-bit integer
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 * @val: 32-bit integer value for the property (native endian)
 *
 * fdt_setprop_u32() sets the value of the named property in the given
 * node to the given 32-bit integer value (converting to big-endian if
 * necessary), or creates a new property with that value if it does
 * not already exist.
 *
 * This function may insert or delete data from the blob, and will
 * therefore change the offsets of some existing nodes.
 *
 * returns:
 *   0, on success
 *   -FDT_ERR_NOSPACE, there is insufficient free space in the blob to
 *     contain the new property value
 *   -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_TRUNCATED, standard meanings
 */
static inline int fdt_setprop_u32(void *fdt, int nodeoffset, const char *name,
                uint32_t val)
{
        fdt32_t tmp = fdt32_from_cpu(val);
        return fdt_setprop(fdt, nodeoffset, name, &tmp, sizeof(tmp));
}

/**
 * fdt_setprop_u64 - set a property to a 64-bit integer
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 * @val: 64-bit integer value for the property (native endian)
 *
 * fdt_setprop_u64() sets the value of the named property in the given
 * node to the given 64-bit integer value (converting to big-endian if
 * necessary), or creates a new property with that value if it does
 * not already exist.
 *
 * This function may insert or delete data from the blob, and will
 * therefore change the offsets of some existing nodes.
 *
 * returns:
 *   0, on success
 *   -FDT_ERR_NOSPACE, there is insufficient free space in the blob to
 *     contain the new property value
 *   -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_TRUNCATED, standard meanings
 */
static inline int fdt_setprop_u64(void *fdt, int nodeoffset, const char *name,
                uint64_t val)
{
        fdt64_t tmp = fdt64_from_cpu(val);
        return fdt_setprop(fdt, nodeoffset, name, &tmp, sizeof(tmp));
}

/**
 * fdt_setprop_cell - set a property to a single cell value
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 * @val: 32-bit integer value for the property (native endian)
 *
 * This is an alternative name for fdt_setprop_u32()
 *
 * Return: 0 on success, negative libfdt error value otherwise.
 */
static inline int fdt_setprop_cell(void *fdt, int nodeoffset, const char *name,
                uint32_t val)
{
        return fdt_setprop_u32(fdt, nodeoffset, name, val);
}

/**
 * fdt_setprop_empty - set a property to an empty value
 * @fdt: pointer to the device tree blob
 * @nodeoffset: offset of the node whose property to change
 * @name: name of the property to change
 *
 * fdt_setprop_empty() sets the value of the named property in the
 * given node to an empty (zero length) value, or creates a new empty
 * property if it does not already exist.
 *
 * This function may insert or delete data from the blob, and will
 * therefore change the offsets of some existing nodes.
 *
 * returns:
 *   0, on success
 *   -FDT_ERR_NOSPACE, there is insufficient free space in the blob to
 *     contain the new property value
 *   -FDT_ERR_BADOFFSET, nodeoffset did not point to FDT_BEGIN_NODE tag
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_BADMAGIC,
 *   -FDT_ERR_BADVERSION,
 *   -FDT_ERR_BADSTATE,
 *   -FDT_ERR_BADSTRUCTURE,
 *   -FDT_ERR_BADLAYOUT,
 *   -FDT_ERR_TRUNCATED, standard meanings
 */
#define fdt_setprop_empty(fdt, nodeoffset, name) \
        fdt_setprop((fdt), (nodeoffset), (name), NULL, 0)

/**
 * fdt_add_subnode_namelen - creates a new node based on substring
 * @fdt: pointer to the device tree blob
 * @parentoffset: structure block offset of a node
 * @name: name of the subnode to create
 * @namelen: number of characters of name to consider
 *
 * Identical to fdt_add_subnode(), but use only the first @namelen
 * characters of @name as the name of the new node.  This is useful for
 * creating subnodes based on a portion of a larger string, such as a
 * full path.
 *
 * Return: structure block offset of the created subnode (>=0),
 *         negative libfdt error value otherwise
 */
int fdt_add_subnode_namelen(void *fdt, int parentoffset,
                const char *name, int namelen);

#endif /* FDT_H */
