/* SPDX-License-Identifier: LGPL-2.1-or-later */

/* Minimal, self-contained editor for the "struct" and "strings" blocks of
 * an FDT blob, sufficient to patch type 1 hypervisor VM nodes into an
 * already-installed devicetree. This avoids a libfdt dependency in the
 * freestanding EFI stub. */

#include "devicetree.h"
#include "efi-log.h"
#include "efi-string.h"
#include "fdt-writer.h"
#include "util.h"

typedef struct {
        uint8_t *data;
        size_t len;
        size_t cap;
} FdtBuf;

static void fdt_buf_done(FdtBuf *buf) {
        free(buf->data);
        buf->data = NULL;
        buf->len = buf->cap = 0;
}

static void fdt_buf_reserve(FdtBuf *buf, size_t extra) {
        if (buf->len + extra <= buf->cap)
                return;

        size_t new_cap = buf->cap * 2;
        if (new_cap < buf->len + extra)
                new_cap = buf->len + extra;
        if (new_cap < 256)
                new_cap = 256;

        buf->data = xrealloc(buf->data, buf->cap, new_cap);
        buf->cap = new_cap;
}

/* Shifts the 'n' bytes at 'src' up to 'dst' (dst > src), where the two
 * ranges may overlap. util.h/efi-string.h only provide memchr/memcmp/memcpy/
 * memset for this freestanding build (no memmove, and __builtin_memmove can
 * still lower to an external libcall that isn't available at link time), so
 * we do the overlap-safe copy by hand: since dst > src, copying back-to-front
 * guarantees every byte is read before it is overwritten. */
static void fdt_buf_shift_up(uint8_t *dst, const uint8_t *src, size_t n) {
        for (size_t i = n; i > 0; i--)
                dst[i - 1] = src[i - 1];
}

/* Inserts len bytes of data at byte offset 'at' (0 <= at <= buf->len),
 * shifting any existing trailing bytes forward. */
static void fdt_buf_insert(FdtBuf *buf, size_t at, const void *data, size_t len) {
        assert(at <= buf->len);

        if (len == 0)
                return;

        fdt_buf_reserve(buf, len);

        fdt_buf_shift_up(buf->data + at + len, buf->data + at, buf->len - at);
        if (data)
                memcpy(buf->data + at, data, len);
        else
                memset(buf->data + at, 0, len);
        buf->len += len;
}

/* be32toh()/htobe32() are the same byte-swap operation on our
 * little-endian targets; only be32toh() is provided by util.h, so we reuse
 * it for the host-to-big-endian direction too. */
static void fdt_buf_insert_u32be(FdtBuf *buf, size_t at, uint32_t v) {
        uint32_t be = be32toh(v);
        fdt_buf_insert(buf, at, &be, sizeof(be));
}

/* Inserts a nul-terminated name padded up to a 4-byte boundary (as required
 * between FDT_BEGIN_NODE and the node body). */
static void fdt_buf_insert_name(FdtBuf *buf, size_t at, const char *name) {
        size_t namelen = strlen8(name) + 1;
        size_t padded = ALIGN4(namelen);

        fdt_buf_insert(buf, at, NULL, padded);
        memcpy(buf->data + at, name, namelen);
}

/* Starting at the offset of a node's FDT_BEGIN_NODE token, returns the
 * offset of its matching FDT_END_NODE token by walking the struct block and
 * tracking nesting depth. */
static size_t fdt_struct_node_end(const FdtBuf *struct_buf, size_t begin_off) {
        size_t off = begin_off;
        int depth = 0;

        for (;;) {
                assert(off + 4 <= struct_buf->len);
                uint32_t token = be32toh(*(const uint32_t *) (struct_buf->data + off));
                off += 4;

                switch (token) {
                case FDT_BEGIN_NODE: {
                        size_t namelen = strlen8((const char *) (struct_buf->data + off)) + 1;
                        off += ALIGN4(namelen);
                        depth++;
                        break;
                }
                case FDT_END_NODE:
                        depth--;
                        if (depth == 0)
                                return off - 4;
                        break;
                case FDT_PROP: {
                        uint32_t len = be32toh(*(const uint32_t *) (struct_buf->data + off));
                        off += 8; /* len + nameoff */
                        off += ALIGN4(len);
                        break;
                }
                case FDT_NOP:
                        break;
                default:
                        assert(false);
                }
        }
}

/* Looks up a direct child of the node beginning at node_begin_off by name.
 * Returns the child's FDT_BEGIN_NODE offset, or SIZE_MAX if not found. */
static size_t fdt_struct_find_child(const FdtBuf *struct_buf, size_t node_begin_off, const char *name) {
        size_t node_end = fdt_struct_node_end(struct_buf, node_begin_off);
        size_t off = node_begin_off + 4;

        /* Skip our own name. */
        off += ALIGN4(strlen8((const char *) (struct_buf->data + off)) + 1);

        while (off < node_end) {
                uint32_t token = be32toh(*(const uint32_t *) (struct_buf->data + off));

                if (token == FDT_BEGIN_NODE) {
                        const char *child_name = (const char *) (struct_buf->data + off + 4);
                        size_t child_end = fdt_struct_node_end(struct_buf, off);

                        if (streq8(child_name, name))
                                return off;

                        off = child_end + 4;
                } else if (token == FDT_PROP) {
                        uint32_t len = be32toh(*(const uint32_t *) (struct_buf->data + off + 4));
                        off += 4 + 8 + ALIGN4(len);
                } else if (token == FDT_NOP)
                        off += 4;
                else
                        assert(false);
        }

        return SIZE_MAX;
}

/* Inserts a new, empty node named 'name' at byte offset 'at', and returns
 * the offset of its FDT_BEGIN_NODE token (== 'at'). */
static size_t fdt_struct_insert_empty_node(FdtBuf *struct_buf, size_t at, const char *name) {
        fdt_buf_insert_u32be(struct_buf, at, FDT_END_NODE);
        fdt_buf_insert_name(struct_buf, at, name);
        fdt_buf_insert_u32be(struct_buf, at, FDT_BEGIN_NODE);
        return at;
}

/* Finds the direct child named 'name' under the node at node_begin_off, or
 * creates an empty one (inserted right before the parent's FDT_END_NODE)
 * if none exists. Returns the child's FDT_BEGIN_NODE offset. */
static size_t fdt_find_or_create_child(FdtBuf *struct_buf, size_t node_begin_off, const char *name) {
        size_t child = fdt_struct_find_child(struct_buf, node_begin_off, name);
        if (child != SIZE_MAX)
                return child;

        size_t insert_at = fdt_struct_node_end(struct_buf, node_begin_off);
        return fdt_struct_insert_empty_node(struct_buf, insert_at, name);
}

static uint32_t fdt_strings_add(FdtBuf *strings_buf, const char *name) {
        uint32_t off = (uint32_t) strings_buf->len;
        fdt_buf_insert(strings_buf, strings_buf->len, name, strlen8(name) + 1);
        return off;
}

/* Inserts an FDT_PROP entry for 'prop_name' with the given raw bytes, into
 * the node at node_begin_off, right before that node's FDT_END_NODE. */
static void fdt_add_prop(
                FdtBuf *struct_buf, FdtBuf *strings_buf,
                size_t node_begin_off, const char *prop_name,
                const void *data, uint32_t data_len) {

        size_t at = fdt_struct_node_end(struct_buf, node_begin_off);
        uint32_t nameoff = fdt_strings_add(strings_buf, prop_name);

        fdt_buf_insert(struct_buf, at, NULL, ALIGN4(data_len));
        if (data_len > 0)
                memcpy(struct_buf->data + at, data, data_len);
        fdt_buf_insert_u32be(struct_buf, at, nameoff);
        fdt_buf_insert_u32be(struct_buf, at, data_len);
        fdt_buf_insert_u32be(struct_buf, at, FDT_PROP);
}

static void fdt_add_prop_u32(
                FdtBuf *struct_buf, FdtBuf *strings_buf,
                size_t node_begin_off, const char *prop_name, uint32_t v) {

        uint32_t be = be32toh(v);
        fdt_add_prop(struct_buf, strings_buf, node_begin_off, prop_name, &be, sizeof(be));
}

static void fdt_add_prop_u64_pair(
                FdtBuf *struct_buf, FdtBuf *strings_buf,
                size_t node_begin_off, const char *prop_name, uint64_t hi, uint64_t lo) {

        uint32_t be[4] = {
                be32toh((uint32_t) (hi >> 32)),
                be32toh((uint32_t) hi),
                be32toh((uint32_t) (lo >> 32)),
                be32toh((uint32_t) lo),
        };
        fdt_add_prop(struct_buf, strings_buf, node_begin_off, prop_name, be, sizeof(be));
}

/* Scans the struct block for the highest "phandle"/"linux,phandle" value
 * already in use, and returns one higher, so a new node can be given a
 * phandle guaranteed not to collide with any already present in the DTB. */
static uint32_t fdt_alloc_phandle(const FdtBuf *struct_buf, const FdtBuf *strings_buf) {
        uint32_t max_phandle = 0;
        size_t off = 0;

        while (off + 4 <= struct_buf->len) {
                uint32_t token = be32toh(*(const uint32_t *) (struct_buf->data + off));
                off += 4;

                if (token == FDT_BEGIN_NODE) {
                        off += ALIGN4(strlen8((const char *) (struct_buf->data + off)) + 1);
                } else if (token == FDT_PROP) {
                        uint32_t len = be32toh(*(const uint32_t *) (struct_buf->data + off));
                        uint32_t nameoff = be32toh(*(const uint32_t *) (struct_buf->data + off + 4));
                        const char *pname = (const char *) (strings_buf->data + nameoff);

                        if (len == 4 && (streq8(pname, "phandle") || streq8(pname, "linux,phandle"))) {
                                uint32_t v = be32toh(*(const uint32_t *) (struct_buf->data + off + 8));
                                if (v > max_phandle)
                                        max_phandle = v;
                        }

                        off += 8 + ALIGN4(len);
                } else if (token == FDT_END_NODE || token == FDT_NOP) {
                        /* nothing to skip */
                } else
                        break;
        }

        return max_phandle + 1;
}

EFI_STATUS fdt_patch_type_1_hypervisor_vms(
                struct devicetree_state *dt_state,
                const FdtVmPayload payloads[],
                size_t n_payloads) {

        assert(dt_state);
        assert(payloads);
        assert(n_payloads > 0);

        const FdtHeader *src = (const FdtHeader *) PHYSICAL_ADDRESS_TO_POINTER(dt_state->addr);
        if (!src || be32toh(src->magic) != UINT32_C(0xd00dfeed))
                return EFI_INVALID_PARAMETER;

        uint32_t struct_off = be32toh(src->off_dt_struct);
        uint32_t struct_size = be32toh(src->size_dt_struct);
        uint32_t strings_off = be32toh(src->off_dt_strings);
        uint32_t strings_size = be32toh(src->size_dt_strings);
        uint32_t mem_rsvmap_off = be32toh(src->off_mem_rsv_map);

        _cleanup_(fdt_buf_done) FdtBuf struct_buf = {};
        _cleanup_(fdt_buf_done) FdtBuf strings_buf = {};
        fdt_buf_insert(&struct_buf, 0, (const uint8_t *) src + struct_off, struct_size);
        fdt_buf_insert(&strings_buf, 0, (const uint8_t *) src + strings_off, strings_size);

        size_t chosen = fdt_find_or_create_child(&struct_buf, 0, "chosen");
        size_t hyp = fdt_find_or_create_child(&struct_buf, chosen, "hypervisor");
        size_t vms = fdt_find_or_create_child(&struct_buf, hyp, "vms");
        fdt_add_prop_u32(&struct_buf, &strings_buf, vms, "boot-order", 0);

        bool resv_exists = fdt_struct_find_child(&struct_buf, 0, "reserved-memory") != SIZE_MAX;
        size_t resv = fdt_find_or_create_child(&struct_buf, 0, "reserved-memory");
        if (!resv_exists) {
                fdt_add_prop_u32(&struct_buf, &strings_buf, resv, "#address-cells", 2);
                fdt_add_prop_u32(&struct_buf, &strings_buf, resv, "#size-cells", 2);
        }

        for (size_t i = 0; i < n_payloads; i++) {
                const FdtVmPayload *p = payloads + i;
                char vm_name[] = { 'v', 'm', '@', p->id, 0 };
                char image_name[] = { 'i', 'm', 'a', 'g', 'e', '@', p->id, 0 };
                char dtb_name[] = { 'd', 't', 'b', '@', p->id, 0 };

                size_t image = fdt_find_or_create_child(&struct_buf, resv, image_name);
                uint32_t image_phandle = fdt_alloc_phandle(&struct_buf, &strings_buf);
                fdt_add_prop_u64_pair(
                                &struct_buf, &strings_buf, image, "reg", p->kernel_addr, p->kernel_size);
                fdt_add_prop_u32(&struct_buf, &strings_buf, image, "phandle", image_phandle);

                uint32_t dtb_phandle = 0;
                if (p->dtb_size > 0) {
                        size_t dtb = fdt_find_or_create_child(&struct_buf, resv, dtb_name);
                        dtb_phandle = fdt_alloc_phandle(&struct_buf, &strings_buf);
                        fdt_add_prop_u64_pair(
                                        &struct_buf, &strings_buf, dtb, "reg", p->dtb_addr, p->dtb_size);
                        fdt_add_prop_u32(&struct_buf, &strings_buf, dtb, "phandle", dtb_phandle);
                }

                chosen = fdt_find_or_create_child(&struct_buf, 0, "chosen");
                hyp = fdt_find_or_create_child(&struct_buf, chosen, "hypervisor");
                vms = fdt_find_or_create_child(&struct_buf, hyp, "vms");
                size_t vm = fdt_find_or_create_child(&struct_buf, vms, vm_name);
                fdt_add_prop_u32(&struct_buf, &strings_buf, vm, "order", (uint32_t) i);
                fdt_add_prop_u32(&struct_buf, &strings_buf, vm, "primary-vm", i == 0);
                fdt_add_prop_u32(&struct_buf, &strings_buf, vm, "auth-type", 1);
                fdt_add_prop_u32(&struct_buf, &strings_buf, vm, "image-memory", image_phandle);
                if (dtb_phandle != 0)
                        fdt_add_prop_u32(&struct_buf, &strings_buf, vm, "dtb-memory", dtb_phandle);
                fdt_add_prop_u64_pair(
                                &struct_buf, &strings_buf, vm, "initrd", p->initrd_addr, p->initrd_size);
                fdt_add_prop(
                                &struct_buf,
                                &strings_buf,
                                vm,
                                "bootargs",
                                p->bootargs ?: "",
                                (uint32_t) (strlen8(p->bootargs ?: "") + 1));
                if (p->attributes && p->attributes_size > 0)
                        fdt_add_prop(
                                        &struct_buf,
                                        &strings_buf,
                                        vm,
                                        "attributes",
                                        p->attributes,
                                        (uint32_t) p->attributes_size);
        }

        size_t mem_rsvmap_size = struct_off - mem_rsvmap_off;
        size_t header_size = ALIGN8(sizeof(FdtHeader));
        size_t total = header_size + mem_rsvmap_size + struct_buf.len + strings_buf.len;
        _cleanup_free_ uint8_t *blob = xmalloc(total);
        memset(blob, 0, header_size);

        FdtHeader *dst = (FdtHeader *) blob;
        *dst = (FdtHeader) {
                .magic = be32toh(UINT32_C(0xd00dfeed)),
                .total_size = be32toh((uint32_t) total),
                .off_dt_struct = be32toh((uint32_t) (header_size + mem_rsvmap_size)),
                .off_dt_strings = be32toh((uint32_t) (header_size + mem_rsvmap_size + struct_buf.len)),
                .off_mem_rsv_map = be32toh((uint32_t) header_size),
                .version = src->version,
                .last_comp_version = src->last_comp_version,
                .boot_cpuid_phys = src->boot_cpuid_phys,
                .size_dt_strings = be32toh((uint32_t) strings_buf.len),
                .size_dt_struct = be32toh((uint32_t) struct_buf.len),
        };

        memcpy(blob + header_size, (const uint8_t *) src + mem_rsvmap_off, mem_rsvmap_size);
        memcpy(blob + header_size + mem_rsvmap_size, struct_buf.data, struct_buf.len);
        memcpy(blob + header_size + mem_rsvmap_size + struct_buf.len, strings_buf.data, strings_buf.len);

        return devicetree_install_from_memory(dt_state, blob, total);
}
