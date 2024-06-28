/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "fileio.h"
#include "macro.h"
#include "smbios11.h"
#include "virt.h"

int read_smbios11_field(unsigned i, size_t max_size, char **ret_data, size_t *ret_size) {
        _cleanup_free_ char *p = NULL, *contents = NULL;
        _cleanup_free_ void *data = NULL;
        size_t size, contents_size;
        int r;

        assert(ret_data);
        assert(ret_size);

        /* Parses DMI OEM strings fields (SMBIOS type 11), as settable with qemu's -smbios type=11,value=… switch. */

        if (detect_container() > 0) /* don't access /sys/ in a container */
                return -ENOENT;

        if (asprintf(&p, "/sys/firmware/dmi/entries/11-%u/raw", i) < 0)
                return -ENOMEM;

        struct dmi_field_header {
                uint8_t type;
                uint8_t length;
                uint16_t handle;
                uint8_t count;
                char contents[];
        } _packed_ *dmi_field_header;

        assert_cc(offsetof(struct dmi_field_header, contents) == 5);

        /* We don't use read_virtual_file() because it only reads a single page of bytes from the DMI sysfs
         * file. Since the SMBIOS data is immutable after boot, it's safe to use read_full_file_full() here. */
        r = read_full_file_full(
                        AT_FDCWD, p,
                        /* offset = */ UINT64_MAX,
                        max_size >= SIZE_MAX - offsetof(struct dmi_field_header, contents) ? SIZE_MAX :
                        sizeof(dmi_field_header) + max_size,
                        /* flags = */ 0,
                        /* bind_name = */ NULL,
                        (char**) &data, &size);
        if (r < 0)
                return r;

        if (size < offsetof(struct dmi_field_header, contents))
                return -EBADMSG;

        dmi_field_header = data;
        if (dmi_field_header->type != 11 ||
            dmi_field_header->length != offsetof(struct dmi_field_header, contents))
                return -EBADMSG;

        contents_size = size - offsetof(struct dmi_field_header, contents);
        contents = memdup_suffix0(dmi_field_header->contents, contents_size);
        if (!contents)
                return -ENOMEM;

        *ret_data = TAKE_PTR(contents);
        *ret_size = contents_size;

        return r; /* NB! read_virtual_file() returns 0 on incomplete reads, and 1 in complete reads */
}
