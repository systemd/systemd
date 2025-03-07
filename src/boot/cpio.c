/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "cpio.h"
#include "device-path-util.h"
#include "measure.h"
#include "proto/device-path.h"
#include "util.h"

static char *write_cpio_word(char *p, uint32_t v) {
        static const char hex[] = "0123456789abcdef";

        assert(p);

        /* Writes a CPIO header 8 character hex value */

        for (size_t i = 0; i < 8; i++)
                p[7-i] = hex[(v >> (4 * i)) & 0xF];

        return p + 8;
}

static char *mangle_filename(char *p, const char16_t *f) {
        char* w;

        assert(p);
        assert(f);

        /* Basically converts UTF-16 to plain ASCII (note that we filtered non-ASCII filenames beforehand, so
         * this operation is always safe) */

        for (w = p; *f != 0; f++) {
                assert(*f <= 0x7fu);

                *(w++) = *f;
        }

        *(w++) = 0;
        return w;
}

static char *pad4(char *p, const char *start) {
        assert(p);
        assert(start);
        assert(p >= start);

        /* Appends NUL bytes to 'p', until the address is divisible by 4, when taken relative to 'start' */

        while ((p - start) % 4 != 0)
                *(p++) = 0;

        return p;
}

static EFI_STATUS pack_cpio_one(
                const char16_t *fname,
                const void *contents,
                size_t contents_size,
                const char *target_dir_prefix,
                uint32_t access_mode,
                uint32_t *inode_counter,
                void **cpio_buffer,
                size_t *cpio_buffer_size) {

        size_t l, target_dir_prefix_size, fname_size, q;
        char *a;

        assert(fname);
        assert(contents || contents_size == 0);
        assert(target_dir_prefix);
        assert(inode_counter);
        assert(cpio_buffer);
        assert(cpio_buffer_size);

        /* Serializes one file in the cpio format understood by the kernel initrd logic.
         *
         * See: https://docs.kernel.org/driver-api/early-userspace/buffer-format.html */

        if (contents_size > UINT32_MAX) /* cpio cannot deal with > 32-bit file sizes */
                return EFI_LOAD_ERROR;

        if (*inode_counter == UINT32_MAX) /* more than 2^32-1 inodes? yikes. cpio doesn't support that either */
                return EFI_OUT_OF_RESOURCES;

        l = 6 + 13*8 + 1 + 1; /* Fixed CPIO header size, slash separator, and NUL byte after the file name */

        target_dir_prefix_size = strlen8(target_dir_prefix);
        if (l > SIZE_MAX - target_dir_prefix_size)
                return EFI_OUT_OF_RESOURCES;
        l += target_dir_prefix_size;

        fname_size = strlen16(fname);
        if (l > SIZE_MAX - fname_size)
                return EFI_OUT_OF_RESOURCES;
        l += fname_size; /* append space for file name */

        /* CPIO can't deal with fnames longer than 2^32-1 */
        if (target_dir_prefix_size + fname_size >= UINT32_MAX)
                return EFI_OUT_OF_RESOURCES;

        /* Align the whole header to 4 byte size */
        l = ALIGN4(l);
        if (l == SIZE_MAX) /* overflow check */
                return EFI_OUT_OF_RESOURCES;

        /* Align the contents to 4 byte size */
        q = ALIGN4(contents_size);
        if (q == SIZE_MAX) /* overflow check */
                return EFI_OUT_OF_RESOURCES;

        if (l > SIZE_MAX - q) /* overflow check */
                return EFI_OUT_OF_RESOURCES;
        l += q; /* Add contents to header */

        if (*cpio_buffer_size > SIZE_MAX - l) /* overflow check */
                return EFI_OUT_OF_RESOURCES;
        a = xrealloc(*cpio_buffer, *cpio_buffer_size, *cpio_buffer_size + l);

        *cpio_buffer = a;
        a = (char *) *cpio_buffer + *cpio_buffer_size;

        a = mempcpy(a, "070701", 6); /* magic ID */

        a = write_cpio_word(a, (*inode_counter)++);                         /* inode */
        a = write_cpio_word(a, access_mode | 0100000 /* = S_IFREG */);      /* mode */
        a = write_cpio_word(a, 0);                                          /* uid */
        a = write_cpio_word(a, 0);                                          /* gid */
        a = write_cpio_word(a, 1);                                          /* nlink */

        /* Note: we don't make any attempt to propagate the mtime here, for two reasons: it's a mess given
         * that FAT usually is assumed to operate with timezoned timestamps, while UNIX does not. More
         * importantly though: the modifications times would hamper our goals of providing stable
         * measurements for the same boots. After all we extend the initrds we generate here into TPM2
         * PCRs. */
        a = write_cpio_word(a, 0);                                          /* mtime */
        a = write_cpio_word(a, contents_size);                              /* size */
        a = write_cpio_word(a, 0);                                          /* major(dev) */
        a = write_cpio_word(a, 0);                                          /* minor(dev) */
        a = write_cpio_word(a, 0);                                          /* major(rdev) */
        a = write_cpio_word(a, 0);                                          /* minor(rdev) */
        a = write_cpio_word(a, target_dir_prefix_size + fname_size + 2);    /* fname size */
        a = write_cpio_word(a, 0);                                          /* "crc" */

        a = mempcpy(a, target_dir_prefix, target_dir_prefix_size);
        *(a++) = '/';
        a = mangle_filename(a, fname);

        /* Pad to next multiple of 4 */
        a = pad4(a, *cpio_buffer);

        a = mempcpy(a, contents, contents_size);

        /* Pad to next multiple of 4 */
        a = pad4(a, *cpio_buffer);

        assert(a == (char *) *cpio_buffer + *cpio_buffer_size + l);
        *cpio_buffer_size += l;

        return EFI_SUCCESS;
}

static EFI_STATUS pack_cpio_dir(
                const char *path,
                uint32_t access_mode,
                uint32_t *inode_counter,
                void **cpio_buffer,
                size_t *cpio_buffer_size) {

        size_t l, path_size;
        char *a;

        assert(path);
        assert(inode_counter);
        assert(cpio_buffer);
        assert(cpio_buffer_size);

        /* Serializes one directory inode in cpio format. Note that cpio archives must first create the dirs
         * they want to place files in. */

        if (*inode_counter == UINT32_MAX)
                return EFI_OUT_OF_RESOURCES;

        l = 6 + 13*8 + 1; /* Fixed CPIO header size, and NUL byte after the file name */

        path_size = strlen8(path);
        if (l > SIZE_MAX - path_size)
                return EFI_OUT_OF_RESOURCES;
        l += path_size;

        /* Align the whole header to 4 byte size */
        l = ALIGN4(l);
        if (l == SIZE_MAX) /* overflow check */
                return EFI_OUT_OF_RESOURCES;

        if (*cpio_buffer_size > SIZE_MAX - l) /* overflow check */
                return EFI_OUT_OF_RESOURCES;

        *cpio_buffer = a = xrealloc(*cpio_buffer, *cpio_buffer_size, *cpio_buffer_size + l);
        a = (char *) *cpio_buffer + *cpio_buffer_size;

        a = mempcpy(a, "070701", 6); /* magic ID */

        a = write_cpio_word(a, (*inode_counter)++);                         /* inode */
        a = write_cpio_word(a, access_mode | 0040000 /* = S_IFDIR */);      /* mode */
        a = write_cpio_word(a, 0);                                          /* uid */
        a = write_cpio_word(a, 0);                                          /* gid */
        a = write_cpio_word(a, 1);                                          /* nlink */
        a = write_cpio_word(a, 0);                                          /* mtime */
        a = write_cpio_word(a, 0);                                          /* size */
        a = write_cpio_word(a, 0);                                          /* major(dev) */
        a = write_cpio_word(a, 0);                                          /* minor(dev) */
        a = write_cpio_word(a, 0);                                          /* major(rdev) */
        a = write_cpio_word(a, 0);                                          /* minor(rdev) */
        a = write_cpio_word(a, path_size + 1);                              /* fname size */
        a = write_cpio_word(a, 0);                                          /* "crc" */

        a = mempcpy(a, path, path_size + 1);

        /* Pad to next multiple of 4 */
        a = pad4(a, *cpio_buffer);

        assert(a == (char *) *cpio_buffer + *cpio_buffer_size + l);

        *cpio_buffer_size += l;
        return EFI_SUCCESS;
}

static EFI_STATUS pack_cpio_prefix(
                const char *path,
                uint32_t dir_mode,
                uint32_t *inode_counter,
                void **cpio_buffer,
                size_t *cpio_buffer_size) {

        EFI_STATUS err;

        assert(path);
        assert(inode_counter);
        assert(cpio_buffer);
        assert(cpio_buffer_size);

        /* Serializes directory inodes of all prefix paths of the specified path in cpio format. Note that
         * (similar to mkdir -p behaviour) all leading paths are created with 0555 access mode, only the
         * final dir is created with the specified directory access mode. */

        for (const char *p = path;;) {
                const char *e;

                e = strchr8(p, '/');
                if (!e)
                        break;

                if (e > p) {
                        _cleanup_free_ char *t = NULL;

                        t = xstrndup8(path, e - path);
                        if (!t)
                                return EFI_OUT_OF_RESOURCES;

                        err = pack_cpio_dir(t, 0555, inode_counter, cpio_buffer, cpio_buffer_size);
                        if (err != EFI_SUCCESS)
                                return err;
                }

                p = e + 1;
        }

        return pack_cpio_dir(path, dir_mode, inode_counter, cpio_buffer, cpio_buffer_size);
}

static EFI_STATUS pack_cpio_trailer(
                void **cpio_buffer,
                size_t *cpio_buffer_size) {

        static const char trailer[] =
                "070701"
                "00000000"
                "00000000"
                "00000000"
                "00000000"
                "00000001"
                "00000000"
                "00000000"
                "00000000"
                "00000000"
                "00000000"
                "00000000"
                "0000000B"
                "00000000"
                "TRAILER!!!\0\0\0"; /* There's a fourth NUL byte appended here, because this is a string */

        /* Generates the cpio trailer record that indicates the end of our initrd cpio archive */

        assert(cpio_buffer);
        assert(cpio_buffer_size);
        assert_cc(sizeof(trailer) % 4 == 0);

        *cpio_buffer = xrealloc(*cpio_buffer, *cpio_buffer_size, *cpio_buffer_size + sizeof(trailer));
        memcpy((uint8_t*) *cpio_buffer + *cpio_buffer_size, trailer, sizeof(trailer));
        *cpio_buffer_size += sizeof(trailer);

        return EFI_SUCCESS;
}

EFI_STATUS pack_cpio(
                EFI_LOADED_IMAGE_PROTOCOL *loaded_image,
                const char16_t *dropin_dir,
                const char16_t *match_suffix,
                const char16_t *exclude_suffix,
                const char *target_dir_prefix,
                uint32_t dir_mode,
                uint32_t access_mode,
                uint32_t tpm_pcr,
                const char16_t *tpm_description,
                struct iovec *ret_buffer,
                bool *ret_measured) {

        _cleanup_file_close_ EFI_FILE *root = NULL, *extra_dir = NULL;
        size_t dirent_size = 0, buffer_size = 0, n_items = 0, n_allocated = 0;
        _cleanup_free_ EFI_FILE_INFO *dirent = NULL;
        _cleanup_strv_free_ char16_t **items = NULL;
        _cleanup_free_ void *buffer = NULL;
        uint32_t inode = 1; /* inode counter, so that each item gets a new inode */
        EFI_STATUS err;

        assert(loaded_image);
        assert(target_dir_prefix);
        assert(ret_buffer);

        if (!loaded_image->DeviceHandle)
                goto nothing;

        if (!dropin_dir)
                goto nothing;

        err = open_volume(loaded_image->DeviceHandle, &root);
        if (err == EFI_UNSUPPORTED)
                /* Error will be unsupported if the bootloader doesn't implement the file system protocol on
                 * its file handles. */
                goto nothing;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Unable to open root directory: %m");

        err = open_directory(root, dropin_dir, &extra_dir);
        if (err == EFI_NOT_FOUND)
                /* No extra subdir, that's totally OK */
                goto nothing;
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to open extra directory of loaded image: %m");

        for (;;) {
                _cleanup_free_ char16_t *d = NULL;

                err = readdir(extra_dir, &dirent, &dirent_size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to read extra directory of loaded image: %m");
                if (!dirent) /* End of directory */
                        break;

                if (dirent->FileName[0] == '.')
                        continue;
                if (FLAGS_SET(dirent->Attribute, EFI_FILE_DIRECTORY))
                        continue;
                if (match_suffix && !endswith_no_case(dirent->FileName, match_suffix))
                        continue;
                if (exclude_suffix && endswith_no_case(dirent->FileName, exclude_suffix))
                        continue;
                if (!is_ascii(dirent->FileName))
                        continue;
                if (strlen16(dirent->FileName) > 255) /* Max filename size on Linux */
                        continue;

                d = xstrdup16(dirent->FileName);

                if (n_items+2 > n_allocated) {
                        /* We allocate 16 entries at a time, as a matter of optimization */
                        if (n_items > (SIZE_MAX / sizeof(uint16_t)) - 16) /* Overflow check, just in case */
                                return log_oom();

                        size_t m = n_items + 16;
                        items = xrealloc(items, n_allocated * sizeof(uint16_t *), m * sizeof(uint16_t *));
                        n_allocated = m;
                }

                items[n_items++] = TAKE_PTR(d);
                items[n_items] = NULL; /* Let's always NUL terminate, to make freeing via strv_free() easy */
        }

        if (n_items == 0)
                /* Empty directory */
                goto nothing;

        /* Now, sort the files we found, to make this uniform and stable (and to ensure the TPM measurements
         * are not dependent on read order) */
        sort_pointer_array((void**) items, n_items, (compare_pointer_func_t) strcmp16);

        /* Generate the leading directory inodes right before adding the first files, to the
         * archive. Otherwise the cpio archive cannot be unpacked, since the leading dirs won't exist. */
        err = pack_cpio_prefix(target_dir_prefix, dir_mode, &inode, &buffer, &buffer_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to pack cpio prefix: %m");

        for (size_t i = 0; i < n_items; i++) {
                _cleanup_free_ char *content = NULL;
                size_t contentsize = 0;  /* avoid false maybe-uninitialized warning */

                err = file_read(extra_dir, items[i], 0, 0, &content, &contentsize);
                if (err != EFI_SUCCESS) {
                        log_error_status(err, "Failed to read %ls, ignoring: %m", items[i]);
                        continue;
                }

                err = pack_cpio_one(
                                items[i],
                                content, contentsize,
                                target_dir_prefix,
                                access_mode,
                                &inode,
                                &buffer, &buffer_size);
                if (err != EFI_SUCCESS)
                        return log_error_status(err, "Failed to pack cpio file %ls: %m", dirent->FileName);
        }

        err = pack_cpio_trailer(&buffer, &buffer_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to pack cpio trailer: %m");

        err = tpm_log_ipl_event(
                        tpm_pcr, POINTER_TO_PHYSICAL_ADDRESS(buffer), buffer_size, tpm_description, ret_measured);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err,
                                "Unable to add cpio TPM measurement for PCR %u (%ls), ignoring: %m",
                                tpm_pcr,
                                tpm_description);

        *ret_buffer = IOVEC_MAKE(TAKE_PTR(buffer), buffer_size);
        return EFI_SUCCESS;

nothing:
        *ret_buffer = (struct iovec) {};

        if (ret_measured)
                *ret_measured = false;

        return EFI_SUCCESS;
}

EFI_STATUS pack_cpio_literal(
                const void *data,
                size_t data_size,
                const char *target_dir_prefix,
                const char16_t *target_filename,
                uint32_t dir_mode,
                uint32_t access_mode,
                uint32_t tpm_pcr,
                const char16_t *tpm_description,
                struct iovec *ret_buffer,
                bool *ret_measured) {

        uint32_t inode = 1; /* inode counter, so that each item gets a new inode */
        _cleanup_free_ void *buffer = NULL;
        size_t buffer_size = 0;
        EFI_STATUS err;

        assert(data || data_size == 0);
        assert(target_dir_prefix);
        assert(target_filename);
        assert(ret_buffer);

        /* Generate the leading directory inodes right before adding the first files, to the
         * archive. Otherwise the cpio archive cannot be unpacked, since the leading dirs won't exist. */

        err = pack_cpio_prefix(target_dir_prefix, dir_mode, &inode, &buffer, &buffer_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to pack cpio prefix: %m");

        err = pack_cpio_one(
                        target_filename,
                        data, data_size,
                        target_dir_prefix,
                        access_mode,
                        &inode,
                        &buffer, &buffer_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to pack cpio file %ls: %m", target_filename);

        err = pack_cpio_trailer(&buffer, &buffer_size);
        if (err != EFI_SUCCESS)
                return log_error_status(err, "Failed to pack cpio trailer: %m");

        err = tpm_log_ipl_event(
                        tpm_pcr, POINTER_TO_PHYSICAL_ADDRESS(buffer), buffer_size, tpm_description, ret_measured);
        if (err != EFI_SUCCESS)
                return log_error_status(
                                err,
                                "Unable to add cpio TPM measurement for PCR %u (%ls), ignoring: %m",
                                tpm_pcr,
                                tpm_description);

        *ret_buffer = IOVEC_MAKE(TAKE_PTR(buffer), buffer_size);
        return EFI_SUCCESS;
}
