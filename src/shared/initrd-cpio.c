/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "initrd-cpio.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "machine-credential.h"
#include "string-util.h"
#include "tmpfile-util.h"

static int write_pad4(int fd, uint64_t *offset) {
        int r;

        assert(offset);

        size_t pad = (4 - (*offset & 3)) & 3;
        if (pad == 0)
                return 0;

        static const char zeros[4] = {};
        r = loop_write(fd, zeros, pad);
        if (r < 0)
                return r;
        *offset += pad;

        return 0;
}

static char *write_cpio_word(char *p, uint32_t v) {
        const char *hex = LOWERCASE_HEXDIGITS;

        assert(p);

        /* Writes a CPIO header 8 character hex value */

        for (size_t i = 0; i < 8; i++)
                p[7-i] = hex[(v >> (4 * i)) & 0xF];

        return p + 8;
}

static int write_cpio_entry(
                int fd,
                uint32_t mode,                  /* full mode incl. S_IFDIR or S_IFREG */
                const char *path,
                const void *data,               /* NULL for directories */
                size_t data_size,               /* 0 for directories */
                uint32_t *inode_counter,
                uint64_t *offset) {

        char header[6 + 13 * 8]; /* 6 magic + 13 x 8-byte hex fields = 110 */
        char *p = header;
        int r;

        assert(data_size <= UINT32_MAX);

        size_t namesize = strlen(path) + 1;

        p = mempcpy(p, "070701", 6); /* magic ID */
        p = write_cpio_word(p, (*inode_counter)++);                         /* inode */
        p = write_cpio_word(p, mode);                                       /* mode */
        p = write_cpio_word(p, 0);                                          /* uid */
        p = write_cpio_word(p, 0);                                          /* gid */
        p = write_cpio_word(p, 1);                                          /* nlink */
        p = write_cpio_word(p, 0);                                          /* mtime */
        p = write_cpio_word(p, data_size);                                  /* size */
        p = write_cpio_word(p, 0);                                          /* major(dev) */
        p = write_cpio_word(p, 0);                                          /* minor(dev) */
        p = write_cpio_word(p, 0);                                          /* major(rdev) */
        p = write_cpio_word(p, 0);                                          /* minor(rdev) */
        p = write_cpio_word(p, namesize);                                   /* fname size */
        p = write_cpio_word(p, 0);                                          /* crc */

        assert(p == header + sizeof header);

        r = loop_write(fd, header, sizeof header);
        if (r < 0)
                return r;
        *offset += sizeof header;

        r = loop_write(fd, path, namesize);
        if (r < 0)
                return r;
        *offset += namesize;

        r = write_pad4(fd, offset);
        if (r < 0)
                return r;

        r = loop_write(fd, data, data_size);
        if (r < 0)
                return r;
        *offset += data_size;

        r = write_pad4(fd, offset);
        if (r < 0)
                return r;

        return 0;
}

static int write_cpio_trailer(int fd, uint64_t *offset) {
        int r;
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

        assert_cc(sizeof(trailer) % 4 == 0);

        r = loop_write(fd, trailer, sizeof trailer);
        if (r < 0)
                return r;
        *offset += sizeof trailer;

        return 0;
}

int initrd_cpio_credentials_to_tempfile(
                const MachineCredentialContext *creds,
                char **ret_path) {

        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        uint32_t inode = 1;
        uint64_t offset = 0;
        int r;

        assert(creds);
        assert(ret_path);

        r = tempfn_random_child(NULL, "vmspawn-credentials-cpio", &path);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temp file name: %m");

        fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create temp file %s: %m", path);

        r = write_cpio_entry(fd, S_IFDIR | 0500, ".extra",             NULL, 0, &inode, &offset);
        if (r < 0)
                return r;
        r = write_cpio_entry(fd, S_IFDIR | 0500, ".extra/credentials", NULL, 0, &inode, &offset);
        if (r < 0)
                return r;

        FOREACH_ARRAY(c, creds->credentials, creds->n_credentials) {
                _cleanup_free_ char *cpath = strjoin(".extra/credentials/", c->id, ".cred");
                if (!cpath)
                        return log_oom();

                r = write_cpio_entry(fd, S_IFREG | 0400, cpath, c->data, c->size, &inode, &offset);
                if (r < 0)
                        return r;
        }

        r = write_cpio_trailer(fd, &offset);
        if (r < 0)
                return r;

        *ret_path = TAKE_PTR(path);
        return 0;
}
