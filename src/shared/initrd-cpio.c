/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/stat.h>

#include "initrd-cpio.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "machine-credential.h"
#include "string-util.h"
#include "tmpfile-util.h"

static int append_bytes(char **buf, size_t *buf_size, const void *data, size_t n) {
        assert(buf);
        assert(buf_size);
        assert(data || n == 0);

        if (n == 0)
                return 0;

        char *new_buf = realloc(*buf, *buf_size + n);
        if (!new_buf)
                return -ENOMEM;

        memcpy(new_buf + *buf_size, data, n);

        *buf = new_buf;
        *buf_size += n;
        return 0;
}

static int append_pad4(char **buf, size_t *buf_size) {
        int r;

        assert(buf);
        assert(buf_size);

        size_t pad = (4 - (*buf_size & 3)) & 3;
        if (pad == 0)
                return 0;

        static const char zeros[4] = {};
        r = append_bytes(buf, buf_size, zeros, pad);
        if (r < 0)
                return r;

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

static int append_cpio_entry(
                char **buf,
                size_t *buf_size,
                uint32_t mode,                  /* full mode incl. S_IFDIR or S_IFREG */
                const char *path,
                const void *data,               /* NULL for directories */
                size_t data_size,               /* 0 for directories */
                uint32_t *inode_counter) {

        char header[6 + 13 * 8]; /* 6 magic + 13 x 8-byte hex fields = 110 */
        char *p = header;
        int r;

        assert(buf);
        assert(buf_size);
        assert(path);
        assert(data || data_size == 0);
        assert(inode_counter);

        if (data_size > UINT32_MAX) /* cpio cannot deal with > 32-bit file sizes */
                return -EFBIG;

        size_t namesize = strlen(path) + 1;
        if (namesize > UINT32_MAX) /* cpio also cannot deal with names > 32-bit */
                return -ENAMETOOLONG;

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

        r = append_bytes(buf, buf_size, header, sizeof header);
        if (r < 0)
                return r;

        r = append_bytes(buf, buf_size, path, namesize);
        if (r < 0)
                return r;

        r = append_pad4(buf, buf_size);
        if (r < 0)
                return r;

        r = append_bytes(buf, buf_size, data, data_size);
        if (r < 0)
                return r;

        r = append_pad4(buf, buf_size);
        if (r < 0)
                return r;

        return 0;
}

static int append_cpio_trailer(char **buf, size_t *buf_size) {
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
                "0000000b"
                "00000000"
                "TRAILER!!!\0\0\0"; /* There's a fourth NUL byte appended here, because this is a string */

        assert_cc(sizeof(trailer) % 4 == 0);
        assert(buf);
        assert(buf_size);

        r = append_bytes(buf, buf_size, trailer, sizeof trailer);
        if (r < 0)
                return r;

        return 0;
}

int initrd_cpio_credentials_to_tempfile(
                const MachineCredentialContext *creds,
                char **ret_path) {

        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *buf = NULL;
        size_t buf_size = 0;
        uint32_t inode = 1;
        int r;

        assert(creds);
        assert(ret_path);

        if (creds->n_credentials == 0) {
                *ret_path = NULL;
                return 0;
        }

        r = append_cpio_entry(&buf, &buf_size, S_IFDIR | 0555, ".extra",             NULL, 0, &inode);
        if (r < 0)
                return log_error_errno(r, "Failed to write '.extra' directory entry to credentials cpio: %m");
        r = append_cpio_entry(&buf, &buf_size, S_IFDIR | 0500, ".extra/system_credentials", NULL, 0, &inode);
        if (r < 0)
                return log_error_errno(r, "Failed to write '.extra/system_credentials' directory entry to credentials cpio: %m");

        FOREACH_ARRAY(c, creds->credentials, creds->n_credentials) {
                _cleanup_free_ char *cpath = strjoin(".extra/system_credentials/", c->id, ".cred");
                if (!cpath)
                        return log_oom();

                r = append_cpio_entry(&buf, &buf_size, S_IFREG | 0400, cpath, c->data, c->size, &inode);
                if (r < 0)
                        return log_error_errno(r, "Failed to write credential '%s' to credentials cpio: %m", c->id);
        }

        r = append_cpio_trailer(&buf, &buf_size);
        if (r < 0)
                return log_error_errno(r, "Failed to write trailer to credentials cpio: %m");

        r = tempfn_random_child(NULL, "credentials-cpio", &path);
        if (r < 0)
                return log_error_errno(r, "Failed to generate temp file name: %m");

        fd = open(path, O_WRONLY|O_CREAT|O_EXCL|O_CLOEXEC, 0600);
        if (fd < 0)
                return log_error_errno(errno, "Failed to create temp file %s: %m", path);

        r = loop_write(fd, buf, buf_size);
        if (r < 0)
                return log_error_errno(r, "Failed to write credentials cpio: %m");

        *ret_path = TAKE_PTR(path);
        return 0;
}
