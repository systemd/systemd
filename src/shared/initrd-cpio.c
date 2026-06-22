/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <stdio.h>
#include <sys/stat.h>

#include "initrd-cpio.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "io-util.h"
#include "log.h"
#include "machine-credential.h"
#include "memory-util.h"
#include "memstream-util.h"
#include "string-util.h"
#include "tmpfile-util.h"

static void write_cpio_word(FILE *f, uint32_t v) {
        assert(f);

        /* Writes a CPIO header 8 character hex value */

        fprintf(f, "%08" PRIx32, v);
}

static int append_pad4(FILE *f) {
        off_t p;

        assert(f);

        /* Appends NUL bytes until the stream position is a multiple of 4 */

        p = ftello(f);
        if (p < 0)
                return -errno;

        for (size_t pad = (4 - ((size_t) p & 3)) & 3; pad > 0; pad--)
                fputc(0, f);

        return 0;
}

static int append_cpio_entry(
                FILE *f,
                uint32_t mode,                  /* full mode incl. S_IFDIR or S_IFREG */
                const char *path,
                const void *data,               /* NULL for directories */
                size_t data_size,               /* 0 for directories */
                uint32_t *inode_counter) {

        int r;

        assert(f);
        assert(path);
        assert(data || data_size == 0);
        assert(inode_counter);

        if (data_size > UINT32_MAX) /* cpio cannot deal with > 32-bit file sizes */
                return -EFBIG;

        if (*inode_counter == UINT32_MAX) /* more than 2^32-1 inodes? cpio cannot represent that either */
                return -EOVERFLOW;

        size_t namesize = strlen(path) + 1;
        if (namesize > UINT32_MAX) /* cpio also cannot deal with names > 32-bit */
                return -ENAMETOOLONG;

        fputs("070701", f);             /* magic ID */
        write_cpio_word(f, (*inode_counter)++); /* inode */
        write_cpio_word(f, mode);               /* mode */
        write_cpio_word(f, 0);                  /* uid */
        write_cpio_word(f, 0);                  /* gid */
        write_cpio_word(f, 1);                  /* nlink */
        write_cpio_word(f, 0);                  /* mtime */
        write_cpio_word(f, data_size);          /* size */
        write_cpio_word(f, 0);                  /* major(dev) */
        write_cpio_word(f, 0);                  /* minor(dev) */
        write_cpio_word(f, 0);                  /* major(rdev) */
        write_cpio_word(f, 0);                  /* minor(rdev) */
        write_cpio_word(f, namesize);           /* fname size */
        write_cpio_word(f, 0);                  /* crc */

        fwrite(path, 1, namesize, f);

        r = append_pad4(f);
        if (r < 0)
                return r;

        if (data_size > 0)
                fwrite(data, 1, data_size, f);

        return append_pad4(f);
}

static void append_cpio_trailer(FILE *f) {
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
        assert(f);

        fwrite(trailer, 1, sizeof trailer, f);
}

int initrd_cpio_credentials_to_tempfile(
                const MachineCredentialContext *creds,
                char **ret_path) {

        _cleanup_(memstream_done) MemStream m = {};
        _cleanup_(unlink_and_freep) char *path = NULL;
        _cleanup_close_ int fd = -EBADF;
        _cleanup_(erase_and_freep) char *buf = NULL; /* holds plaintext credential bytes; scrub on free */
        size_t buf_size = 0;
        uint32_t inode = 1;
        FILE *f;
        int r;

        assert(creds);
        assert(ret_path);

        if (creds->n_credentials == 0) {
                *ret_path = NULL;
                return 0;
        }

        f = memstream_init(&m);
        if (!f)
                return log_oom();

        r = append_cpio_entry(f, S_IFDIR | 0555, ".extra", NULL, 0, &inode);
        if (r < 0)
                return log_error_errno(r, "Failed to write '.extra' directory entry to credentials cpio: %m");
        r = append_cpio_entry(f, S_IFDIR | 0500, ".extra/system_credentials", NULL, 0, &inode);
        if (r < 0)
                return log_error_errno(r, "Failed to write '.extra/system_credentials' directory entry to credentials cpio: %m");

        FOREACH_ARRAY(c, creds->credentials, creds->n_credentials) {
                _cleanup_free_ char *cpath = strjoin(".extra/system_credentials/", c->id, ".cred");
                if (!cpath)
                        return log_oom();

                r = append_cpio_entry(f, S_IFREG | 0400, cpath, c->data, c->size, &inode);
                if (r < 0)
                        return log_error_errno(r, "Failed to write credential '%s' to credentials cpio: %m", c->id);
        }

        append_cpio_trailer(f);

        r = memstream_finalize(&m, &buf, &buf_size);
        if (r < 0)
                return log_error_errno(r, "Failed to finalize credentials cpio: %m");

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
