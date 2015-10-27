/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2015 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <zlib.h>

#include "alloc-util.h"
#include "btrfs-util.h"
#include "qcow2-util.h"
#include "sparse-endian.h"
#include "util.h"

#define QCOW2_MAGIC 0x514649fb

#define QCOW2_COPIED (1ULL << 63)
#define QCOW2_COMPRESSED (1ULL << 62)
#define QCOW2_ZERO (1ULL << 0)

typedef struct _packed_ Header {
      be32_t magic;
      be32_t version;

      be64_t backing_file_offset;
      be32_t backing_file_size;

      be32_t cluster_bits;
      be64_t size;
      be32_t crypt_method;

      be32_t l1_size;
      be64_t l1_table_offset;

      be64_t refcount_table_offset;
      be32_t refcount_table_clusters;

      be32_t nb_snapshots;
      be64_t snapshots_offset;

      /* The remainder is only present on QCOW3 */
      be64_t incompatible_features;
      be64_t compatible_features;
      be64_t autoclear_features;

      be32_t refcount_order;
      be32_t header_length;
} Header;

#define HEADER_MAGIC(header) be32toh((header)->magic)
#define HEADER_VERSION(header) be32toh((header)->version)
#define HEADER_CLUSTER_BITS(header) be32toh((header)->cluster_bits)
#define HEADER_CLUSTER_SIZE(header) (1ULL << HEADER_CLUSTER_BITS(header))
#define HEADER_L2_BITS(header) (HEADER_CLUSTER_BITS(header) - 3)
#define HEADER_SIZE(header) be64toh((header)->size)
#define HEADER_CRYPT_METHOD(header) be32toh((header)->crypt_method)
#define HEADER_L1_SIZE(header) be32toh((header)->l1_size)
#define HEADER_L2_SIZE(header) (HEADER_CLUSTER_SIZE(header)/sizeof(uint64_t))
#define HEADER_L1_TABLE_OFFSET(header) be64toh((header)->l1_table_offset)

static uint32_t HEADER_HEADER_LENGTH(const Header *h) {
        if (HEADER_VERSION(h) < 3)
                return offsetof(Header, incompatible_features);

        return be32toh(h->header_length);
}

static int copy_cluster(
                int sfd, uint64_t soffset,
                int dfd, uint64_t doffset,
                uint64_t cluster_size,
                void *buffer) {

        ssize_t l;
        int r;

        r = btrfs_clone_range(sfd, soffset, dfd, doffset, cluster_size);
        if (r >= 0)
                return r;

        l = pread(sfd, buffer, cluster_size, soffset);
        if (l < 0)
                return -errno;
        if ((uint64_t) l != cluster_size)
                return -EIO;

        l = pwrite(dfd, buffer, cluster_size, doffset);
        if (l < 0)
                return -errno;
        if ((uint64_t) l != cluster_size)
                return -EIO;

        return 0;
}

static int decompress_cluster(
                int sfd, uint64_t soffset,
                int dfd, uint64_t doffset,
                uint64_t compressed_size,
                uint64_t cluster_size,
                void *buffer1,
                void *buffer2) {

        _cleanup_free_ void *large_buffer = NULL;
        z_stream s = {};
        uint64_t sz;
        ssize_t l;
        int r;

        if (compressed_size > cluster_size) {
                /* The usual cluster buffer doesn't suffice, let's
                 * allocate a larger one, temporarily */

                large_buffer = malloc(compressed_size);
                if (!large_buffer)
                        return -ENOMEM;

                buffer1 = large_buffer;
        }

        l = pread(sfd, buffer1, compressed_size, soffset);
        if (l < 0)
                return -errno;
        if ((uint64_t) l != compressed_size)
                return -EIO;

        s.next_in = buffer1;
        s.avail_in = compressed_size;
        s.next_out = buffer2;
        s.avail_out = cluster_size;

        r = inflateInit2(&s, -12);
        if (r != Z_OK)
                return -EIO;

        r = inflate(&s, Z_FINISH);
        sz = (uint8_t*) s.next_out - (uint8_t*) buffer2;
        inflateEnd(&s);
        if (r != Z_STREAM_END || sz != cluster_size)
                return -EIO;

        l = pwrite(dfd, buffer2, cluster_size, doffset);
        if (l < 0)
                return -errno;
        if ((uint64_t) l != cluster_size)
                return -EIO;

        return 0;
}

static int normalize_offset(
                const Header *header,
                uint64_t p,
                uint64_t *ret,
                bool *compressed,
                uint64_t *compressed_size) {

        uint64_t q;

        q = be64toh(p);

        if (q & QCOW2_COMPRESSED) {
                uint64_t sz, csize_shift, csize_mask;

                if (!compressed)
                        return -EOPNOTSUPP;

                csize_shift = 64 - 2 - (HEADER_CLUSTER_BITS(header) - 8);
                csize_mask = (1ULL << (HEADER_CLUSTER_BITS(header) - 8)) - 1;
                sz = (((q >> csize_shift) & csize_mask) + 1) * 512 - (q & 511);
                q &= ((1ULL << csize_shift) - 1);

                if (compressed_size)
                        *compressed_size = sz;

                *compressed = true;

        } else {
                if (compressed)  {
                        *compressed = false;
                        *compressed_size = 0;
                }

                if (q & QCOW2_ZERO) {
                        /* We make no distinction between zero blocks and holes */
                        *ret = 0;
                        return 0;
                }

                q &= ~QCOW2_COPIED;
        }

        *ret = q;
        return q > 0;  /* returns positive if not a hole */
}

static int verify_header(const Header *header) {
        assert(header);

        if (HEADER_MAGIC(header) != QCOW2_MAGIC)
                return -EBADMSG;

        if (HEADER_VERSION(header) != 2 &&
            HEADER_VERSION(header) != 3)
                return -EOPNOTSUPP;

        if (HEADER_CRYPT_METHOD(header) != 0)
                return -EOPNOTSUPP;

        if (HEADER_CLUSTER_BITS(header) < 9) /* 512K */
                return -EBADMSG;

        if (HEADER_CLUSTER_BITS(header) > 21) /* 2MB */
                return -EBADMSG;

        if (HEADER_SIZE(header) % HEADER_CLUSTER_SIZE(header) != 0)
                return -EBADMSG;

        if (HEADER_L1_SIZE(header) > 32*1024*1024) /* 32MB */
                return -EBADMSG;

        if (HEADER_VERSION(header) == 3) {

                if (header->incompatible_features != 0)
                        return -EOPNOTSUPP;

                if (HEADER_HEADER_LENGTH(header) < sizeof(Header))
                        return -EBADMSG;
        }

        return 0;
}

int qcow2_convert(int qcow2_fd, int raw_fd) {
        _cleanup_free_ void *buffer1 = NULL, *buffer2 = NULL;
        _cleanup_free_ be64_t *l1_table = NULL, *l2_table = NULL;
        uint64_t sz, i;
        Header header;
        ssize_t l;
        int r;

        l = pread(qcow2_fd, &header, sizeof(header), 0);
        if (l < 0)
                return -errno;
        if (l != sizeof(header))
                return -EIO;

        r = verify_header(&header);
        if (r < 0)
                return r;

        l1_table = new(be64_t, HEADER_L1_SIZE(&header));
        if (!l1_table)
                return -ENOMEM;

        l2_table = malloc(HEADER_CLUSTER_SIZE(&header));
        if (!l2_table)
                return -ENOMEM;

        buffer1 = malloc(HEADER_CLUSTER_SIZE(&header));
        if (!buffer1)
                return -ENOMEM;

        buffer2 = malloc(HEADER_CLUSTER_SIZE(&header));
        if (!buffer2)
                return -ENOMEM;

        /* Empty the file if it exists, we rely on zero bits */
        if (ftruncate(raw_fd, 0) < 0)
                return -errno;

        if (ftruncate(raw_fd, HEADER_SIZE(&header)) < 0)
                return -errno;

        sz = sizeof(uint64_t) * HEADER_L1_SIZE(&header);
        l = pread(qcow2_fd, l1_table, sz, HEADER_L1_TABLE_OFFSET(&header));
        if (l < 0)
                return -errno;
        if ((uint64_t) l != sz)
                return -EIO;

        for (i = 0; i < HEADER_L1_SIZE(&header); i ++) {
                uint64_t l2_begin, j;

                r = normalize_offset(&header, l1_table[i], &l2_begin, NULL, NULL);
                if (r < 0)
                        return r;
                if (r == 0)
                        continue;

                l = pread(qcow2_fd, l2_table, HEADER_CLUSTER_SIZE(&header), l2_begin);
                if (l < 0)
                        return -errno;
                if ((uint64_t) l != HEADER_CLUSTER_SIZE(&header))
                        return -EIO;

                for (j = 0; j < HEADER_L2_SIZE(&header); j++) {
                        uint64_t data_begin, p, compressed_size;
                        bool compressed;

                        p = ((i << HEADER_L2_BITS(&header)) + j) << HEADER_CLUSTER_BITS(&header);

                        r = normalize_offset(&header, l2_table[j], &data_begin, &compressed, &compressed_size);
                        if (r < 0)
                                return r;
                        if (r == 0)
                                continue;

                        if (compressed)
                                r = decompress_cluster(
                                                qcow2_fd, data_begin,
                                                raw_fd, p,
                                                compressed_size, HEADER_CLUSTER_SIZE(&header),
                                                buffer1, buffer2);
                        else
                                r = copy_cluster(
                                                qcow2_fd, data_begin,
                                                raw_fd, p,
                                                HEADER_CLUSTER_SIZE(&header), buffer1);
                        if (r < 0)
                                return r;
                }
        }

        return 0;
}

int qcow2_detect(int fd) {
        be32_t id;
        ssize_t l;

        l = pread(fd, &id, sizeof(id), 0);
        if (l < 0)
                return -errno;
        if (l != sizeof(id))
                return -EIO;

        return htobe32(QCOW2_MAGIC) == id;
}
