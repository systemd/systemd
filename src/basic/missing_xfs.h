/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

/* This is currently not exported in the public kernel headers, but the libxfs library code part of xfsprogs
 * defines it as public header */

#ifndef XFS_IOC_FSGEOMETRY
#define XFS_IOC_FSGEOMETRY _IOR ('X', 124, struct xfs_fsop_geom)

typedef struct xfs_fsop_geom {
        uint32_t blocksize;
        uint32_t rtextsize;
        uint32_t agblocks;
        uint32_t agcount;
        uint32_t logblocks;
        uint32_t sectsize;
        uint32_t inodesize;
        uint32_t imaxpct;
        uint64_t datablocks;
        uint64_t rtblocks;
        uint64_t rtextents;
        uint64_t logstart;
        unsigned char uuid[16];
        uint32_t sunit;
        uint32_t swidth;
        int32_t version;
        uint32_t flags;
        uint32_t logsectsize;
        uint32_t rtsectsize;
        uint32_t dirblocksize;
        uint32_t logsunit;
} xfs_fsop_geom_t;
#endif

#ifndef XFS_IOC_FSGROWFSDATA
#define XFS_IOC_FSGROWFSDATA _IOW ('X', 110, struct xfs_growfs_data)

typedef struct xfs_growfs_data {
        uint64_t newblocks;
        uint32_t imaxpct;
} xfs_growfs_data_t;
#endif
