/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include <linux/fs.h>
#include <linux/loop.h>

#ifndef LOOP_CONFIGURE
struct loop_config {
        __u32 fd;
        __u32 block_size;
        struct loop_info64 info;
        __u64 __reserved[8];
};

#define LOOP_CONFIGURE 0x4C0A
#endif

#ifndef BLKGETDISKSEQ
#define BLKGETDISKSEQ _IOR(0x12,128,__u64)
#endif
