/*
 * sys/vfs.h
 */

#ifndef _SYS_VFS_H
#define _SYS_VFS_H

#include <stdint.h>
#include <klibc/extern.h>
#include <sys/types.h>
#include <bitsize.h>

/* struct statfs64 -- there seems to be two standards -
   one for 32 and one for 64 bits, and they're incompatible... */

#if _BITSIZE == 32 || defined(__s390__)

struct statfs {
        uint32_t f_type;
        uint32_t f_bsize;
        uint64_t f_blocks;
        uint64_t f_bfree;
        uint64_t f_bavail;
        uint64_t f_files;
        uint64_t f_ffree;
        __kernel_fsid_t f_fsid;
        uint32_t f_namelen;
        uint32_t f_frsize;
        uint32_t f_spare[5];
};

#else /* _BITSIZE == 64 */

struct statfs {
        uint64_t f_type;
        uint64_t f_bsize;
        uint64_t f_blocks;
        uint64_t f_bfree;
        uint64_t f_bavail;
        uint64_t f_files;
        uint64_t f_ffree;
        __kernel_fsid_t f_fsid;
        uint64_t f_namelen;
        uint64_t f_frsize;
        uint64_t f_spare[5];
};

#endif /* _BITSIZE */

__extern int statfs(const char *, struct statfs *);
__extern int fstatfs(int, struct statfs *);

/* Various filesystem types */
#define ADFS_SUPER_MAGIC	0xadf5
#define AFFS_SUPER_MAGIC	0xadff
#define AFS_FS_MAGIC		0x6B414653 /* 'kAFS' */
#define AUTOFS_SUPER_MAGIC	0x0187
#define BFS_MAGIC		0x1BADFACE
#define CAPIFS_SUPER_MAGIC	0x434e
#define CIFS_MAGIC_NUMBER	0xFF534D42
#define CODA_SUPER_MAGIC	0x73757245
#define CRAMFS_MAGIC		0x28cd3d45
#define DEVFS_SUPER_MAGIC	0x1373
#define DEVPTS_SUPER_MAGIC	0x1cd1
#define EFS_SUPER_MAGIC		0x414A53
#define EVENTPOLLFS_MAGIC	0x03111965
#define EXT2_SUPER_MAGIC	0xEF53
#define EXT3_SUPER_MAGIC	0xEF53
#define GADGETFS_MAGIC		0xaee71ee7
#define HFSPLUS_SUPER_MAGIC	0x482b
#define HFS_MFS_SUPER_MAGIC	0xD2D7	   /* MFS MDB (super block) */
#define HFS_SUPER_MAGIC		0x4244	   /* "BD": HFS MDB (super block) */
#define HPFS_SUPER_MAGIC 0xf995e849
#define HUGETLBFS_MAGIC		0x958458f6
#define HWGFS_MAGIC		0x12061983
#define IBMASMFS_MAGIC		0x66726f67
#define ISOFS_SUPER_MAGIC	0x9660
#define JFFS2_SUPER_MAGIC	0x72b6
#define JFFS_MAGIC_BITMASK	0x34383931 /* "1984" */
#define JFFS_MAGIC_SB_BITMASK	0x07c0	   /* 1984 */
#define JFS_SUPER_MAGIC		0x3153464a /* "JFS1" */
#define MINIX2_SUPER_MAGIC	0x2468	   /* minix V2 fs */
#define MINIX2_SUPER_MAGIC2	0x2478	   /* minix V2 fs, 30 char names */
#define MINIX_SUPER_MAGIC	0x137F	   /* original minix fs */
#define MINIX_SUPER_MAGIC2	0x138F	   /* minix fs, 30 char names */
#define MSDOS_SUPER_MAGIC	0x4d44	   /* MD */
#define NCP_SUPER_MAGIC		0x564c
#define NFS_SUPER_MAGIC		0x6969
#define NFS_SUPER_MAGIC		0x6969
#define OPENPROM_SUPER_MAGIC	0x9fa1
#define OPROFILEFS_MAGIC	0x6f70726f
#define PFMFS_MAGIC		0xa0b4d889
#define PIPEFS_MAGIC		0x50495045
#define PROC_SUPER_MAGIC	0x9fa0
#define QNX4_SUPER_MAGIC	0x002f	   /* qnx4 fs detection */
#define RAMFS_MAGIC		0x858458f6
#define REISERFS_SUPER_MAGIC	0x52654973
#define ROMFS_MAGIC		0x7275
#define SMB_SUPER_MAGIC		0x517B
#define SOCKFS_MAGIC		0x534F434B
#define SYSFS_MAGIC		0x62656572
#define TMPFS_MAGIC		0x01021994
#define UDF_SUPER_MAGIC		0x15013346
#define UFS_MAGIC		0x00011954
#define UFS_MAGIC_4GB		0x05231994 /* fs > 4 GB && fs_featurebits */
#define UFS_MAGIC_FEA		0x00195612 /* fs_featurebits supported */
#define UFS_MAGIC_LFN		0x00095014 /* fs supports filenames > 14 chars */
#define UFS_MAGIC_SEC		0x00612195 /* B1 security fs */
#define USBDEVICE_SUPER_MAGIC	0x9fa2
#define VXFS_SUPER_MAGIC	0xa501FCF5

#endif /* _SYS_VFS_H */
