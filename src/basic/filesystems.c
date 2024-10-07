/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "filesystems-gperf.h"
#include "stat-util.h"

const char* fs_type_to_string(statfs_f_type_t magic) {

        switch (magic) {
#include "filesystem-switch-case.h"
        }

        return NULL;
}

int fs_type_from_string(const char *name, const statfs_f_type_t **ret) {
        const struct FilesystemMagic *fs_magic;

        assert(name);
        assert(ret);

        fs_magic = filesystems_gperf_lookup(name, strlen(name));
        if (!fs_magic)
                return -EINVAL;

        *ret = fs_magic->magic;
        return 0;
}

bool fs_in_group(const struct statfs *s, FilesystemGroups fs_group) {
        int r;

        NULSTR_FOREACH(fs, filesystem_sets[fs_group].value) {
                const statfs_f_type_t *magic;

                r = fs_type_from_string(fs, &magic);
                if (r >= 0)
                        for (size_t i = 0; i < FILESYSTEM_MAGIC_MAX; i++) {
                                if (magic[i] == 0)
                                        break;

                                if (is_fs_type(s, magic[i]))
                                        return true;
                        }
        }

        return false;
}

const FilesystemSet filesystem_sets[_FILESYSTEM_SET_MAX] = {
        [FILESYSTEM_SET_BASIC_API] = {
                .name = "@basic-api",
                .help = "Basic filesystem API",
                .value =
                "cgroup\0"
                "cgroup2\0"
                "devpts\0"
                "devtmpfs\0"
                "mqueue\0"
                "proc\0"
                "sysfs\0"
        },
        [FILESYSTEM_SET_ANONYMOUS] = {
                .name = "@anonymous",
                .help = "Anonymous inodes",
                .value =
                "anon_inodefs\0"
                "pipefs\0"
                "sockfs\0"
        },
        [FILESYSTEM_SET_APPLICATION] = {
                .name = "@application",
                .help = "Application virtual filesystems",
                .value =
                "autofs\0"
                "fuse\0"
                "overlay\0"
        },
        [FILESYSTEM_SET_AUXILIARY_API] = {
                .name = "@auxiliary-api",
                .help = "Auxiliary filesystem API",
                .value =
                "binfmt_misc\0"
                "configfs\0"
                "efivarfs\0"
                "fusectl\0"
                "hugetlbfs\0"
                "rpc_pipefs\0"
                "securityfs\0"
        },
        [FILESYSTEM_SET_COMMON_BLOCK] = {
                .name = "@common-block",
                .help = "Common block device filesystems",
                .value =
                "btrfs\0"
                "erofs\0"
                "exfat\0"
                "ext4\0"
                "f2fs\0"
                "iso9660\0"
                "ntfs3\0"
                "squashfs\0"
                "udf\0"
                "vfat\0"
                "xfs\0"
        },
        [FILESYSTEM_SET_HISTORICAL_BLOCK] = {
                .name = "@historical-block",
                .help = "Historical block device filesystems",
                .value =
                "ext2\0"
                "ext3\0"
                "minix\0"
        },
        [FILESYSTEM_SET_NETWORK] = {
                .name = "@network",
                .help = "Well-known network filesystems",
                .value =
                "afs\0"
                "ceph\0"
                "cifs\0"
                "gfs\0"
                "gfs2\0"
                "ncp\0"
                "ncpfs\0"
                "nfs\0"
                "nfs4\0"
                "ocfs2\0"
                "orangefs\0"
                "pvfs2\0"
                "smb3\0"
                "smbfs\0"
        },
        [FILESYSTEM_SET_PRIVILEGED_API] = {
                .name = "@privileged-api",
                .help = "Privileged filesystem API",
                .value =
                "bpf\0"
                "debugfs\0"
                "pstore\0"
                "tracefs\0"
        },
        [FILESYSTEM_SET_SECURITY] = {
                .name = "@security",
                .help = "Security/MAC API VFS",
                .value =
                "apparmorfs\0"
                "selinuxfs\0"
                "smackfs\0"
        },
        [FILESYSTEM_SET_TEMPORARY] = {
                .name = "@temporary",
                .help = "Temporary filesystems",
                .value =
                "ramfs\0"
                "tmpfs\0"
        },
        [FILESYSTEM_SET_KNOWN] = {
                .name = "@known",
                .help = "All known filesystems declared in the kernel",
                .value =
#include "filesystem-list.h"
        },
};

const FilesystemSet *filesystem_set_find(const char *name) {
        if (isempty(name) || name[0] != '@')
                return NULL;

        for (FilesystemGroups i = 0; i < _FILESYSTEM_SET_MAX; i++)
                if (streq(filesystem_sets[i].name, name))
                        return filesystem_sets + i;

        return NULL;
}
