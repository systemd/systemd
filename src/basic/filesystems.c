/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "filesystems-gperf.h"
#include "nulstr-util.h"
#include "stat-util.h"
#include "string-util.h"

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

const FilesystemSet* filesystem_set_find(const char *name) {
        if (isempty(name) || name[0] != '@')
                return NULL;

        for (FilesystemGroups i = 0; i < _FILESYSTEM_SET_MAX; i++)
                if (streq(filesystem_sets[i].name, name))
                        return filesystem_sets + i;

        return NULL;
}
