/* SPDX-License-Identifier: LGPL-2.1+ */
#pragma once

#include <linux/fs.h>
#include <sys/vfs.h>

#include "sd-id128.h"

#include "loop-util.h"
#include "user-record.h"
#include "user-record-util.h"

typedef struct HomeSetup {
        char *dm_name;
        char *dm_node;

        LoopDevice *loop;
        struct crypt_device *crypt_device;
        int root_fd;
        sd_id128_t found_partition_uuid;
        sd_id128_t found_luks_uuid;
        sd_id128_t found_fs_uuid;

        uint8_t fscrypt_key_descriptor[FS_KEY_DESCRIPTOR_SIZE];

        void *volume_key;
        size_t volume_key_size;

        bool undo_dm;
        bool undo_mount;

        uint64_t partition_offset;
        uint64_t partition_size;
} HomeSetup;

#define HOME_SETUP_INIT                                 \
        {                                               \
                .root_fd = -1,                          \
                .partition_offset = UINT64_MAX,         \
                .partition_size = UINT64_MAX,           \
        }

int home_setup_undo(HomeSetup *setup);

int home_prepare(UserRecord *h, bool already_activated, char ***pkcs11_decrypted_passwords, HomeSetup *setup, UserRecord **ret_header_home);

int home_refresh(UserRecord *h, HomeSetup *setup, UserRecord *header_home, char ***pkcs11_decrypted_passwords, struct statfs *ret_statfs, UserRecord **ret_new_home);

int home_populate(UserRecord *h, int dir_fd);

int home_load_embedded_identity(UserRecord *h, int root_fd, UserRecord *header_home, UserReconcileMode mode, char ***pkcs11_decrypted_passwords, UserRecord **ret_embedded_home, UserRecord **ret_new_home);
int home_store_embedded_identity(UserRecord *h, int root_fd, uid_t uid, UserRecord *old_home);
int home_extend_embedded_identity(UserRecord *h, UserRecord *used, HomeSetup *setup);

int user_record_authenticate(UserRecord *h, UserRecord *secret, char ***pkcs11_decrypted_passwords);

int home_sync_and_statfs(int root_fd, struct statfs *ret);
