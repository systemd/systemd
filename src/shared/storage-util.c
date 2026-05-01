/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-varlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "json-util.h"
#include "machine-util.h"
#include "path-lookup.h"
#include "path-util.h"
#include "runtime-scope.h"
#include "string-table.h"
#include "storage-util.h"
#include "user-util.h"

static const char *volume_type_table[_VOLUME_TYPE_MAX] = {
        [VOLUME_BLK] = "blk",
        [VOLUME_REG] = "reg",
        [VOLUME_DIR] = "dir",
};

static const char *create_mode_table[_CREATE_MODE_MAX] = {
        [CREATE_ANY]  = "any",
        [CREATE_NEW]  = "new",
        [CREATE_OPEN] = "open",
};

DEFINE_STRING_TABLE_LOOKUP(volume_type, VolumeType);
DEFINE_STRING_TABLE_LOOKUP(create_mode, CreateMode);

JSON_DISPATCH_ENUM_DEFINE(json_dispatch_volume_type, VolumeType, volume_type_from_string);
JSON_DISPATCH_ENUM_DEFINE(json_dispatch_create_mode, CreateMode, create_mode_from_string);

void storage_acquire_reply_done(StorageAcquireReply *reply) {
        if (!reply)
                return;

        reply->fd = safe_close(reply->fd);
        reply->error_id = mfree(reply->error_id);
}

int storage_acquire_volume(
                RuntimeScope scope,
                const BindVolume *bv,
                bool allow_interactive_auth,
                StorageAcquireReply *ret) {

        int r;

        assert(bv);
        assert(bv->provider);
        assert(bv->volume);
        assert(ret);

        /* Defense-in-depth: this is a libshared helper that may grow new callers; reject
         * provider names that could escape the StorageProvider runtime directory. */
        if (!storage_provider_name_is_valid(bv->provider))
                return -EINVAL;

        _cleanup_free_ char *socket_path = NULL;
        r = runtime_directory_generic(scope, "systemd/io.systemd.StorageProvider", &socket_path);
        if (r < 0)
                return r;

        if (!path_extend(&socket_path, bv->provider))
                return -ENOMEM;

        _cleanup_(sd_varlink_unrefp) sd_varlink *link = NULL;
        r = sd_varlink_connect_address(&link, socket_path);
        if (r < 0)
                return r;

        r = sd_varlink_set_allow_fd_passing_input(link, true);
        if (r < 0)
                return r;

        sd_json_variant *mreply = NULL;
        const char *merror_id = NULL;
        r = sd_varlink_callbo(
                        link,
                        "io.systemd.StorageProvider.Acquire",
                        &mreply,
                        &merror_id,
                        SD_JSON_BUILD_PAIR_STRING("name", bv->volume),
                        JSON_BUILD_PAIR_CONDITION_STRING(bv->create_mode >= 0, "createMode", create_mode_to_string(bv->create_mode)),
                        JSON_BUILD_PAIR_STRING_NON_EMPTY("template", bv->template),
                        JSON_BUILD_PAIR_TRISTATE_NON_NULL("readOnly", bv->read_only),
                        JSON_BUILD_PAIR_CONDITION_STRING(bv->request_as >= 0, "requestAs", volume_type_to_string(bv->request_as)),
                        JSON_BUILD_PAIR_UNSIGNED_NOT_EQUAL("createSizeBytes", bv->create_size_bytes, UINT64_MAX),
                        SD_JSON_BUILD_PAIR_BOOLEAN("allowInteractiveAuthentication", allow_interactive_auth));
        if (r < 0)
                return r;

        if (merror_id) {
                /* error_id points into mreply, which dies with 'link'. */
                char *copy = strdup(merror_id);
                if (!copy)
                        return -ENOMEM;
                ret->error_id = copy;

                r = sd_varlink_error_to_errno(merror_id, mreply);
                return r == -EBADR ? -EPROTO : r;
        }

        /* tmp.fd holds the JSON fd index until sd_varlink_take_fd() swaps it for the real fd. */
        StorageAcquireReply tmp = STORAGE_ACQUIRE_REPLY_INIT;

        static const sd_json_dispatch_field dispatch_table[] = {
                { "fileDescriptorIndex", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_int,         voffsetof(StorageAcquireReply, fd),        SD_JSON_MANDATORY },
                { "readOnly",            SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,    voffsetof(StorageAcquireReply, read_only), 0                 },
                { "type",                SD_JSON_VARIANT_STRING,        json_dispatch_volume_type,    voffsetof(StorageAcquireReply, type),      SD_JSON_MANDATORY },
                { "baseUID",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,     voffsetof(StorageAcquireReply, base_uid),  0                 },
                { "baseGID",             _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uid_gid,     voffsetof(StorageAcquireReply, base_gid),  0                 },
                {}
        };

        r = sd_json_dispatch(mreply, dispatch_table, SD_JSON_ALLOW_EXTENSIONS, &tmp);
        if (r < 0)
                return r;
        if (tmp.fd < 0)
                return -EBADMSG;

        _cleanup_close_ int fd = sd_varlink_take_fd(link, tmp.fd);
        if (fd < 0)
                return fd;

        tmp.fd = TAKE_FD(fd);
        *ret = tmp;
        return 0;
}
