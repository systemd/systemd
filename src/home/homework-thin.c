/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <inttypes.h>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

#include "alloc-util.h"
#include "blkid-util.h"
#include "blockdev-util.h"
#include "dm-util.h"
#include "errno-util.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "gpt.h"
#include "home-util.h"
#include "homework-thin.h"
#include "json-util.h"
#include "log.h"
#include "parse-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"
#include "time-util.h"
#include "udev-util.h"
#include "user-record.h"
#include "user-record-util.h"

#define HOME_THIN_DEVICE_ID_MAX ((UINT32_C(1) << 24) - 1U)
#define DISK_SIZE_ROUND_DOWN(x) ((x) & ~(U64_MB - 1))

typedef struct ThinPoolInfo {
        DmDeviceInfo device;
        char *name, *path;
        HomeThinPoolStatus status;
} ThinPoolInfo;

static void thin_pool_info_done(ThinPoolInfo *info) {
        if (!info)
                return;

        free(info->name);
        free(info->path);
}

int home_thin_volume_make_path(UserRecord *h, const char *pool, char **ret_path, char **ret_name) {
        _cleanup_free_ char *name = NULL, *path = NULL;

        assert(h);
        assert(pool);
        assert(ret_path);
        assert(ret_name);

        if (!path_is_absolute(pool) || !path_is_normalized(pool))
                return -EINVAL;
        if (sd_id128_is_null(h->uuid))
                return -EINVAL;

        if (asprintf(&name, "homed-" SD_ID128_FORMAT_STR, SD_ID128_FORMAT_VAL(h->uuid)) < 0)
                return -ENOMEM;

        path = path_join("/dev/mapper", name);
        if (!path)
                return -ENOMEM;

        *ret_path = TAKE_PTR(path);
        *ret_name = TAKE_PTR(name);
        return 0;
}

static int thin_volume_partition_name_from_path(const char *path, char **ret) {
        _cleanup_free_ char *name = NULL, *volume = NULL;
        int r;

        assert(path);
        assert(ret);

        r = path_extract_filename(path, &volume);
        if (r < 0)
                return r;
        if (!startswith(volume, "homed-") || strlen(volume) != STRLEN("homed-") + 32)
                return -EINVAL;

        name = strjoin(volume, "-part1");
        if (!name)
                return -ENOMEM;

        *ret = TAKE_PTR(name);
        return 0;
}

static int thin_volume_unmap_partition(const char *volume_path) {
        _cleanup_free_ char *name = NULL;
        usec_t until;
        int r;

        assert(volume_path);

        r = thin_volume_partition_name_from_path(volume_path, &name);
        if (r < 0)
                return r;

        until = usec_add(now(CLOCK_MONOTONIC), 2 * USEC_PER_SEC);
        for (;;) {
                r = dm_remove_device(name);
                if (r != -EBUSY || now(CLOCK_MONOTONIC) >= until)
                        return r;

                (void) usleep_safe(50 * USEC_PER_MSEC);
        }
}

int home_thin_volume_map_partition(
                UserRecord *h,
                int volume_fd,
                uint64_t offset,
                uint64_t size,
                char **ret_path) {

        _cleanup_free_ char *name = NULL, *node = NULL, *uuid = NULL;
        uint64_t volume_size;
        struct stat st;
        int r;

        assert(h);
        assert(volume_fd >= 0);
        assert(ret_path);

        if (sd_id128_is_null(h->uuid))
                return -EINVAL;
        if (offset % 512U != 0 || size == 0 || size % 512U != 0)
                return -EINVAL;

        if (fstat(volume_fd, &st) < 0)
                return -errno;
        if (!S_ISBLK(st.st_mode))
                return -ENOTBLK;

        r = blockdev_get_device_size(volume_fd, &volume_size);
        if (r < 0)
                return r;
        if (offset > volume_size || size > volume_size - offset)
                return -ERANGE;

        if (asprintf(&name,
                     "homed-" SD_ID128_FORMAT_STR "-part1",
                     SD_ID128_FORMAT_VAL(h->uuid)) < 0)
                return -ENOMEM;

        uuid = strjoin("HOMED-PART1-", SD_ID128_TO_STRING(h->uuid));
        node = path_join("/dev/mapper", name);
        if (!uuid || !node)
                return -ENOMEM;

        r = dm_create_linear(name, uuid, st.st_rdev, offset, size);
        if (r < 0)
                return r;

        r = device_wait_for_devlink(node, "block", 45 * USEC_PER_SEC, /* ret= */ NULL);
        if (r < 0) {
                (void) dm_remove_device(name);
                return r;
        }

        *ret_path = TAKE_PTR(node);
        return 1;
}

static int thin_volume_find_partition(UserRecord *h, int fd, uint64_t *ret_offset, uint64_t *ret_size) {
#if HAVE_BLKID
        _cleanup_(blkid_free_probep) blkid_probe b = NULL;
        const char *pttype = NULL;
        blkid_partlist partitions;
        int n, r;

        assert(h);
        assert(fd >= 0);
        assert(ret_offset);
        assert(ret_size);

        if (sd_id128_is_null(h->partition_uuid))
                return -ENXIO;

        r = dlopen_libblkid(LOG_DEBUG);
        if (r < 0)
                return r;

        b = sym_blkid_new_probe();
        if (!b)
                return -ENOMEM;

        errno = 0;
        r = sym_blkid_probe_set_device(b, fd, /* off= */ 0, /* size= */ 0);
        if (r != 0)
                return errno_or_else(ENOMEM);

        (void) sym_blkid_probe_enable_partitions(b, 1);
        (void) sym_blkid_probe_set_partitions_flags(b, BLKID_PARTS_ENTRY_DETAILS);

        errno = 0;
        r = sym_blkid_do_safeprobe(b);
        if (r == _BLKID_SAFEPROBE_ERROR)
                return errno_or_else(EIO);
        if (IN_SET(r, _BLKID_SAFEPROBE_AMBIGUOUS, _BLKID_SAFEPROBE_NOT_FOUND))
                return -ENOPKG;

        assert(r == _BLKID_SAFEPROBE_FOUND);

        (void) sym_blkid_probe_lookup_value(b, "PTTYPE", &pttype, /* len= */ NULL);
        if (!streq_ptr(pttype, "gpt"))
                return -ENOPKG;

        errno = 0;
        partitions = sym_blkid_probe_get_partitions(b);
        if (!partitions)
                return errno_or_else(ENOMEM);

        errno = 0;
        n = sym_blkid_partlist_numof_partitions(partitions);
        if (n < 0)
                return errno_or_else(EIO);

        for (int i = 0; i < n; i++) {
                sd_id128_t uuid;
                blkid_loff_t offset, size;
                blkid_partition partition;

                errno = 0;
                partition = sym_blkid_partlist_get_partition(partitions, i);
                if (!partition)
                        return errno_or_else(EIO);

                if (sd_id128_string_equal(
                                    sym_blkid_partition_get_type_string(partition),
                                    SD_GPT_USER_HOME) <= 0)
                        continue;

                r = blkid_partition_get_uuid_id128(partition, &uuid);
                if (r < 0 || !sd_id128_equal(uuid, h->partition_uuid))
                        continue;

                offset = sym_blkid_partition_get_start(partition);
                size = sym_blkid_partition_get_size(partition);
                if (offset < 0 || (uint64_t) offset > UINT64_MAX / 512U)
                        return -EINVAL;
                if (size <= 0 || (uint64_t) size > UINT64_MAX / 512U)
                        return -EINVAL;

                *ret_offset = (uint64_t) offset * 512U;
                *ret_size = (uint64_t) size * 512U;
                return 1;
        }

        return -ENOPKG;
#else
        return -EOPNOTSUPP;
#endif
}

typedef enum ThinOperation {
        THIN_OPERATION_NONE,
        THIN_OPERATION_CREATE,
        THIN_OPERATION_DELETE,
        _THIN_OPERATION_MAX,
        _THIN_OPERATION_INVALID = -EINVAL,
} ThinOperation;

typedef struct ThinPoolState {
        char *pool_uuid;
        uint32_t next_device_id;
        uint64_t transaction_id;
        ThinOperation operation;
        sd_id128_t home_uuid;
        uint32_t device_id;
        uint64_t operation_transaction_id;
} ThinPoolState;

static void thin_pool_state_done(ThinPoolState *state) {
        if (!state)
                return;

        free(state->pool_uuid);
}

static const char* thin_operation_to_string(ThinOperation operation) {
        static const char * const table[_THIN_OPERATION_MAX] = {
                [THIN_OPERATION_NONE] = "none",
                [THIN_OPERATION_CREATE] = "create",
                [THIN_OPERATION_DELETE] = "delete",
        };

        if (operation < 0 || operation >= _THIN_OPERATION_MAX)
                return NULL;
        return table[operation];
}

static int thin_operation_from_string(const char *s) {
        assert(s);

        for (ThinOperation operation = 0; operation < _THIN_OPERATION_MAX; operation++)
                if (streq(s, thin_operation_to_string(operation)))
                        return operation;

        return -EINVAL;
}

static int parse_fraction(const char *s, uint64_t *ret_used, uint64_t *ret_total) {
        _cleanup_free_ char *used = NULL;
        const char *slash;
        uint64_t u, t;
        int r;

        assert(s);
        assert(ret_used);
        assert(ret_total);

        slash = strchr(s, '/');
        if (!slash || slash == s || isempty(slash + 1) || strchr(slash + 1, '/'))
                return -EINVAL;

        used = strndup(s, slash - s);
        if (!used)
                return -ENOMEM;

        r = safe_atou64(used, &u);
        if (r < 0)
                return r;
        r = safe_atou64(slash + 1, &t);
        if (r < 0)
                return r;
        if (t == 0 || u > t)
                return -ERANGE;

        *ret_used = u;
        *ret_total = t;
        return 0;
}

int home_thin_pool_parse_status(const char *status, HomeThinPoolStatus *ret) {
        _cleanup_strv_free_ char **fields = NULL;
        int r;

        assert(status);
        assert(ret);

        if (streq(status, "Fail"))
                return -EIO;

        fields = strv_split(status, WHITESPACE);
        if (!fields)
                return -ENOMEM;
        if (strv_length(fields) < 8)
                return -EBADMSG;

        r = safe_atou64(fields[0], &ret->transaction_id);
        if (r < 0)
                return r;
        r = parse_fraction(fields[1], &ret->used_metadata, &ret->total_metadata);
        if (r < 0)
                return r;
        r = parse_fraction(fields[2], &ret->used_data, &ret->total_data);
        if (r < 0)
                return r;

        if (!streq(fields[4], "rw"))
                return streq(fields[4], "ro") ? -EROFS : -ENOSPC;
        if (!streq(fields[5], "discard_passdown"))
                return -EOPNOTSUPP;
        if (!streq(fields[6], "error_if_no_space"))
                return -EOPNOTSUPP;
        if (!streq(fields[7], "-"))
                return streq(fields[7], "needs_check") ? -EUCLEAN : -EBADMSG;

        return 0;
}

int home_thin_pool_validate_table(const char *parameters) {
        _cleanup_free_ char *copy = NULL;
        const char *p;
        unsigned n_features;
        int r;

        assert(parameters);

        copy = strdup(parameters);
        if (!copy)
                return -ENOMEM;
        p = copy;

        for (unsigned i = 0; i < 4; i++) {
                _cleanup_free_ char *word = NULL;

                r = extract_first_word(&p, &word, NULL, 0);
                if (r <= 0)
                        return -EBADMSG;
        }

        _cleanup_free_ char *count = NULL;
        r = extract_first_word(&p, &count, NULL, 0);
        if (r == 0)
                return -EOPNOTSUPP; /* error_if_no_space is mandatory. */
        if (r < 0)
                return r;
        r = safe_atou(count, &n_features);
        if (r < 0)
                return r;

        bool error_if_no_space = false;
        for (unsigned i = 0; i < n_features; i++) {
                _cleanup_free_ char *feature = NULL;

                r = extract_first_word(&p, &feature, NULL, 0);
                if (r <= 0)
                        return -EBADMSG;

                if (streq(feature, "error_if_no_space"))
                        error_if_no_space = true;
                else if (STR_IN_SET(feature, "read_only", "ignore_discard", "no_discard_passdown"))
                        return -EOPNOTSUPP;
        }
        if (!error_if_no_space)
                return -EOPNOTSUPP;
        if (!isempty(p))
                return -EBADMSG;

        return 0;
}

static int thin_pool_query(const char *path, ThinPoolInfo *ret) {
        _cleanup_(dm_target_info_done) DmTargetInfo status = {}, table = {};
        _cleanup_(thin_pool_info_done) ThinPoolInfo info = {};
        int r;

        assert(path);
        assert(ret);

        if (!path_is_absolute(path) || !path_is_normalized(path))
                return -EINVAL;

        r = dm_device_info_from_path(path, &info.device);
        if (r < 0)
                return log_error_errno(r, "Failed to query configured thin pool %s: %m", path);
        if (isempty(info.device.uuid))
                return log_error_errno(SYNTHETIC_ERRNO(ENXIO),
                                       "Configured thin pool %s has no DM UUID, refusing.", path);
        if (startswith(info.device.uuid, "LVM-"))
                return log_error_errno(SYNTHETIC_ERRNO(EREMCHG),
                                       "Configured thin pool %s is owned by LVM, refusing.", path);
        if (FLAGS_SET(info.device.flags, DM_READONLY_FLAG))
                return log_error_errno(SYNTHETIC_ERRNO(EROFS),
                                       "Configured thin pool %s is read-only, refusing.", path);
        if (info.device.target_count != 1)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTUNIQ),
                                       "Configured thin pool %s does not contain exactly one target.", path);

        info.name = strdup(info.device.name);
        info.path = strdup(path);
        if (!info.name || !info.path)
                return -ENOMEM;

        r = dm_device_query_target(info.name, true, &table);
        if (r < 0)
                return r;
        if (!streq(table.type, "thin-pool") || table.start != 0)
                return log_error_errno(SYNTHETIC_ERRNO(ENOTTY),
                                       "Configured device %s is not a whole-device thin pool.", path);
        r = home_thin_pool_validate_table(table.parameters);
        if (r < 0)
                return log_error_errno(r, "Thin pool %s has unsupported table options: %m", path);

        r = dm_device_query_target(info.name, false, &status);
        if (r < 0)
                return r;
        if (!streq(status.type, "thin-pool") || status.start != 0 || status.length != table.length)
                return -EREMCHG;
        r = home_thin_pool_parse_status(status.parameters, &info.status);
        if (r < 0)
                return log_error_errno(r, "Thin pool %s is not healthy and writable: %m", path);

        if (info.status.used_metadata == info.status.total_metadata ||
            info.status.used_data == info.status.total_data)
                return log_error_errno(SYNTHETIC_ERRNO(ENOSPC), "Thin pool %s is exhausted.", path);
        if (info.status.used_metadata >= info.status.total_metadata - info.status.total_metadata / 5U)
                log_warning("Thin pool %s metadata usage is at least 80%%.", path);
        if (info.status.used_data >= info.status.total_data - info.status.total_data / 5U)
                log_warning("Thin pool %s data usage is at least 80%%.", path);

        *ret = TAKE_STRUCT(info);
        return 0;
}

int home_thin_pool_validate(const char *pool_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};

        assert(pool_path);

        return thin_pool_query(pool_path, &pool);
}

int home_thin_pool_default_size(const char *pool, uint64_t *ret_size, uint64_t *ret_backing_size) {
        _cleanup_(dm_target_info_done) DmTargetInfo table = {};
        _cleanup_(thin_pool_info_done) ThinPoolInfo info = {};
        uint64_t size;
        int r;

        assert(pool);
        assert(ret_size);

        r = thin_pool_query(pool, &info);
        if (r < 0)
                return r;
        r = dm_device_query_target(info.name, true, &table);
        if (r < 0)
                return r;
        if (table.length > UINT64_MAX / 512U)
                return -EOVERFLOW;

        size = DISK_SIZE_ROUND_DOWN(MIN(table.length * 512U, USER_DISK_SIZE_MAX));
        if (size < USER_DISK_SIZE_MIN)
                return -ENOSPC;

        *ret_size = size;
        if (ret_backing_size)
                *ret_backing_size = table.length * 512U;
        return 0;
}

static char* thin_pool_state_path(void) {
        return path_join(home_record_dir(), ".thin-pool-state");
}

static char* thin_pool_lock_path(void) {
        return path_join(home_record_dir(), ".thin-pool-state.lock");
}

static int thin_pool_state_load(ThinPoolState *ret) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *operation = NULL, *path = NULL, *text = NULL;
        ThinPoolState state = {
                .next_device_id = UINT32_MAX,
                .operation = _THIN_OPERATION_INVALID,
                .device_id = UINT32_MAX,
        };
        int r;

        static const sd_json_dispatch_field table[] = {
                { "poolUuid",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(ThinPoolState, pool_uuid),                SD_JSON_MANDATORY },
                { "nextDeviceId",           _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(ThinPoolState, next_device_id),            SD_JSON_MANDATORY },
                { "transactionId",          _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(ThinPoolState, transaction_id),             SD_JSON_MANDATORY },
                { "operation",              SD_JSON_VARIANT_STRING,        NULL,                    0,                                                   SD_JSON_MANDATORY },
                { "homeUuid",               SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,  offsetof(ThinPoolState, home_uuid),                 0 },
                { "deviceId",               _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint32, offsetof(ThinPoolState, device_id),                 0 },
                { "operationTransactionId", _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(ThinPoolState, operation_transaction_id), 0 },
                {},
        };

        assert(ret);

        path = thin_pool_state_path();
        if (!path)
                return -ENOMEM;

        r = read_full_file(path, &text, NULL);
        if (r < 0)
                return r;
        r = sd_json_parse(text, SD_JSON_PARSE_MUST_BE_OBJECT, &v, NULL, NULL);
        if (r < 0)
                return r;
        r = sd_json_dispatch(v, table, SD_JSON_LOG, &state);
        if (r < 0)
                return r;

        sd_json_variant *o = sd_json_variant_by_key(v, "operation");
        if (!o || !sd_json_variant_is_string(o))
                return -EBADMSG;
        operation = strdup(sd_json_variant_string(o));
        if (!operation)
                return -ENOMEM;
        state.operation = thin_operation_from_string(operation);
        if (state.operation < 0)
                return state.operation;
        if (state.next_device_id > HOME_THIN_DEVICE_ID_MAX + 1U)
                return -ERANGE;
        if (state.operation != THIN_OPERATION_NONE &&
            (sd_id128_is_null(state.home_uuid) || state.device_id > HOME_THIN_DEVICE_ID_MAX))
                return -EBADMSG;

        *ret = TAKE_STRUCT(state);
        return 0;
}

static int thin_pool_state_save(const ThinPoolState *state) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *path = NULL, *text = NULL;
        int r;

        assert(state);
        assert(state->pool_uuid);

        r = sd_json_buildo(
                        &v,
                        SD_JSON_BUILD_PAIR_STRING("poolUuid", state->pool_uuid),
                        SD_JSON_BUILD_PAIR_UNSIGNED("nextDeviceId", state->next_device_id),
                        SD_JSON_BUILD_PAIR_UNSIGNED("transactionId", state->transaction_id),
                        SD_JSON_BUILD_PAIR_STRING("operation", thin_operation_to_string(state->operation)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        state->operation != THIN_OPERATION_NONE,
                                        "homeUuid", SD_JSON_BUILD_ID128(state->home_uuid)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        state->operation != THIN_OPERATION_NONE,
                                        "deviceId", SD_JSON_BUILD_UNSIGNED(state->device_id)),
                        SD_JSON_BUILD_PAIR_CONDITION(
                                        state->operation != THIN_OPERATION_NONE,
                                        "operationTransactionId",
                                        SD_JSON_BUILD_UNSIGNED(state->operation_transaction_id)));
        if (r < 0)
                return r;
        r = sd_json_variant_format(v, SD_JSON_FORMAT_PRETTY|SD_JSON_FORMAT_NEWLINE, &text);
        if (r < 0)
                return r;

        path = thin_pool_state_path();
        if (!path)
                return -ENOMEM;

        return write_string_file(
                        path, text,
                        WRITE_STRING_FILE_CREATE|WRITE_STRING_FILE_ATOMIC|WRITE_STRING_FILE_SYNC|
                        WRITE_STRING_FILE_MODE_0600|WRITE_STRING_FILE_MKDIR_0755);
}

static int thin_pool_lock(int *ret_fd) {
        _cleanup_close_ int fd = -EBADF;
        _cleanup_free_ char *path = NULL;

        assert(ret_fd);

        path = thin_pool_lock_path();
        if (!path)
                return -ENOMEM;

        fd = open(path, O_RDWR|O_CREAT|O_CLOEXEC|O_NOFOLLOW, 0600);
        if (fd < 0)
                return -errno;
        if (flock(fd, LOCK_EX) < 0)
                return -errno;

        *ret_fd = TAKE_FD(fd);
        return 0;
}

static int thin_pool_state_acquire(
                const char *path,
                ThinPoolInfo *ret_pool,
                ThinPoolState *ret,
                int *ret_lock_fd) {

        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(path);
        assert(ret_pool);
        assert(ret);
        assert(ret_lock_fd);

        r = thin_pool_lock(&lock_fd);
        if (r < 0)
                return r;

        r = thin_pool_query(path, &pool);
        if (r < 0)
                return r;

        r = thin_pool_state_load(&state);
        if (r == -ENOENT) {
                /* Once homed has modified a pool it always advances the transaction ID. Thus a missing
                 * allocator file is safe to initialize only for an untouched pool; otherwise starting at
                 * device ID zero could collide with an existing home. */
                if (pool.status.transaction_id != 0)
                        return -ENODATA;

                state = (ThinPoolState) {
                        .pool_uuid = strdup(pool.device.uuid),
                        .next_device_id = 0,
                        .transaction_id = pool.status.transaction_id,
                        .operation = THIN_OPERATION_NONE,
                        .device_id = UINT32_MAX,
                };
                if (!state.pool_uuid)
                        return -ENOMEM;
                r = thin_pool_state_save(&state);
        }
        if (r < 0)
                return r;
        if (!streq(state.pool_uuid, pool.device.uuid))
                return -ESTALE;
        if (state.operation == THIN_OPERATION_NONE && state.transaction_id != pool.status.transaction_id)
                return -EREMCHG;
        if (state.operation != THIN_OPERATION_NONE &&
            pool.status.transaction_id != state.operation_transaction_id &&
            pool.status.transaction_id != state.operation_transaction_id + 1U)
                return -EREMCHG;

        *ret_pool = TAKE_STRUCT(pool);
        *ret = TAKE_STRUCT(state);
        *ret_lock_fd = TAKE_FD(lock_fd);
        return 0;
}

static int thin_pool_advance_transaction(const ThinPoolInfo *pool, uint64_t old_id) {
        _cleanup_free_ char *message = NULL;

        assert(pool);

        if (old_id == UINT64_MAX)
                return -EOVERFLOW;
        if (asprintf(&message, "set_transaction_id %" PRIu64 " %" PRIu64, old_id, old_id + 1U) < 0)
                return -ENOMEM;

        return dm_target_message(pool->name, 0, message);
}

static int thin_volume_validate_mapping(
                UserRecord *h,
                const ThinPoolInfo *pool,
                char **ret_path);

static int thin_volume_create_mapping(
                UserRecord *h,
                const ThinPoolInfo *pool,
                uint32_t device_id,
                uint64_t size,
                char **ret_path,
                char **ret_name) {

        _cleanup_free_ char *name = NULL, *parameters = NULL, *path = NULL, *uuid = NULL;
        int r;

        assert(h);
        assert(pool);
        assert(device_id <= HOME_THIN_DEVICE_ID_MAX);
        assert(size > 0 && size % 512U == 0);

        r = home_thin_volume_make_path(h, pool->path, &path, &name);
        if (r < 0)
                return r;
        if (asprintf(&parameters, "%u:%u %" PRIu32,
                     major(pool->device.devnum), minor(pool->device.devnum), device_id) < 0)
                return -ENOMEM;
        uuid = strjoin("HOMED-THIN-", SD_ID128_TO_STRING(h->uuid));
        if (!uuid)
                return -ENOMEM;

        r = dm_create_device(name, uuid, 0, size / 512U, "thin", parameters);
        if (r == -EEXIST) {
                r = thin_volume_validate_mapping(h, pool, NULL);
                if (r <= 0)
                        return r < 0 ? r : -EREMCHG;
        } else if (r < 0)
                return r;
        else
                r = device_wait_for_devlink(path, "block", 45 * USEC_PER_SEC, NULL);
        if (r < 0) {
                (void) dm_remove_device(name);
                return r;
        }

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        if (ret_name)
                *ret_name = TAKE_PTR(name);
        return 1;
}

static int thin_pool_send_device_message(const ThinPoolInfo *pool, const char *verb, uint32_t device_id) {
        _cleanup_free_ char *message = NULL;

        assert(pool);
        assert(verb);
        assert(device_id <= HOME_THIN_DEVICE_ID_MAX);

        if (asprintf(&message, "%s %" PRIu32, verb, device_id) < 0)
                return -ENOMEM;

        return dm_target_message(pool->name, 0, message);
}

static int thin_pool_confirm_transaction(const char *path, uint64_t expected) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        int r;

        assert(path);

        r = thin_pool_query(path, &pool);
        if (r < 0)
                return r;

        return pool.status.transaction_id == expected ? 0 : -EREMCHG;
}

int home_thin_pool_recover(const char *pool_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(pool_path);

        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        if (state.operation != THIN_OPERATION_DELETE)
                return 0;

        if (pool.status.transaction_id == state.operation_transaction_id) {
                r = thin_pool_send_device_message(&pool, "delete", state.device_id);
                if (r < 0 && r != -ENODATA)
                        return r;

                r = thin_pool_advance_transaction(&pool, pool.status.transaction_id);
                if (r < 0)
                        return r;
                r = thin_pool_confirm_transaction(pool_path, pool.status.transaction_id + 1U);
                if (r < 0)
                        return r;

                pool.status.transaction_id++;
        }

        assert(pool.status.transaction_id == state.operation_transaction_id + 1U);
        state.transaction_id = pool.status.transaction_id;
        state.operation = THIN_OPERATION_NONE;
        state.home_uuid = SD_ID128_NULL;
        state.device_id = UINT32_MAX;
        state.operation_transaction_id = 0;

        r = thin_pool_state_save(&state);
        if (r < 0)
                return r;

        log_notice("Recovered interrupted dm-thin deletion transaction.");
        return 1;
}

int home_thin_volume_allocate(
                UserRecord *h,
                const char *pool_path,
                char **ret_pool_uuid,
                uint32_t *ret_device_id) {

        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        uint32_t device_id;
        int r;

        assert(h);
        assert(pool_path);
        assert(ret_pool_uuid);
        assert(ret_device_id);

        if (sd_id128_is_null(h->uuid))
                return -EINVAL;

        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        if (state.operation != THIN_OPERATION_NONE)
                return -EBUSY;
        if (state.next_device_id > HOME_THIN_DEVICE_ID_MAX)
                return -ENOSPC;

        device_id = state.next_device_id++;
        state.operation = THIN_OPERATION_CREATE;
        state.home_uuid = h->uuid;
        state.device_id = device_id;
        state.operation_transaction_id = pool.status.transaction_id;

        r = thin_pool_state_save(&state);
        if (r < 0)
                return r;

        *ret_pool_uuid = strdup(pool.device.uuid);
        if (!*ret_pool_uuid)
                return -ENOMEM;
        *ret_device_id = device_id;
        return 1;
}

static int thin_volume_validate_binding(UserRecord *h, const ThinPoolInfo *pool) {
        assert(h);
        assert(pool);

        if (!h->thin_pool_uuid && h->thin_device_id == UINT32_MAX)
                return 0;
        if (!h->thin_pool_uuid || h->thin_device_id > HOME_THIN_DEVICE_ID_MAX)
                return -EBADMSG;
        if (user_record_storage(h) != USER_LUKS)
                return -EBADMSG;
        if (h->disk_size == UINT64_MAX || h->disk_size == 0 || h->disk_size % 512U != 0)
                return -EBADMSG;
        if (!streq(h->thin_pool_uuid, pool->device.uuid))
                return -ESTALE;

        return 1;
}

static int thin_volume_validate_mapping(
                UserRecord *h,
                const ThinPoolInfo *pool,
                char **ret_path) {

        _cleanup_(dm_target_info_done) DmTargetInfo target = {};
        _cleanup_free_ char *expected_uuid = NULL, *name = NULL, *path = NULL;
        DmDeviceInfo device;
        unsigned pool_major, pool_minor, device_id;
        int consumed = 0, r;

        assert(h);
        assert(pool);

        r = home_thin_volume_make_path(h, pool->path, &path, &name);
        if (r < 0)
                return r;
        r = dm_device_info_from_path(path, &device);
        if (r == -ENOENT)
                return 0;
        if (r < 0)
                return r;

        expected_uuid = strjoin("HOMED-THIN-", SD_ID128_TO_STRING(h->uuid));
        if (!expected_uuid)
                return -ENOMEM;
        if (!streq(device.name, name) || !streq(device.uuid, expected_uuid) ||
            FLAGS_SET(device.flags, DM_READONLY_FLAG) || device.target_count != 1)
                return -EREMCHG;

        r = dm_device_query_target(name, true, &target);
        if (r < 0)
                return r;
        if (!streq(target.type, "thin") || target.start != 0 || target.length != h->disk_size / 512U ||
            sscanf(target.parameters, "%u:%u %u %n", &pool_major, &pool_minor, &device_id, &consumed) != 3 ||
            consumed <= 0 || !isempty(target.parameters + consumed) ||
            makedev(pool_major, pool_minor) != pool->device.devnum || device_id != h->thin_device_id)
                return -EREMCHG;

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return 1;
}

int home_thin_volume_create(
                UserRecord *h,
                const char *pool_path,
                uint64_t size,
                sd_id128_t creation_id,
                char **ret_path,
                char **ret_name) {

        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(h);
        assert(pool_path);
        assert(size > 0 && size % 512U == 0);
        assert(!sd_id128_is_null(creation_id));
        assert(ret_path);
        assert(ret_name);

        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        r = thin_volume_validate_binding(h, &pool);
        if (r <= 0)
                return r < 0 ? r : -EBADMSG;
        if (state.operation != THIN_OPERATION_CREATE ||
            !sd_id128_equal(state.home_uuid, h->uuid) || state.device_id != h->thin_device_id)
                return -EREMCHG;
        if (pool.status.transaction_id != state.operation_transaction_id)
                return -EALREADY;

        r = thin_pool_send_device_message(&pool, "create_thin", h->thin_device_id);
        if (r < 0)
                return log_error_errno(r, "Failed to allocate dm-thin device ID %" PRIu32 ": %m",
                                       h->thin_device_id);
        r = thin_pool_advance_transaction(&pool, pool.status.transaction_id);
        if (r < 0)
                return log_error_errno(r, "Failed to advance dm-thin transaction: %m");
        r = thin_pool_confirm_transaction(pool_path, pool.status.transaction_id + 1U);
        if (r < 0)
                return r;

        state.transaction_id = ++pool.status.transaction_id;
        r = thin_pool_state_save(&state);
        if (r < 0)
                return r;

        r = thin_volume_create_mapping(h, &pool, h->thin_device_id, size, ret_path, ret_name);
        if (r < 0)
                return log_error_errno(r, "Failed to activate new dm-thin home device: %m");

        return 1;
}

int home_thin_volume_commit_path(UserRecord *h, const char *pool_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(h);
        assert(pool_path);
        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        r = thin_volume_validate_binding(h, &pool);
        if (r <= 0)
                return r < 0 ? r : -EBADMSG;
        if (state.operation == THIN_OPERATION_NONE)
                return 0;
        if (state.operation != THIN_OPERATION_CREATE ||
            !sd_id128_equal(state.home_uuid, h->uuid) || state.device_id != h->thin_device_id ||
            pool.status.transaction_id != state.operation_transaction_id + 1U)
                return -EREMCHG;

        state.operation = THIN_OPERATION_NONE;
        state.home_uuid = SD_ID128_NULL;
        state.device_id = UINT32_MAX;
        state.operation_transaction_id = 0;
        return thin_pool_state_save(&state);
}

int home_thin_volume_commit(UserRecord *h) {
        const char *pool_path;

        assert(h);

        pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;

        return home_thin_volume_commit_path(h, pool_path);
}

int home_thin_volume_activate(UserRecord *h, bool already_active, char **ret_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int fd = -EBADF;
        _cleanup_close_ int lock_fd = -EBADF;
        _cleanup_free_ char *mapping = NULL, *path = NULL;
        const char *image_path, *pool_path;
        uint64_t offset, size;
        int r;

        assert(h);

        if (!h->thin_pool_uuid && h->thin_device_id == UINT32_MAX)
                return 0;
        pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;
        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        lock_fd = safe_close(lock_fd);
        r = thin_volume_validate_binding(h, &pool);
        if (r <= 0)
                return r;
        r = thin_volume_validate_mapping(h, &pool, &path);
        if (r < 0)
                return r;
        if (r == 0) {
                r = thin_volume_create_mapping(h, &pool, h->thin_device_id, h->disk_size, &path, NULL);
                if (r < 0)
                        return r;
        }

        if (already_active) {
                if (ret_path)
                        *ret_path = TAKE_PTR(path);
                return 1;
        }

        image_path = user_record_image_path(h);
        if (!image_path || path_equal(image_path, path))
                return -EBADMSG;
        fd = open(path, O_RDONLY|O_CLOEXEC|O_NONBLOCK|O_NOCTTY);
        if (fd < 0)
                return -errno;
        r = thin_volume_find_partition(h, fd, &offset, &size);
        if (r < 0)
                goto fail;
        r = thin_volume_unmap_partition(path);
        if (r < 0)
                goto fail;
        r = home_thin_volume_map_partition(h, fd, offset, size, &mapping);
        if (r < 0)
                goto fail;
        r = device_wait_for_devlink(image_path, "block", 45 * USEC_PER_SEC, NULL);
        if (r < 0)
                goto fail;

        if (ret_path)
                *ret_path = TAKE_PTR(path);
        return 1;

fail:
        (void) home_thin_volume_deactivate_path(path);
        return r;
}

int home_thin_volume_exists(UserRecord *h) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        const char *pool_path;
        int r;

        assert(h);

        if (!h->thin_pool_uuid && h->thin_device_id == UINT32_MAX)
                return 0;
        pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;
        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        lock_fd = safe_close(lock_fd);
        r = thin_volume_validate_binding(h, &pool);
        if (r <= 0)
                return r;
        r = thin_volume_validate_mapping(h, &pool, NULL);
        if (r != 0)
                return r;

        _cleanup_free_ char *name = NULL, *path = NULL;
        r = home_thin_volume_make_path(h, pool_path, &path, &name);
        if (r < 0)
                return r;
        r = thin_volume_create_mapping(h, &pool, h->thin_device_id, h->disk_size, NULL, NULL);
        if (r < 0)
                return ERRNO_IS_NEG_DEVICE_ABSENT(r) ? 0 : r;
        (void) dm_remove_device(name);
        return 1;
}

int home_thin_volume_deactivate_path(const char *path) {
        _cleanup_free_ char *name = NULL;
        int r;

        assert(path);

        r = thin_volume_unmap_partition(path);
        if (r < 0)
                return r;
        r = path_extract_filename(path, &name);
        if (r < 0)
                return r;
        r = dm_remove_device(name);
        if (r < 0)
                return r;
        return 1;
}

int home_thin_volume_deactivate(UserRecord *h) {
        _cleanup_free_ char *name = NULL, *path = NULL;
        const char *pool_path;
        int r;

        assert(h);

        if (!h->thin_pool_uuid && h->thin_device_id == UINT32_MAX)
                return 0;
        pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;
        r = home_thin_volume_make_path(h, pool_path, &path, &name);
        if (r < 0)
                return r;
        return home_thin_volume_deactivate_path(path);
}

static int thin_volume_delete(UserRecord *h, const char *pool_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        ThinOperation previous_operation;
        uint64_t previous_transaction;
        int r;

        assert(h);
        assert(pool_path);
        r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
        if (r < 0)
                return r;
        r = thin_volume_validate_binding(h, &pool);
        if (r <= 0)
                return r;

        previous_operation = state.operation;
        previous_transaction = state.operation_transaction_id;
        if (state.operation == THIN_OPERATION_DELETE &&
            sd_id128_equal(state.home_uuid, h->uuid) && state.device_id == h->thin_device_id &&
            pool.status.transaction_id == state.operation_transaction_id + 1U) {
                state.transaction_id = pool.status.transaction_id;
                state.operation = THIN_OPERATION_NONE;
                state.home_uuid = SD_ID128_NULL;
                state.device_id = UINT32_MAX;
                state.operation_transaction_id = 0;
                return thin_pool_state_save(&state);
        }
        if (state.operation != THIN_OPERATION_NONE &&
            !((state.operation == THIN_OPERATION_CREATE || state.operation == THIN_OPERATION_DELETE) &&
              sd_id128_equal(state.home_uuid, h->uuid) && state.device_id == h->thin_device_id))
                return -EBUSY;

        state.operation = THIN_OPERATION_DELETE;
        state.home_uuid = h->uuid;
        state.device_id = h->thin_device_id;
        state.operation_transaction_id = pool.status.transaction_id;
        r = thin_pool_state_save(&state);
        if (r < 0)
                return r;

        r = thin_pool_send_device_message(&pool, "delete", h->thin_device_id);
        if (r < 0 && r != -ENODATA)
                return r;
        if (r == -ENODATA && previous_operation == THIN_OPERATION_CREATE &&
            pool.status.transaction_id == previous_transaction) {
                state.operation = THIN_OPERATION_NONE;
                state.home_uuid = SD_ID128_NULL;
                state.device_id = UINT32_MAX;
                state.operation_transaction_id = 0;
                return thin_pool_state_save(&state);
        }
        r = thin_pool_advance_transaction(&pool, pool.status.transaction_id);
        if (r < 0)
                return r;
        r = thin_pool_confirm_transaction(pool_path, pool.status.transaction_id + 1U);
        if (r < 0)
                return r;

        state.transaction_id = pool.status.transaction_id + 1U;
        state.operation = THIN_OPERATION_NONE;
        state.home_uuid = SD_ID128_NULL;
        state.device_id = UINT32_MAX;
        state.operation_transaction_id = 0;
        return thin_pool_state_save(&state);
}

int home_thin_volume_remove(UserRecord *h) {
        _cleanup_free_ char *name = NULL, *path = NULL;
        const char *pool_path;
        int r;

        assert(h);

        if (!h->thin_pool_uuid && h->thin_device_id == UINT32_MAX)
                return 0;

        pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;
        r = home_thin_volume_make_path(h, pool_path, &path, &name);
        if (r < 0)
                return r;
        r = home_thin_volume_deactivate_path(path);
        if (r < 0 && r != -ENXIO)
                return r;
        r = thin_volume_delete(h, pool_path);
        if (r < 0)
                return r;

        log_info("Removed dm-thin home device ID %" PRIu32 ".", h->thin_device_id);
        return 1;
}

int home_thin_volume_remove_incomplete(UserRecord *h, const char *pool_path) {
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        _cleanup_(thin_pool_state_done) ThinPoolState state = {};
        _cleanup_close_ int lock_fd = -EBADF;
        int r;

        assert(h);
        assert(pool_path);

        if (!h->thin_pool_uuid || h->thin_device_id == UINT32_MAX) {
                r = thin_pool_state_acquire(pool_path, &pool, &state, &lock_fd);
                if (r < 0)
                        return r;
                if (state.operation != THIN_OPERATION_CREATE ||
                    !sd_id128_equal(state.home_uuid, h->uuid))
                        return 0;

                h->thin_pool_uuid = strdup(pool.device.uuid);
                if (!h->thin_pool_uuid)
                        return -ENOMEM;
                h->thin_device_id = state.device_id;
                lock_fd = safe_close(lock_fd);
        }

        _cleanup_free_ char *name = NULL, *path = NULL;
        r = home_thin_volume_make_path(h, pool_path, &path, &name);
        if (r < 0)
                return r;
        r = home_thin_volume_deactivate_path(path);
        if (r < 0 && r != -ENXIO)
                return r;
        return thin_volume_delete(h, pool_path);
}

int home_thin_volume_remove_created(const char *path) {
        _cleanup_(dm_target_info_done) DmTargetInfo target = {};
        _cleanup_(user_record_unrefp) UserRecord *h = NULL;
        _cleanup_free_ char *name = NULL;
        DmDeviceInfo device;
        unsigned pool_major, pool_minor, device_id;
        sd_id128_t home_uuid;
        int r;

        assert(path);

        r = dm_device_info_from_path(path, &device);
        if (r < 0)
                return r;
        if (!startswith(device.uuid, "HOMED-THIN-") ||
            sd_id128_from_string(device.uuid + STRLEN("HOMED-THIN-"), &home_uuid) < 0)
                return -EREMCHG;
        r = path_extract_filename(path, &name);
        if (r < 0)
                return r;
        r = dm_device_query_target(name, true, &target);
        if (r < 0)
                return r;
        if (!streq(target.type, "thin") ||
            sscanf(target.parameters, "%u:%u %u", &pool_major, &pool_minor, &device_id) != 3 ||
            device_id > HOME_THIN_DEVICE_ID_MAX)
                return -EREMCHG;

        h = user_record_new();
        if (!h)
                return -ENOMEM;
        h->uuid = home_uuid;
        h->storage = USER_LUKS;
        h->thin_device_id = device_id;

        const char *pool_path = secure_getenv("SYSTEMD_HOME_THIN_POOL");
        if (!pool_path)
                return -ENXIO;
        _cleanup_(thin_pool_info_done) ThinPoolInfo pool = {};
        r = thin_pool_query(pool_path, &pool);
        if (r < 0)
                return r;
        if (makedev(pool_major, pool_minor) != pool.device.devnum)
                return -EREMCHG;
        h->thin_pool_uuid = strdup(pool.device.uuid);
        if (!h->thin_pool_uuid)
                return -ENOMEM;

        r = home_thin_volume_deactivate_path(path);
        if (r < 0)
                return r;
        return thin_volume_delete(h, pool_path);
}
