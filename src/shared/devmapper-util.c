/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <sys/ioctl.h>
#include <sys/stat.h>
#include <sys/sysmacros.h>
#include <linux/dm-ioctl.h>

#include "alloc-util.h"
#include "devmapper-util.h"
#include "log.h"
#include "sd-dlopen.h"
#include "string-util.h"
#include "fd-util.h"
#include "fs-util.h"
#include "errno-util.h"

static int dm_ioctl_run(const char *name, uint32_t cmd, struct dm_ioctl *data, size_t data_size) {
        _cleanup_close_ int fd = -EBADF;
        struct dm_ioctl *dm = data;
        int r;

        assert(name);
        assert(data);
        assert(data_size >= sizeof(struct dm_ioctl));

        if (data_size > UINT32_MAX)
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM ioctl data too large.");

        dm->version[0] = DM_VERSION_MAJOR;
        dm->version[1] = DM_VERSION_MINOR;
        dm->version[2] = DM_VERSION_PATCHLEVEL;
        dm->data_size = data_size;

        if (strlen(name) >= sizeof_field(struct dm_ioctl, name))
                return log_error_errno(SYNTHETIC_ERRNO(ENAMETOOLONG),
                               "DM device name too long: %s", name);
        strncpy_exact(dm->name, name, sizeof(dm->name));

        fd = xopenat(AT_FDCWD, "/dev/mapper/control", O_RDWR);
        if (fd < 0)
                return log_error_errno(fd, "Failed to open /dev/mapper/control: %m");

        r = RET_NERRNO(ioctl(fd, cmd, dm));
        if (r < 0) {
                if (r == -ENXIO && cmd == DM_DEV_REMOVE) {
                        log_full_errno(LOG_DEBUG, r, "Device \"%s\" is already inactive, ignoring: %m", dm->name);
                        return 0;
                }
                return log_error_errno(r, "DM ioctl failed: %m");
        }
        return 0;
}

static int dm_load_table(const char *name, const char *target_type, uint64_t start, uint64_t size, const char *target_params, uint32_t flags) {
        char *params_buf;
        size_t params_len, target_size, dm_size;
        _cleanup_free_ struct dm_ioctl *dm = NULL;
        struct dm_target_spec *tgt;

        assert(name);
        assert(target_params);

        params_len = strlen(target_params);
        target_size = sizeof(struct dm_target_spec);
        if (!ADD_SAFE(&params_len, params_len, 1) ||
            !ADD_SAFE(&target_size, target_size, params_len))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM target parameters too long.");

        /* ensure that dm_size is always aligned, so it makes the buffer actually match what .next claims */
        target_size = ALIGN8(target_size);
        dm_size = ALIGN8(sizeof(struct dm_ioctl));
        if (target_size == SIZE_MAX ||
            !ADD_SAFE(&dm_size, dm_size, target_size))
                return log_error_errno(SYNTHETIC_ERRNO(EOVERFLOW), "DM target parameters too long.");

        dm = malloc0(dm_size);
        if (!dm)
                return log_oom();
        *dm = (struct dm_ioctl) {
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
                .target_count = 1,
                .flags = flags,
        };

        tgt = CAST_ALIGN_PTR(struct dm_target_spec, (uint8_t *) dm + dm->data_start);
        *tgt = (struct dm_target_spec) {
                .sector_start = start,
                .length = size,
                /* Per linux/dm-ioctl.h: next is the byte offset from this dm_target_spec to the next one,
                 * rounded up to 8-byte alignment. With target_count == 1 next == 0 works, but set it
                 * correctly to avoid silent breakage if a second target is ever added. */
                .next = target_size,
        };
        strncpy(tgt->target_type, target_type, sizeof(tgt->target_type));

        params_buf = (char *) tgt + ALIGN8(sizeof(struct dm_target_spec));
        memcpy(params_buf, target_params, params_len);

        return dm_ioctl_run(name, DM_TABLE_LOAD, dm, dm_size);
}

static int resume(const char *name) {
        struct dm_ioctl dm = {};
        int r;

        r = dm_ioctl_run(name, DM_DEV_SUSPEND, &dm, sizeof(dm));
        if (r < 0)
                return r;

        return 0;
}

static int get_params(const char *name, uint64_t *start, uint64_t *size, char **ret) {
        _cleanup_free_ struct dm_ioctl *dm = NULL;
        size_t data_size = 16384;
        struct dm_target_spec *tgt;
        char *params;
        size_t params_max_len;
        int r;

        assert(ret);
        assert(start);
        assert(size);

        dm = malloc0(data_size);
        if (!dm)
                return log_oom();

        *dm = (struct dm_ioctl) {
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
                .flags = DM_STATUS_TABLE_FLAG,
        };

        r = dm_ioctl_run(name, DM_TABLE_STATUS, dm, data_size);
        if (r < 0)
                return r;

        assert(dm->data_size >= sizeof(struct dm_ioctl));

        if (dm->target_count != 1)
                return 0;

        tgt = CAST_ALIGN_PTR(struct dm_target_spec, (uint8_t *)dm + dm->data_start);

        assert(dm->data_size >= (uint8_t *)tgt + sizeof(struct dm_target_spec) - (uint8_t *)dm);

        if (!streq(tgt->target_type, "verity"))
                return -EINVAL;

        params = (char *)tgt + ALIGN8(sizeof(struct dm_target_spec));
        params_max_len = (char *)dm + dm->data_size - params;

        *ret = strndup(params, params_max_len);
        if (!*ret)
                return log_oom();
        *start = tgt->sector_start;
        *size = tgt->length;

        return 0;
}

static int reload_params(const char *name, const char *params, uint64_t start, uint64_t size) {
        return dm_load_table(name, "verity", start, size, params, DM_READONLY_FLAG);
}

static int device_name(dev_t dev, char **ret) {
        struct stat st;

        assert(ret);
        assert(!*ret);

        if (asprintf(ret, "%u:%u", major(dev), minor(dev)) < 0)
                return -ENOMEM;

        return 0;
}

static int update_params(const char *src_params, dev_t new_dev, dev_t new_hash_dev, char **ret) {
        _cleanup_free_ char *params = NULL;
        _cleanup_free_ char *new_dev_formatted = NULL;
        _cleanup_free_ char *new_hash_dev_formatted = NULL;
        int r;

        assert(ret);
        assert(!*ret);

        params = strdup(src_params);
        if (!params)
                return log_oom();

        const char* params_comps[10];
        size_t index = 0;
        params_comps[index++] = params;
        for (size_t i = 0; params[i] && index < 10; ++i) {
                if (params[i] == ' ') {
                        params_comps[index++] = params + i + 1;
                        params[i] = '\0';
                }
        }

        if (index != 10)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not enough parameters");

        if (new_dev) {
                r = device_name(new_dev, &new_dev_formatted);
                if (r < 0)
                        return r;
        }

        if (new_hash_dev) {
                r = device_name(new_hash_dev, &new_hash_dev_formatted);
                if (r < 0)
                        return r;
        }

        if (asprintf(ret, "%s %s %s %s %s %s %s %s %s %s",
                     params_comps[0],
                     new_dev_formatted?new_dev_formatted:params_comps[1],
                     new_hash_dev_formatted?new_hash_dev_formatted:params_comps[2],
                     params_comps[3],
                     params_comps[4],
                     params_comps[5],
                     params_comps[6],
                     params_comps[7],
                     params_comps[8],
                     params_comps[9]) < 0)
                return log_oom();

        return 0;
}

int swap_verity_devices(const char *name, dev_t new_dev, dev_t new_hash_dev) {
        _cleanup_free_ char* src_params = NULL;
        _cleanup_free_ char* new_params = NULL;
        uint64_t start, size;
        int r;

        assert(name);
        assert(new_dev || new_hash_dev);

        r = get_params(name, &start, &size, &src_params);
        if (r < 0)
                return r;

        r = update_params(src_params, new_dev, new_hash_dev, &new_params);
        if (r < 0)
                return r;

        r = reload_params(name, new_params, start, size);
        if (r < 0)
                return r;

        r = resume(name);
        if (r < 0)
                return r;

        return 0;
}

int dm_is_verity(const char *name, char **ret_dev, char **ret_hash_dev) {
        _cleanup_free_ struct dm_ioctl *dm = NULL;
        struct dm_target_spec *tgt;
        char *params;
        size_t params_max_len;
        int r;
        size_t data_size = 16384;

        assert(ret_dev);
        assert(ret_hash_dev);

        dm = malloc0(data_size);
        if (!dm)
                return log_oom();

        *dm = (struct dm_ioctl) {
                .data_start = ALIGN8(sizeof(struct dm_ioctl)),
                .flags = DM_STATUS_TABLE_FLAG,
        };

        r = dm_ioctl_run(name, DM_TABLE_STATUS, dm, data_size);
        if (r < 0)
                return r;

        assert(dm->data_size >= sizeof(struct dm_ioctl));

        if (dm->target_count != 1)
                return 0;

        tgt = CAST_ALIGN_PTR(struct dm_target_spec, (uint8_t *)dm + dm->data_start);

        assert(dm->data_size >= (uint8_t *)tgt + sizeof(struct dm_target_spec) - (uint8_t *)dm);

        if (!streq(tgt->target_type, "verity"))
                return 0;

        params = (char *)tgt + ALIGN8(sizeof(struct dm_target_spec));
        params_max_len = (char *)dm + dm->data_size - params;

        const char* params_comps[10];
        size_t index = 0;
        params_comps[index++] = params;
        for (size_t i = 0; i < params_max_len && params[i] && index < 10; ++i) {
                if (params[i] == ' ') {
                        params_comps[index++] = params + i + 1;
                        params[i] = '\0';
                }
        }

        if (index != 10)
                return log_error_errno(SYNTHETIC_ERRNO(EINVAL), "Not enough parameters");

        if (asprintf(ret_dev, "/dev/block/%s", params_comps[1]) < 0) {
                return log_oom();
        }

        if (asprintf(ret_hash_dev, "/dev/block/%s", params_comps[2]) < 0) {
                return log_oom();
        }

        return 1;
}
