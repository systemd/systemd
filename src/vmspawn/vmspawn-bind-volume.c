/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <fcntl.h>
#include <sys/stat.h>

#include "sd-varlink.h"

#include "alloc-util.h"
#include "fd-util.h"
#include "log.h"
#include "runtime-scope.h"
#include "stat-util.h"
#include "storage-util.h"
#include "string-util.h"
#include "vmspawn-bind-volume.h"
#include "vmspawn-qmp.h"

DiskType disk_type_from_bind_volume_config(const char *config) {
        if (isempty(config))
                return DISK_TYPE_VIRTIO_BLK;
        return disk_type_from_string(config);
}

int vmspawn_bind_volume_acquire(
                RuntimeScope scope,
                const BindVolume *v,
                bool removable,
                sd_varlink *link,
                DriveInfo **ret,
                char **reterr_error_id) {

        _cleanup_(storage_acquire_reply_done) StorageAcquireReply reply = STORAGE_ACQUIRE_REPLY_INIT;
        _cleanup_(drive_info_unrefp) DriveInfo *d = NULL;
        _cleanup_free_ char *err = NULL;
        int r;

        assert(v);
        assert(ret);

        DiskType dt = disk_type_from_bind_volume_config(v->config);
        if (dt < 0) {
                r = dt;
                goto fail;
        }

        r = storage_acquire_volume(scope, v, /* allow_interactive_auth= */ false, &err, &reply);
        if (r < 0)
                goto fail;

        if (reply.type == VOLUME_DIR) {
                r = log_debug_errno(SYNTHETIC_ERRNO(EOPNOTSUPP),
                                    "Directory volumes are not supported for vmspawn block devices.");
                goto fail;
        }

        struct stat st;
        if (fstat(reply.fd, &st) < 0) {
                r = -errno;
                goto fail;
        }
        r = stat_verify_regular_or_block(&st);
        if (r < 0)
                goto fail;

        d = drive_info_new();
        if (!d) {
                r = -ENOMEM;
                goto fail;
        }

        d->id = strjoin(v->provider, ":", v->volume);
        d->disk_driver = strdup(ASSERT_PTR(qemu_device_driver_to_string(dt)));
        d->format = strdup("raw");
        d->path = strdup(v->volume);
        if (!d->id || !d->disk_driver || !d->format || !d->path) {
                r = -ENOMEM;
                goto fail;
        }

        d->disk_type = dt;
        d->fd = TAKE_FD(reply.fd);

        if (reply.type == VOLUME_BLK || S_ISBLK(st.st_mode))
                d->flags |= QMP_DRIVE_BLOCK_DEVICE;
        if (reply.read_only > 0 || dt == DISK_TYPE_VIRTIO_SCSI_CDROM)
                d->flags |= QMP_DRIVE_READ_ONLY;
        if (removable)
                d->flags |= QMP_DRIVE_REMOVABLE;
        d->link = sd_varlink_ref(link);

        *ret = TAKE_PTR(d);
        return 0;

fail:
        if (reterr_error_id)
                *reterr_error_id = TAKE_PTR(err);
        return r;
}

/* Takes ownership of fd unconditionally — it is closed on every error path too. */
int vmspawn_bind_volume_attach_fd(
                VmspawnQmpBridge *bridge,
                sd_varlink *link,
                int fd,
                const char *name,
                const char *config) {

        _cleanup_close_ int owned_fd = fd;
        int r;

        assert(bridge);
        assert(link);
        assert(fd >= 0);
        assert(name);

        DiskType dt = disk_type_from_bind_volume_config(config);
        if (dt < 0)
                return dt;

        struct stat st;
        if (fstat(owned_fd, &st) < 0)
                return -errno;
        r = stat_verify_regular_or_block(&st);
        if (r < 0)
                return r;

        int oflags = fcntl(owned_fd, F_GETFL);
        if (oflags < 0)
                return -errno;
        if (FLAGS_SET(oflags, O_PATH))
                return -EBADF;
        if ((oflags & O_ACCMODE_STRICT) == O_WRONLY)
                return -EBADF;

        _cleanup_(drive_info_unrefp) DriveInfo *d = drive_info_new();
        if (!d)
                return -ENOMEM;

        d->id = strdup(name);
        d->disk_driver = strdup(ASSERT_PTR(qemu_device_driver_to_string(dt)));
        d->format = strdup("raw");
        d->path = strdup(name);
        if (!d->id || !d->disk_driver || !d->format || !d->path)
                return -ENOMEM;

        d->disk_type = dt;
        d->fd = TAKE_FD(owned_fd);
        if (S_ISBLK(st.st_mode))
                d->flags |= QMP_DRIVE_BLOCK_DEVICE;
        if (dt == DISK_TYPE_VIRTIO_SCSI_CDROM || (oflags & O_ACCMODE_STRICT) == O_RDONLY)
                d->flags |= QMP_DRIVE_READ_ONLY;
        d->flags |= QMP_DRIVE_REMOVABLE;
        d->link = sd_varlink_ref(link);

        return vmspawn_qmp_add_block_device(bridge, TAKE_PTR(d));
}

void bind_volumes_done(BindVolumes *bv) {
        assert(bv);
        FOREACH_ARRAY(v, bv->items, bv->n_items)
                bind_volume_free(*v);
        bv->items = mfree(bv->items);
        bv->n_items = 0;
}

int vmspawn_bind_volume_prepare_boot(
                RuntimeScope scope,
                const BindVolumes *bv,
                DriveInfos *drives) {

        int r;

        assert(bv);
        assert(drives);

        if (bv->n_items == 0)
                return 0;

        if (!GREEDY_REALLOC(drives->drives, drives->n_drives + bv->n_items))
                return log_oom();

        FOREACH_ARRAY(it, bv->items, bv->n_items) {
                BindVolume *v = *it;
                _cleanup_(drive_info_unrefp) DriveInfo *d = NULL;
                _cleanup_free_ char *error_id = NULL;

                r = vmspawn_bind_volume_acquire(
                                scope, v,
                                /* removable= */ false,
                                /* link= */ NULL,
                                &d, &error_id);
                if (r < 0) {
                        if (error_id)
                                return log_error_errno(r,
                                                       "Failed to acquire storage volume '%s:%s' (%s): %m",
                                                       v->provider, v->volume, error_id);
                        return log_error_errno(r,
                                               "Failed to acquire storage volume '%s:%s': %m",
                                               v->provider, v->volume);
                }

                drives->drives[drives->n_drives++] = TAKE_PTR(d);
        }

        return 0;
}
