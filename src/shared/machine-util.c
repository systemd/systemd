/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "extract-word.h"
#include "machine-util.h"
#include "parse-argument.h"
#include "parse-util.h"
#include "storage-util.h"
#include "string-table.h"
#include "string-util.h"
#include "strv.h"

static const char *const image_format_table[_IMAGE_FORMAT_MAX] = {
        [IMAGE_FORMAT_RAW]   = "raw",
        [IMAGE_FORMAT_QCOW2] = "qcow2",
};

DEFINE_STRING_TABLE_LOOKUP(image_format, ImageFormat);

static const char *const disk_type_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio-blk",
        [DISK_TYPE_VIRTIO_SCSI]       = "virtio-scsi",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi-cd",
};

DEFINE_STRING_TABLE_LOOKUP(disk_type, DiskType);

/* Wire value for the io.systemd.VirtualMachineInstance.BlockDriver IDL enum. */
static const char *const block_driver_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio_blk",
        [DISK_TYPE_VIRTIO_SCSI]       = "scsi_hd",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi_cd",
};

DEFINE_STRING_TABLE_LOOKUP(block_driver, DiskType);

/* QEMU -device driver name (e.g. "virtio-blk-pci"). */
static const char *const qemu_device_driver_table[_DISK_TYPE_MAX] = {
        [DISK_TYPE_VIRTIO_BLK]        = "virtio-blk-pci",
        [DISK_TYPE_VIRTIO_SCSI]       = "scsi-hd",
        [DISK_TYPE_NVME]              = "nvme",
        [DISK_TYPE_VIRTIO_SCSI_CDROM] = "scsi-cd",
};

DEFINE_STRING_TABLE_LOOKUP(qemu_device_driver, DiskType);

int parse_disk_spec(
                const char *arg,
                ImageFormat *format,
                DiskType *disk_type,
                char **ret_path) {

        int r;

        assert(arg);
        assert(format);
        assert(disk_type);
        assert(ret_path);

        ImageFormat parsed_format = *format;
        DiskType parsed_disk_type = *disk_type;
        const char *dp = arg;

        /* Format and disk-type vocabularies don't overlap, so prefixes may appear in any order. */
        for (;;) {
                _cleanup_free_ char *word = NULL;
                const char *save = dp;

                r = extract_first_word(&dp, &word, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
                if (r < 0)
                        return r;
                if (r == 0 || !dp) {
                        /* No ':' remained after this word — rest is the path. */
                        dp = save;
                        break;
                }

                ImageFormat f = image_format_from_string(word);
                if (f >= 0) {
                        parsed_format = f;
                        continue;
                }

                DiskType dt = disk_type_from_string(word);
                if (dt >= 0) {
                        parsed_disk_type = dt;
                        continue;
                }

                /* Unknown prefix — rewind, remainder is the path. */
                dp = save;
                break;
        }

        _cleanup_free_ char *path = NULL;
        r = parse_path_argument(dp, /* suppress_root= */ false, &path);
        if (r < 0)
                return r;

        *format = parsed_format;
        *disk_type = parsed_disk_type;
        *ret_path = TAKE_PTR(path);
        return 0;
}

BindVolume* bind_volume_free(BindVolume *v) {
        if (!v)
                return NULL;

        free(v->provider);
        free(v->volume);
        free(v->config);
        free(v->template);

        return mfree(v);
}

static int bind_volume_apply_extra(BindVolume *v, const char *key, const char *value) {
        int r;

        assert(v);
        assert(key);
        assert(value);

        if (streq(key, "template")) {
                if (v->template)
                        return -EINVAL;
                if (!storage_template_name_is_valid(value))
                        return -EINVAL;
                return free_and_strdup(&v->template, value);
        }

        if (streq(key, "create")) {
                if (v->create_mode != _CREATE_MODE_INVALID)
                        return -EINVAL;
                CreateMode m = create_mode_from_string(value);
                if (m < 0)
                        return m;
                v->create_mode = m;
                return 0;
        }

        if (STR_IN_SET(key, "read-only", "ro")) {
                if (v->read_only != -1)
                        return -EINVAL;
                if (streq(value, "auto"))
                        v->read_only = -ENODATA;
                else {
                        r = parse_boolean(value);
                        if (r < 0)
                                return r;
                        v->read_only = r;
                }
                return 0;
        }

        if (STR_IN_SET(key, "size", "create-size")) {
                if (v->create_size_bytes != UINT64_MAX)
                        return -EINVAL;
                uint64_t sz;
                r = parse_size(value, 1024, &sz);
                if (r < 0)
                        return r;
                v->create_size_bytes = sz;
                return 0;
        }

        if (streq(key, "request-as")) {
                if (v->request_as != _VOLUME_TYPE_INVALID)
                        return -EINVAL;
                VolumeType t = volume_type_from_string(value);
                if (t < 0)
                        return t;
                v->request_as = t;
                return 0;
        }

        return -EINVAL;
}

int bind_volume_parse(const char *arg, BindVolume **ret) {
        _cleanup_(bind_volume_freep) BindVolume *v = NULL;
        int r;

        assert(arg);
        assert(ret);

        v = new(BindVolume, 1);
        if (!v)
                return -ENOMEM;

        *v = BIND_VOLUME_INIT;

        const char *p = arg;
        _cleanup_free_ char *provider = NULL, *volume = NULL, *config = NULL;

        r = extract_first_word(&p, &provider, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || isempty(provider) || !storage_provider_name_is_valid(provider))
                return -EINVAL;

        r = extract_first_word(&p, &volume, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;
        if (r == 0 || isempty(volume) || !storage_volume_name_is_valid(volume))
                return -EINVAL;

        r = extract_first_word(&p, &config, ":", EXTRACT_DONT_COALESCE_SEPARATORS);
        if (r < 0)
                return r;

        /* "<provider>:<volume>" ends up as a QEMU device id — guard against control-char injection. */
        _cleanup_free_ char *combined = strjoin(provider, ":", volume);
        if (!combined)
                return -ENOMEM;
        if (!string_is_safe(combined, /* flags= */ 0))
                return -EINVAL;

        v->provider = TAKE_PTR(provider);
        v->volume = TAKE_PTR(volume);
        if (!isempty(config))
                v->config = TAKE_PTR(config);

        for (;;) {
                _cleanup_free_ char *kv = NULL, *key = NULL, *value = NULL;

                r = extract_first_word(&p, &kv, ",", 0);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                r = split_pair(kv, "=", &key, &value);
                if (r < 0)
                        return r;
                if (isempty(key))
                        return -EINVAL;

                r = bind_volume_apply_extra(v, key, value);
                if (r < 0)
                        return r;
        }

        *ret = TAKE_PTR(v);
        return 0;
}

int machine_storage_name_split(const char *s, char **ret_provider, char **ret_volume) {
        _cleanup_free_ char *p = NULL, *v = NULL;
        int r;

        if (isempty(s))
                return -EINVAL;

        r = split_pair(s, ":", &p, &v);
        if (r < 0)
                return r;

        if (!storage_provider_name_is_valid(p) || !storage_volume_name_is_valid(v))
                return -EINVAL;

        if (ret_provider)
                *ret_provider = TAKE_PTR(p);
        if (ret_volume)
                *ret_volume = TAKE_PTR(v);
        return 0;
}
