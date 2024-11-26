/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"

#include "alloc-util.h"
#include "device-nodes.h"
#include "fstab-util.h"
#include "hibernate-resume-config.h"
#include "os-util.h"
#include "parse-util.h"
#include "path-util.h"
#include "proc-cmdline.h"
#include "efivars.h"

typedef struct KernelHibernateLocation {
        char *device;
        uint64_t offset;
        bool offset_set;
} KernelHibernateLocation;

static KernelHibernateLocation* kernel_hibernate_location_free(KernelHibernateLocation *k) {
        if (!k)
                return NULL;

        free(k->device);

        return mfree(k);
}

DEFINE_TRIVIAL_CLEANUP_FUNC(KernelHibernateLocation*, kernel_hibernate_location_free);

EFIHibernateLocation* efi_hibernate_location_free(EFIHibernateLocation *e) {
        if (!e)
                return NULL;

        free(e->device);

        free(e->kernel_version);
        free(e->id);
        free(e->image_id);
        free(e->image_version);

        return mfree(e);
}

void hibernate_info_done(HibernateInfo *info) {
        assert(info);

        kernel_hibernate_location_free(info->cmdline);
        efi_hibernate_location_free(info->efi);
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        KernelHibernateLocation *k = ASSERT_PTR(data);
        int r;

        assert(key);

        if (streq(key, "resume")) {
                _cleanup_free_ char *d = NULL;

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                d = fstab_node_to_udev_node(value);
                if (!d)
                        return log_oom();

                free_and_replace(k->device, d);

        } else if (proc_cmdline_key_streq(key, "resume_offset")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = safe_atou64(value, &k->offset);
                if (r < 0)
                        return log_error_errno(r, "Failed to parse resume_offset=%s: %m", value);

                k->offset_set = true;
        }

        return 0;
}

static int get_kernel_hibernate_location(KernelHibernateLocation **ret) {
        _cleanup_(kernel_hibernate_location_freep) KernelHibernateLocation *k = NULL;
        int r;

        assert(ret);

        k = new0(KernelHibernateLocation, 1);
        if (!k)
                return log_oom();

        r = proc_cmdline_parse(parse_proc_cmdline_item, k, 0);
        if (r < 0)
                return log_error_errno(r, "Failed to parse kernel command line: %m");

        if (!k->device) {
                if (k->offset_set)
                        return log_error_errno(SYNTHETIC_ERRNO(EINVAL),
                                               "Found resume_offset=%" PRIu64 " but resume= is unset, refusing.",
                                               k->offset);

                *ret = NULL;
                return 0;
        }

        *ret = TAKE_PTR(k);
        return 1;
}

#if ENABLE_EFI
static bool validate_efi_hibernate_location(EFIHibernateLocation *e) {
        _cleanup_free_ char *id = NULL, *image_id = NULL;
        int r;

        assert(e);

        r = parse_os_release(NULL,
                             "ID", &id,
                             "IMAGE_ID", &image_id);
        if (r < 0)
                log_warning_errno(r, "Failed to parse os-release: %m");

        if (!streq_ptr(id, e->id) ||
            !streq_ptr(image_id, e->image_id)) {
                log_notice("HibernateLocation system identifier doesn't match currently running system, would not resume from it.");
                return false;
        }

        /*
         * Note that we accept kernel version mismatches. Linux writes the old kernel to disk as part of the
         * hibernation image, and thus resuming means the short-lived kernel that reads the image from the
         * disk will be replaced by the original kernel and effectively removed from memory as part of that.
         */

        return true;
}
#endif

int get_efi_hibernate_location(EFIHibernateLocation **ret) {
#if ENABLE_EFI
        static const sd_json_dispatch_field dispatch_table[] = {
                { "uuid",                  SD_JSON_VARIANT_STRING,        sd_json_dispatch_id128,  offsetof(EFIHibernateLocation, uuid),           SD_JSON_MANDATORY             },
                { "offset",                _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64, offsetof(EFIHibernateLocation, offset),         SD_JSON_MANDATORY             },
                { "kernelVersion",         SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(EFIHibernateLocation, kernel_version), SD_JSON_PERMISSIVE|SD_JSON_DEBUG },
                { "osReleaseId",           SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(EFIHibernateLocation, id),             SD_JSON_PERMISSIVE|SD_JSON_DEBUG },
                { "osReleaseImageId",      SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(EFIHibernateLocation, image_id),       SD_JSON_PERMISSIVE|SD_JSON_DEBUG },
                { "osReleaseVersionId",    SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(EFIHibernateLocation, version_id),     SD_JSON_PERMISSIVE|SD_JSON_DEBUG },
                { "osReleaseImageVersion", SD_JSON_VARIANT_STRING,        sd_json_dispatch_string, offsetof(EFIHibernateLocation, image_version),  SD_JSON_PERMISSIVE|SD_JSON_DEBUG },
                {},
        };

        _cleanup_(efi_hibernate_location_freep) EFIHibernateLocation *e = NULL;
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_free_ char *location_str = NULL;
        int r;

        if (!is_efi_boot())
                goto skip;

        r = efi_get_variable_string(EFI_SYSTEMD_VARIABLE_STR("HibernateLocation"), &location_str);
        if (r == -ENOENT) {
                log_debug_errno(r, "EFI variable HibernateLocation is not set, skipping.");
                goto skip;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to get EFI variable HibernateLocation: %m");

        r = sd_json_parse(location_str, 0, &v, NULL, NULL);
        if (r < 0)
                return log_error_errno(r, "Failed to parse HibernateLocation JSON object: %m");

        e = new0(EFIHibernateLocation, 1);
        if (!e)
                return log_oom();

        r = sd_json_dispatch(v, dispatch_table, SD_JSON_LOG|SD_JSON_ALLOW_EXTENSIONS, e);
        if (r < 0)
                return r;

        log_info("Reported hibernation image:%s%s%s%s%s%s%s%s%s%s UUID="SD_ID128_UUID_FORMAT_STR" offset=%"PRIu64,
                 e->id ? " ID=" : "",                       strempty(e->id),
                 e->image_id ? " IMAGE_ID=" : "",           strempty(e->image_id),
                 e->version_id ? " VERSION_ID=" : "",       strempty(e->version_id),
                 e->image_version ? " IMAGE_VERSION=" : "", strempty(e->image_version),
                 e->kernel_version ? " kernel=" : "",       strempty(e->kernel_version),
                 SD_ID128_FORMAT_VAL(e->uuid),
                 e->offset);

        if (!validate_efi_hibernate_location(e))
                goto skip;

        if (asprintf(&e->device, "/dev/disk/by-uuid/" SD_ID128_UUID_FORMAT_STR, SD_ID128_FORMAT_VAL(e->uuid)) < 0)
                return log_oom();

        if (ret)
                *ret = TAKE_PTR(e);
        return 1;

skip:
#endif
        if (ret)
                *ret = NULL;
        return 0;
}

void compare_hibernate_location_and_warn(const HibernateInfo *info) {
#if ENABLE_EFI
        int r;

        assert(info);

        if (!info->cmdline || !info->efi)
                return;

        assert(info->device == info->cmdline->device);

        if (!path_equal(info->cmdline->device, info->efi->device)) {
                r = devnode_same(info->cmdline->device, info->efi->device);
                if (r < 0)
                        log_warning_errno(r,
                                          "Failed to check if resume=%s is the same device as EFI HibernateLocation device '%s', ignoring: %m",
                                          info->cmdline->device, info->efi->device);
                if (r == 0)
                        log_warning("resume=%s doesn't match with EFI HibernateLocation device '%s', proceeding anyway with resume=.",
                                    info->cmdline->device, info->efi->device);
        }

        if (info->cmdline->offset != info->efi->offset)
                log_warning("resume_offset=%" PRIu64 " doesn't match with EFI HibernateLocation offset %" PRIu64 ", proceeding anyway with resume_offset=.",
                            info->cmdline->offset, info->efi->offset);
#endif
}

int acquire_hibernate_info(HibernateInfo *ret) {
        _cleanup_(hibernate_info_done) HibernateInfo i = {};
        int r;

        r = get_kernel_hibernate_location(&i.cmdline);
        if (r < 0)
                return r;

        r = get_efi_hibernate_location(&i.efi);
        if (r < 0)
                return r;

        if (i.cmdline) {
                i.device = i.cmdline->device;
                i.offset = i.cmdline->offset;
        } else if (i.efi) {
                i.device = i.efi->device;
                i.offset = i.efi->offset;
        } else
                return -ENODEV;

        *ret = TAKE_STRUCT(i);
        return 0;
}
