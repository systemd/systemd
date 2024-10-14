/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-json.h"
#include "sd-varlink.h"

#include "bus-polkit.h"
#include "image-varlink.h"
#include "machine.h"
#include "string-util.h"

int vl_method_update_image(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata) {
        struct params {
                const char *image_name;
                const char *new_name;
                int read_only;
                uint64_t limit;
        };

        static const sd_json_dispatch_field dispatch_table[] = {
                { "name",     SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct params, image_name), SD_JSON_MANDATORY },
                { "newName",  SD_JSON_VARIANT_STRING,        sd_json_dispatch_const_string, offsetof(struct params, new_name),   0 },
                { "readOnly", SD_JSON_VARIANT_BOOLEAN,       sd_json_dispatch_tristate,     offsetof(struct params, read_only),  0 },
                { "limit",    _SD_JSON_VARIANT_TYPE_INVALID, sd_json_dispatch_uint64,       offsetof(struct params, limit),      0 },
                VARLINK_DISPATCH_POLKIT_FIELD,
                {}
        };

        Manager *manager = ASSERT_PTR(userdata);
        struct params p = {
                .read_only = -1,
                .limit = UINT64_MAX,
        };
        Image *image;
        int r, ret = 0;

        assert(link);
        assert(parameters);

        r = sd_varlink_dispatch(link, parameters, dispatch_table, &p);
        if (r != 0)
                return r;

        if (!image_name_is_valid(p.image_name))
                return sd_varlink_error_invalid_parameter_name(link, "name");

        if (p.new_name && !image_name_is_valid(p.new_name))
                return sd_varlink_error_invalid_parameter_name(link, "newName");

        r = manager_acquire_image(manager, p.image_name, &image);
        if (r == -ENOENT)
                return sd_varlink_error(link, "io.systemd.MachineImage.NoSuchImage", NULL);
        if (r < 0)
                return r;

        r = varlink_verify_polkit_async(
                        link,
                        manager->bus,
                        "org.freedesktop.machine1.manage-images",
                        (const char**) STRV_MAKE("image", image->name,
                                                 "verb", "update_image"),
                        &manager->polkit_registry);
        if (r <= 0)
                return r;

        if (p.new_name) {
                r = rename_image_and_update_cache(manager, image, p.new_name);
                if (r < 0)
                        return log_debug_errno(r, "Failed to rename image: %m");
        }

        if (p.read_only >= 0) {
                r = image_read_only(image, p.read_only);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to toggle image read only, ignoring: %m"));
        }

        if (p.limit != UINT64_MAX) {
                r = image_set_limit(image, p.limit);
                if (r < 0)
                        RET_GATHER(ret, log_debug_errno(r, "Failed to set image limit, ignoring: %m"));
        }

        /* We intentionally swallowed errors from image_read_only() and image_set_limit(). Here we return first one to the user if any */
        if (ret < 0)
                return ret;

        return sd_varlink_reply(link, NULL);
}
