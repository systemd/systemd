/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <string.h>

#include "bootspec.h"
#include "env-util.h"
#include "escape.h"
#include "fuzz.h"
#include "fd-util.h"
#include "json.h"

static int json_dispatch_config(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        BootConfig *config = ASSERT_PTR(userdata);

        const char *s = json_variant_string(variant);
        if (!s)
                return -EINVAL;

        _cleanup_fclose_ FILE *f = NULL;
        assert_se(f = data_to_file((const uint8_t*) s, strlen(s)));

        (void) boot_loader_read_conf(config, f, "memstream");
        return 0;
}

static int json_dispatch_entries(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        BootConfig *config = ASSERT_PTR(userdata);
        JsonVariant *entry;

        JSON_VARIANT_ARRAY_FOREACH(entry, variant) {
                if (!json_variant_is_array(entry) ||
                    json_variant_elements(entry) < 1)
                        return -EINVAL;

                JsonVariant *v;
                const char *id = NULL, *raw = NULL;
                _cleanup_free_ char *data = NULL;
                ssize_t len = -ENODATA;

                v = json_variant_by_index(entry, 0);
                if (v)
                        id = json_variant_string(v);
                if (!id)
                        continue;

                v = json_variant_by_index(entry, 1);
                if (v)
                        raw = json_variant_string(v);
                if (raw)
                        len = cunescape(raw, UNESCAPE_RELAX | UNESCAPE_ACCEPT_NUL, &data);
                if (len >= 0) {
                        _cleanup_fclose_ FILE *f = NULL;
                        assert_se(f = data_to_file((const uint8_t*) data, len));

                        assert_se(boot_config_load_type1(config, f, "/", "/entries", id) != -ENOMEM);
                }
        }

        return 0;
}

static int json_dispatch_loader(const char *name, JsonVariant *variant, JsonDispatchFlags flags, void *userdata) {
        BootConfig *config = ASSERT_PTR(userdata);
        _cleanup_strv_free_ char **entries = NULL;
        int r;

        r = json_dispatch_strv(name, variant, flags, &entries);
        if (r < 0)
                return r;

        (void) boot_config_augment_from_loader(config, entries, false);
        return 0;
}

static const JsonDispatch data_dispatch[] = {
        { "config",  JSON_VARIANT_STRING, json_dispatch_config,  0, 0 },
        { "entries", JSON_VARIANT_ARRAY,  json_dispatch_entries, 0, 0 },
        { "loader",  JSON_VARIANT_ARRAY,  json_dispatch_loader,  0, 0 },
        {}
};

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
        _cleanup_free_ const char *datadup = NULL;
        _cleanup_(boot_config_free) BootConfig config = BOOT_CONFIG_NULL;
        int r;

        if (outside_size_range(size, 0, 65536))
                return 0;

        /* Disable most logging if not running standalone */
        if (!getenv("SYSTEMD_LOG_LEVEL"))
                log_set_max_level(LOG_CRIT);

        assert_se(datadup = memdup_suffix0(data, size));

        _cleanup_(json_variant_unrefp) JsonVariant *v = NULL;
        r = json_parse(datadup, 0, &v, NULL, NULL);
        if (r < 0)
                return 0;

        r = json_dispatch(v, data_dispatch, NULL, 0, &config);
        if (r < 0)
                return 0;

        assert_se(boot_config_finalize(&config) >= 0);

        (void) boot_config_select_special_entries(&config, /* skip_efivars= */ false);

        _cleanup_close_ int orig_stdout_fd = -1;
        if (getenv_bool("SYSTEMD_FUZZ_OUTPUT") <= 0) {
                orig_stdout_fd = fcntl(fileno(stdout), F_DUPFD_CLOEXEC, 3);
                if (orig_stdout_fd < 0)
                        log_warning_errno(orig_stdout_fd, "Failed to duplicate fd 1: %m");
                else
                        assert_se(freopen("/dev/null", "w", stdout));
        }

        (void) show_boot_entries(&config, JSON_FORMAT_OFF);
        (void) show_boot_entries(&config, JSON_FORMAT_PRETTY);

        if (orig_stdout_fd >= 0)
                assert_se(freopen(FORMAT_PROC_FD_PATH(orig_stdout_fd), "w", stdout));

        return 0;
}
