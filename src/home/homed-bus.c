/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "fd-util.h"
#include "home-util.h"
#include "homed-bus.h"
#include "stat-util.h"
#include "strv.h"

int bus_message_read_secret(sd_bus_message *m, UserRecord **ret, sd_bus_error *error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL, *full = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        unsigned line = 0, column = 0;
        const char *json;
        int r;

        assert(ret);

        r = sd_bus_message_read(m, "s", &json);
        if (r < 0)
                return r;

        r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse JSON secret record at %u:%u: %m", line, column);

        r = sd_json_buildo(&full, SD_JSON_BUILD_PAIR("secret", SD_JSON_BUILD_VARIANT(v)));
        if (r < 0)
                return r;

        hr = user_record_new();
        if (!hr)
                return -ENOMEM;

        r = user_record_load(hr, full, USER_RECORD_REQUIRE_SECRET|USER_RECORD_PERMISSIVE);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(hr);
        return 0;
}

int bus_message_read_home_record(sd_bus_message *m, UserRecordLoadFlags flags, UserRecord **ret, sd_bus_error *error) {
        _cleanup_(sd_json_variant_unrefp) sd_json_variant *v = NULL;
        _cleanup_(user_record_unrefp) UserRecord *hr = NULL;
        unsigned line = 0, column = 0;
        const char *json;
        int r;

        assert(ret);

        r = sd_bus_message_read(m, "s", &json);
        if (r < 0)
                return r;

        r = sd_json_parse(json, SD_JSON_PARSE_SENSITIVE, &v, &line, &column);
        if (r < 0)
                return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Failed to parse JSON identity record at %u:%u: %m", line, column);

        hr = user_record_new();
        if (!hr)
                return -ENOMEM;

        r = user_record_load(hr, v, flags);
        if (r < 0)
                return sd_bus_error_set(error, SD_BUS_ERROR_INVALID_ARGS, "JSON data is not a valid identity record");

        *ret = TAKE_PTR(hr);
        return 0;
}

int bus_message_read_blobs(sd_bus_message *m, Hashmap **ret, sd_bus_error *error) {
        _cleanup_hashmap_free_ Hashmap *blobs = NULL;
        int r;

        assert(m);
        assert(ret);

        /* We want to differentiate between blobs being NULL (not passed at all)
         * and empty (passed from dbus, but it was empty) */
        r = hashmap_ensure_allocated(&blobs, &blob_fd_hash_ops);
        if (r < 0)
                return r;

        r = sd_bus_message_enter_container(m, 'a', "{sh}");
        if (r < 0)
                return r;

        for (;;) {
                _cleanup_free_ char *filename = NULL;
                _cleanup_close_ int fd = -EBADF;
                const char *_filename = NULL;
                int _fd;

                r = sd_bus_message_read(m, "{sh}", &_filename, &_fd);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;

                filename = strdup(_filename);
                if (!filename)
                        return -ENOMEM;

                fd = fcntl(_fd, F_DUPFD_CLOEXEC, 3);
                if (fd < 0)
                        return -errno;

                r = suitable_blob_filename(filename);
                if (r < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "Invalid blob directory filename: %s", filename);

                r = fd_verify_regular(fd);
                if (r < 0)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS, "FD for '%s' is not a regular file", filename);

                r = fd_verify_safe_flags(fd);
                if (r == -EREMOTEIO)
                        return sd_bus_error_setf(error, SD_BUS_ERROR_INVALID_ARGS,
                                                 "FD for '%s' has unexpected flags set", filename);
                if (r < 0)
                        return r;

                r = hashmap_put(blobs, filename, FD_TO_PTR(fd));
                if (r < 0)
                        return r;
                TAKE_PTR(filename); /* Ownership transferred to hashmap */
                TAKE_FD(fd);
        }

        r = sd_bus_message_exit_container(m);
        if (r < 0)
                return r;

        *ret = TAKE_PTR(blobs);
        return 0;
}
