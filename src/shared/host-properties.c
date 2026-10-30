/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "chase.h"
#include "env-file.h"
#include "fd-util.h"
#include "hostname-setup.h"
#include "hostname-util.h"
#include "id128-util.h"
#include "log.h"
#include "os-util.h"
#include "string-util.h"
#include "strv.h"
#include "host-properties.h"

void host_properties_done(HostProperties *h) {
        assert(h);

        h->hostname = mfree(h->hostname);
        h->machine_id = SD_ID128_NULL;
        h->machine_tags = strv_free(h->machine_tags);
        h->os_id = mfree(h->os_id);
        h->os_version_id = mfree(h->os_version_id);
        h->image_id = mfree(h->image_id);
        h->image_version = mfree(h->image_version);
        h->loaded = false;
}

static int load_hostname(const char *root, char **ret) {
        int r;

        assert(ret);

        if (!root) {
                /* For the host itself, use the hostname currently in effect */
                r = gethostname_full(GET_HOSTNAME_ALLOW_LOCALHOST, ret);
                if (r < 0)
                        return log_error_errno(r, "Failed to determine hostname: %m");

                return 0;
        }

        _cleanup_fclose_ FILE *f = NULL;
        r = chase_and_fopen_unlocked("/etc/hostname", root, CHASE_PREFIX_ROOT|CHASE_MUST_BE_REGULAR, "re", /* ret_path= */ NULL, &f);
        if (r == -ENOENT) {
                *ret = NULL;
                return 0;
        }
        if (r < 0)
                return log_error_errno(r, "Failed to open '%s/etc/hostname': %m", root);

        /* Don't substitute wildcards, that would be based on the host's machine ID, not the image's */
        r = read_etc_hostname_stream(f, /* substitute_wildcards= */ false, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to read hostname from '%s/etc/hostname': %m", root);

        return 0;
}

static int load_machine_tags(const char *root, char ***ret) {
        int r;

        assert(ret);

        _cleanup_free_ char *tags = NULL;
        if (root) {
                _cleanup_fclose_ FILE *f = NULL;
                r = chase_and_fopen_unlocked("/etc/machine-info", root, CHASE_PREFIX_ROOT|CHASE_MUST_BE_REGULAR, "re", /* ret_path= */ NULL, &f);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to open '%s/etc/machine-info': %m", root);
                if (f) {
                        r = parse_env_file(f, "/etc/machine-info", "TAGS", &tags);
                        if (r < 0)
                                return log_error_errno(r, "Failed to read '%s/etc/machine-info': %m", root);
                }
        } else {
                r = parse_env_file(/* f= */ NULL, etc_machine_info(), "TAGS", &tags);
                if (r < 0 && r != -ENOENT)
                        return log_error_errno(r, "Failed to read '%s': %m", etc_machine_info());
        }

        /* Silently ignore invalid tags, like ConditionMachineTag= does */
        r = machine_tags_from_string(tags, /* graceful= */ true, ret);
        if (r < 0)
                return log_error_errno(r, "Failed to parse machine tags '%s': %m", tags);

        return 0;
}

int host_properties_load(HostProperties *h, const char *root) {
        _cleanup_(host_properties_done) HostProperties n = HOST_PROPERTIES_NULL;
        int r;

        assert(h);

        if (h->loaded)
                return 0;

        r = load_hostname(root, &n.hostname);
        if (r < 0)
                return r;

        r = id128_get_machine(root, &n.machine_id);
        if (r < 0 && !ERRNO_IS_NEG_MACHINE_ID_UNSET(r))
                return log_error_errno(r, "Failed to read machine ID: %m");

        r = load_machine_tags(root, &n.machine_tags);
        if (r < 0)
                return r;

        r = parse_os_release(
                        root,
                        "ID", &n.os_id,
                        "VERSION_ID", &n.os_version_id,
                        "IMAGE_ID", &n.image_id,
                        "IMAGE_VERSION", &n.image_version);
        if (r < 0 && r != -ENOENT)
                return log_error_errno(r, "Failed to read os-release: %m");

        log_debug("Loaded host properties: hostname=%s machine-id=%s os-id=%s os-version-id=%s image-id=%s image-version=%s",
                  strna(n.hostname),
                  sd_id128_is_null(n.machine_id) ? "n/a" : SD_ID128_TO_STRING(n.machine_id),
                  strna(n.os_id),
                  strna(n.os_version_id),
                  strna(n.image_id),
                  strna(n.image_version));

        n.loaded = true;
        host_properties_done(h);
        *h = TAKE_GENERIC(n, HostProperties, HOST_PROPERTIES_NULL);
        return 0;
}
