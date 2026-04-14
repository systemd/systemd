/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

#include "alloc-util.h"
#include "dirent-util.h"
#include "dropin.h"
#include "extract-word.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "macro.h"
#include "path-util.h"
#include "string-util.h"

/* systemd-network-ovs-generator:
 *
 * If any .netdev file declares Kind=ovs-bridge/ovs-port/ovs-tunnel, or any
 * .network file uses [Network] OVSBridge= / OVSBond=, emit drop-ins ordering
 * systemd-networkd.service and systemd-networkd-wait-online.service after
 * openvswitch.service. Wants= is soft (no-op when openvswitch.service isn't
 * installed).
 */

static const char *arg_dest = NULL;

static const char * const network_dirs[] = {
        "/etc/systemd/network",
        "/run/systemd/network",
        "/usr/lib/systemd/network",
        NULL,
};

/* Returns true if line (already stripped of leading whitespace and comments)
 * has the form "<key>=<value>" where <key> matches key (case-insensitive)
 * and value starts with value_prefix (case-insensitive), optional whitespace
 * around '='. */
static bool line_matches_kv(const char *line, const char *key, const char *value_prefix) {
        const char *p;
        size_t key_len;

        assert(line);
        assert(key);

        key_len = strlen(key);
        if (strncasecmp(line, key, key_len) != 0)
                return false;

        p = line + key_len;
        while (*p == ' ' || *p == '\t')
                p++;

        if (*p != '=')
                return false;

        p++;
        while (*p == ' ' || *p == '\t')
                p++;

        if (!value_prefix) {
                /* Match any non-empty value: "OVSBridge=" without a value
                 * is a config error, not OVS usage; don't trigger ordering. */
                return *p != '\0' && *p != '\n' && *p != '\r';
        }

        return strncasecmp(p, value_prefix, strlen(value_prefix)) == 0;
}

/* Scan one file for any line matching any of the key/value_prefix pairs.
 * kvs is a NULL-terminated array of {key, value_prefix} pairs;
 * value_prefix may be NULL to match any value. */
static int file_has_kv(const char *path, const char *const (*kvs)[2]) {
        _cleanup_fclose_ FILE *f = NULL;
        int r;

        assert(path);
        assert(kvs);

        f = fopen(path, "re");
        if (!f)
                return errno == ENOENT ? 0 : -errno;

        for (;;) {
                _cleanup_free_ char *line = NULL;
                const char *p;

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                if (isempty(line) || *line == '#' || *line == ';')
                        continue;

                p = line;
                for (size_t i = 0; kvs[i][0]; i++)
                        if (line_matches_kv(p, kvs[i][0], kvs[i][1]))
                                return 1;
        }

        return 0;
}

/* Scan .conf drop-in files inside a *.netdev.d or *.network.d directory */
static int dropin_dir_has_kv(const char *dir, const char *const (*kvs)[2]) {
        _cleanup_closedir_ DIR *d = NULL;
        int r;

        assert(dir);

        d = opendir(dir);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                _cleanup_free_ char *path = NULL;

                if (de->d_name[0] == '.')
                        continue;
                if (!endswith(de->d_name, ".conf"))
                        continue;

                path = path_join(dir, de->d_name);
                if (!path)
                        return log_oom();

                r = file_has_kv(path, kvs);
                if (r < 0) {
                        log_debug_errno(r, "Failed to scan '%s', ignoring: %m", path);
                        continue;
                }
                if (r > 0)
                        return 1;
        }

        return 0;
}

/* Scan all files in the given dir with the given suffix for any of the kv pairs.
 * Also scans matching *.<suffix>.d/*.conf drop-in directories. */
static int dir_has_kv_in_suffix(const char *dir, const char *suffix, const char *const (*kvs)[2]) {
        _cleanup_closedir_ DIR *d = NULL;
        _cleanup_free_ char *dropin_suffix = NULL;
        int r;

        assert(dir);
        assert(suffix);

        dropin_suffix = strjoin(suffix, ".d");
        if (!dropin_suffix)
                return log_oom();

        d = opendir(dir);
        if (!d)
                return errno == ENOENT ? 0 : -errno;

        FOREACH_DIRENT_ALL(de, d, return -errno) {
                _cleanup_free_ char *path = NULL;

                if (de->d_name[0] == '.')
                        continue;

                path = path_join(dir, de->d_name);
                if (!path)
                        return log_oom();

                /* Direct .netdev / .network file */
                if (endswith(de->d_name, suffix)) {
                        r = file_has_kv(path, kvs);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to scan '%s', ignoring: %m", path);
                                continue;
                        }
                        if (r > 0)
                                return 1;
                        continue;
                }

                /* Drop-in directory: foo.netdev.d/ or foo.network.d/ */
                if (endswith(de->d_name, dropin_suffix)) {
                        r = dropin_dir_has_kv(path, kvs);
                        if (r < 0) {
                                log_debug_errno(r, "Failed to scan drop-in dir '%s', ignoring: %m", path);
                                continue;
                        }
                        if (r > 0)
                                return 1;
                }
        }

        return 0;
}

static int detect_ovs_usage(void) {
        /* .netdev keys: Kind=ovs-{bridge,port,tunnel} — match "Kind=ovs-" prefix */
        static const char *const netdev_kvs[][2] = {
                { "Kind", "ovs-" },
                { NULL, NULL },
        };

        /* .network keys: OVSBridge= or OVSBond= (any non-empty value) */
        static const char *const network_kvs[][2] = {
                { "OVSBridge", NULL },
                { "OVSBond",   NULL },
                { NULL,        NULL },
        };

        int r;

        for (size_t i = 0; network_dirs[i]; i++) {
                r = dir_has_kv_in_suffix(network_dirs[i], ".netdev", netdev_kvs);
                if (r < 0)
                        log_debug_errno(r, "Failed to scan '%s' for .netdev, continuing: %m", network_dirs[i]);
                if (r > 0)
                        return 1;

                r = dir_has_kv_in_suffix(network_dirs[i], ".network", network_kvs);
                if (r < 0)
                        log_debug_errno(r, "Failed to scan '%s' for .network, continuing: %m", network_dirs[i]);
                if (r > 0)
                        return 1;
        }

        return 0;
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        /* Use the normal generator directory: drop-ins are ordering hints only
         * and should not override admin-provided configuration in dest_late. */
        arg_dest = ASSERT_PTR(dest);

        /* Skip in initrd: openvswitch.service typically isn't present there,
         * and ordering against a non-existent unit is meaningless. */
        if (in_initrd()) {
                log_debug("Running in initrd, skipping OVS service ordering generator.");
                return 0;
        }

        r = detect_ovs_usage();
        if (r < 0)
                return log_error_errno(r, "Failed to detect OVS usage: %m");
        if (r == 0) {
                log_debug("No OVS configuration found, nothing to do.");
                return 0;
        }

        log_debug("OVS configuration detected, emitting ordering drop-ins against %s.",
                  OPENVSWITCH_SERVICE_NAMES);

        r = write_drop_in_format(arg_dest, "systemd-networkd.service", 10, "ovs",
                                 "# Automatically generated by systemd-network-ovs-generator\n"
                                 "#\n"
                                 "# SourcePath=/etc/systemd/network\n"
                                 "\n"
                                 "[Unit]\n"
                                 "After=%s\n"
                                 "Wants=%s\n",
                                 OPENVSWITCH_SERVICE_NAMES,
                                 OPENVSWITCH_SERVICE_NAMES);
        if (r < 0)
                return log_error_errno(r, "Failed to write networkd.service drop-in: %m");

        r = write_drop_in_format(arg_dest, "systemd-networkd-wait-online.service", 10, "ovs",
                                 "# Automatically generated by systemd-network-ovs-generator\n"
                                 "#\n"
                                 "# SourcePath=/etc/systemd/network\n"
                                 "\n"
                                 "[Unit]\n"
                                 "After=%s\n",
                                 OPENVSWITCH_SERVICE_NAMES);
        if (r < 0)
                return log_error_errno(r, "Failed to write networkd-wait-online.service drop-in: %m");

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
