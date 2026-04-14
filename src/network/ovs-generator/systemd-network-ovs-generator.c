/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "alloc-util.h"
#include "conf-files.h"
#include "dropin.h"
#include "fd-util.h"
#include "fileio.h"
#include "generator.h"
#include "initrd-util.h"
#include "log.h"
#include "network-util.h"
#include "path-util.h"
#include "string-util.h"
#include "strv.h"

/* systemd-network-ovs-generator:
 *
 * If any .netdev file declares Kind=ovs-bridge/ovs-port/ovs-tunnel, or any
 * .network file uses [Network] OVSBridge= / OVSBond=, emit drop-ins ordering
 * systemd-networkd.service and systemd-networkd-wait-online.service after
 * openvswitch.service. Wants= is soft (no-op when openvswitch.service isn't
 * installed).
 */

/* Returns true if line (already stripped of leading whitespace and comments)
 * has the form "<key>=<value>" where <key> matches key (case-sensitive, mirroring
 * systemd's INI parser) and value starts with value_prefix (case-sensitive),
 * optional whitespace around '='. */
static bool line_matches_kv(const char *line, const char *key, const char *value_prefix) {
        const char *p;
        size_t key_len;

        assert(line);
        assert(key);

        key_len = strlen(key);
        /* Match systemd's INI parser: case-sensitive key compare. */
        if (strncmp(line, key, key_len) != 0)
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
                 * is a config error, not OVS usage; don't trigger ordering.
                 * Lines come from read_stripped_line() so trailing whitespace
                 * (incl. \n/\r) is already removed. */
                return *p != '\0';
        }

        return strncmp(p, value_prefix, strlen(value_prefix)) == 0;
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

                r = read_stripped_line(f, LONG_LINE_MAX, &line);
                if (r < 0)
                        return r;
                if (r == 0)
                        break;
                if (isempty(line) || *line == '#' || *line == ';')
                        continue;

                for (size_t i = 0; kvs[i][0]; i++)
                        if (line_matches_kv(line, kvs[i][0], kvs[i][1]))
                                return 1;
        }

        return 0;
}

/* Scan every <suffix> file networkd would load — conf_files_list_strv() returns the merged,
 * mask-filtered, sorted set across NETWORK_DIRS — plus each file's <name><suffix>.d drop-ins,
 * for any of the kv pairs. Returns 1 on the first match. */
static int scan_suffix_for_kv(const char *suffix, const char *const (*kvs)[2]) {
        _cleanup_strv_free_ char **files = NULL;
        int r;

        assert(suffix);
        assert(kvs);

        r = conf_files_list_strv(&files, suffix, /* root= */ NULL,
                                 CONF_FILES_REGULAR | CONF_FILES_FILTER_MASKED, NETWORK_DIRS);
        if (r < 0)
                return r;

        STRV_FOREACH(f, files) {
                _cleanup_strv_free_ char **dropins = NULL;
                _cleanup_free_ char *fn = NULL, *dropin_dirname = NULL;

                r = file_has_kv(*f, kvs);
                if (r < 0)
                        log_debug_errno(r, "Failed to scan '%s', ignoring: %m", *f);
                else if (r > 0)
                        return 1;

                /* Also scan the file's drop-in .conf snippets under <name><suffix>.d, merged across NETWORK_DIRS. */
                r = path_extract_filename(*f, &fn);
                if (r < 0)
                        return r;

                dropin_dirname = strjoin(fn, ".d");
                if (!dropin_dirname)
                        return log_oom();

                r = conf_files_list_dropins(&dropins, dropin_dirname, /* root= */ NULL,
                                            /* root_fd= */ XAT_FDROOT, CONF_FILES_REGULAR, NETWORK_DIRS);
                if (r < 0) {
                        log_debug_errno(r, "Failed to list drop-ins for '%s', ignoring: %m", *f);
                        continue;
                }

                STRV_FOREACH(d, dropins) {
                        r = file_has_kv(*d, kvs);
                        if (r < 0)
                                log_debug_errno(r, "Failed to scan drop-in '%s', ignoring: %m", *d);
                        else if (r > 0)
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

        r = scan_suffix_for_kv(".netdev", netdev_kvs);
        if (r != 0)
                return r;

        return scan_suffix_for_kv(".network", network_kvs);
}

static int run(const char *dest, const char *dest_early, const char *dest_late) {
        int r;

        /* Use the normal generator directory: drop-ins are ordering hints only
         * and should not override admin-provided configuration in dest_late. */
        assert(dest);

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

        /* systemd-networkd talks to ovsdb-server over /run/openvswitch/db.sock as the
         * unprivileged "systemd-network" user. Pull in systemd-networkd-ovsdb-acl.path,
         * which watches for the socket and grants that user access to it via an ACL once
         * ovsdb-server creates it. Pulling it from here keeps the watcher inert on systems
         * that do not use OVS. */
        r = write_drop_in_format(dest, "systemd-networkd.service", 50, "ovs",
                                 "# Automatically generated by systemd-network-ovs-generator\n"
                                 "\n"
                                 "[Unit]\n"
                                 "After=%s\n"
                                 "Wants=%s\n"
                                 "Wants=systemd-networkd-ovsdb-acl.path\n",
                                 OPENVSWITCH_SERVICE_NAMES,
                                 OPENVSWITCH_SERVICE_NAMES);
        if (r < 0)
                return log_error_errno(r, "Failed to write networkd.service drop-in: %m");

        r = write_drop_in_format(dest, "systemd-networkd-wait-online.service", 50, "ovs",
                                 "# Automatically generated by systemd-network-ovs-generator\n"
                                 "\n"
                                 "[Unit]\n"
                                 "After=%s\n",
                                 OPENVSWITCH_SERVICE_NAMES);
        if (r < 0)
                return log_error_errno(r, "Failed to write networkd-wait-online.service drop-in: %m");

        return 0;
}

DEFINE_MAIN_GENERATOR_FUNCTION(run);
