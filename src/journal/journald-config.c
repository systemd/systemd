/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "conf-parser.h"
#include "creds-util.h"
#include "daemon-util.h"
#include "journald-config.h"
#include "journald-manager.h"
#include "journald-kmsg.h"
#include "log.h"
#include "parse-util.h"
#include "proc-cmdline.h"
#include "socket-netlink.h"
#include "string-table.h"
#include "string-util.h"
#include "syslog-util.h"
#include "time-util.h"

#define DEFAULT_SYNC_INTERVAL_USEC  (5*USEC_PER_MINUTE)
#define DEFAULT_RATE_LIMIT_INTERVAL (30*USEC_PER_SEC)
#define DEFAULT_RATE_LIMIT_BURST    10000
#define DEFAULT_MAX_FILE_USEC       USEC_PER_MONTH

/* Pick a good default that is likely to fit into AF_UNIX and AF_INET SOCK_DGRAM datagrams, and even leaves some room
 * for a bit of additional metadata. */
#define DEFAULT_LINE_MAX            (48*1024)

#define JOURNAL_CONFIG_INIT                                                                     \
        (JournalConfig) {                                                                       \
                .forward_to_socket = (SocketAddress) { .sockaddr.sa.sa_family = AF_UNSPEC },    \
                .storage = _STORAGE_INVALID,                                                    \
                .max_level_store = -1,                                                          \
                .max_level_syslog = -1,                                                         \
                .max_level_kmsg = -1,                                                           \
                .max_level_console = -1,                                                        \
                .max_level_wall = -1,                                                           \
                .max_level_socket = -1,                                                         \
        }

static void manager_set_defaults(Manager *m) {
        assert(m);

        m->compress.enabled = true;
        m->compress.threshold_bytes = UINT64_MAX;

        m->seal = true;

        /* By default, only read from /dev/kmsg if are the main namespace */
        m->read_kmsg = !m->namespace;

        /* By default, kernel auditing is enabled by the main namespace instance, and not controlled by
         * non-default namespace instances. */
        m->set_audit = m->namespace ? -1 : true;

        m->sync_interval_usec = DEFAULT_SYNC_INTERVAL_USEC;

        m->ratelimit_interval = DEFAULT_RATE_LIMIT_INTERVAL;
        m->ratelimit_burst = DEFAULT_RATE_LIMIT_BURST;

        m->system_storage.name = "System Journal";
        journal_reset_metrics(&m->system_storage.metrics);

        m->runtime_storage.name = "Runtime Journal";
        journal_reset_metrics(&m->runtime_storage.metrics);

        m->max_file_usec = DEFAULT_MAX_FILE_USEC;

        m->config.forward_to_wall = true;

        m->config.max_level_store = LOG_DEBUG;
        m->config.max_level_syslog = LOG_DEBUG;
        m->config.max_level_kmsg = LOG_NOTICE;
        m->config.max_level_console = LOG_INFO;
        m->config.max_level_wall = LOG_EMERG;
        m->config.max_level_socket = LOG_DEBUG;

        m->line_max = DEFAULT_LINE_MAX;
}

static void manager_reset_configs(Manager *m) {
        assert(m);

        m->config_by_cmdline = JOURNAL_CONFIG_INIT;
        m->config_by_conf = JOURNAL_CONFIG_INIT;
        m->config_by_cred = JOURNAL_CONFIG_INIT;
}

static void manager_merge_forward_to_socket(Manager *m) {
        assert(m);

        /* Conf file takes precedence over credentials. */
        if (m->config_by_conf.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC)
                m->config.forward_to_socket = m->config_by_conf.forward_to_socket;
        else if (m->config_by_cred.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC)
                m->config.forward_to_socket = m->config_by_cred.forward_to_socket;
        else
                m->config.forward_to_socket = (SocketAddress) { .sockaddr.sa.sa_family = AF_UNSPEC };
}

static void manager_merge_storage(Manager *m) {
        assert(m);

        /* Conf file takes precedence over credentials. */
        if (m->config_by_conf.storage != _STORAGE_INVALID)
                m->config.storage = m->config_by_conf.storage;
        else if (m->config_by_cred.storage != _STORAGE_INVALID)
                m->config.storage = m->config_by_cred.storage;
        else
                m->config.storage = m->namespace ? STORAGE_PERSISTENT : STORAGE_AUTO;
}

#define MERGE_BOOL(name, default_value)                                                 \
    (m->config.name = (m->config_by_cmdline.name  ? m->config_by_cmdline.name :         \
                       m->config_by_conf.name     ? m->config_by_conf.name     :        \
                       m->config_by_cred.name     ? m->config_by_cred.name     :        \
                       default_value))

#define MERGE_NON_NEGATIVE(name, default_value)                                         \
        (m->config.name = (m->config_by_cmdline.name >= 0 ? m->config_by_cmdline.name : \
                           m->config_by_conf.name >= 0    ? m->config_by_conf.name :    \
                           m->config_by_cred.name >= 0    ? m->config_by_cred.name :    \
                           default_value))

static void manager_merge_configs(Manager *m) {
        assert(m);

        /*
         * From highest to lowest priority: cmdline, conf, cred
         */
        manager_merge_storage(m);
        manager_merge_forward_to_socket(m);

        MERGE_BOOL(forward_to_syslog, false);
        MERGE_BOOL(forward_to_kmsg, false);
        MERGE_BOOL(forward_to_console, false);
        MERGE_BOOL(forward_to_wall, true);

        MERGE_NON_NEGATIVE(max_level_store, LOG_DEBUG);
        MERGE_NON_NEGATIVE(max_level_syslog, LOG_DEBUG);
        MERGE_NON_NEGATIVE(max_level_kmsg, LOG_NOTICE);
        MERGE_NON_NEGATIVE(max_level_console, LOG_INFO);
        MERGE_NON_NEGATIVE(max_level_wall, LOG_EMERG);
        MERGE_NON_NEGATIVE(max_level_socket, LOG_DEBUG);
}

static void manager_adjust_configs(Manager *m) {
        assert(m);

        if (!!m->ratelimit_interval != !!m->ratelimit_burst) { /* One set to 0 and the other not? */
                log_debug("Setting both rate limit interval and burst from %s/%u to 0/0",
                          FORMAT_TIMESPAN(m->ratelimit_interval, USEC_PER_SEC),
                          m->ratelimit_burst);
                m->ratelimit_interval = m->ratelimit_burst = 0;
        }
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        Manager *m = ASSERT_PTR(data);
        int r;

        if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_syslog")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to syslog switch \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.forward_to_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_kmsg")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to kmsg switch \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.forward_to_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_console")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to console switch \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.forward_to_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_wall")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to wall switch \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.forward_to_wall = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_console")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level console value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_store")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level store value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_store = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_syslog")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level syslog value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_kmsg")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level kmsg value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_wall")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level wall value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_wall = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_socket")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level socket value \"%s\". Ignoring.", value);
                else
                        m->config_by_cmdline.max_level_socket = r;

        } else if (startswith(key, "systemd.journald"))
                log_warning("Unknown journald kernel command line option \"%s\". Ignoring.", key);

        /* do not warn about state here, since probably systemd already did */
        return 0;
}

static void manager_parse_config_file(Manager *m) {
        const char *conf_file;

        assert(m);

        if (m->namespace)
                conf_file = strjoina("systemd/journald@", m->namespace, ".conf");
        else
                conf_file = "systemd/journald.conf";

        (void) config_parse_standard_file_with_dropins(
                        conf_file,
                        "Journal\0",
                        config_item_perf_lookup,
                        journald_gperf_lookup,
                        CONFIG_PARSE_WARN,
                        m);
}

static void manager_load_credentials(Manager *m) {
        _cleanup_free_ void *data = NULL;
        int r;

        assert(m);

        r = read_credential("journal.forward_to_socket", &data, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential journal.forward_to_socket, ignoring: %m");
        else {
                r = socket_address_parse(&m->config_by_cred.forward_to_socket, data);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse socket address '%s' from credential journal.forward_to_socket, ignoring: %m", (char *) data);
        }

        data = mfree(data);

        r = read_credential("journal.storage", &data, NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential journal.storage, ignoring: %m");
        else {
                r = storage_from_string(data);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse storage '%s' from credential journal.storage, ignoring: %m", (char *) data);
                else
                        m->config_by_cred.storage = r;
        }
}

void manager_load_config(Manager *m) {
        int r;

        assert(m);

        manager_set_defaults(m);
        manager_reset_configs(m);

        manager_load_credentials(m);
        manager_parse_config_file(m);

        if (!m->namespace) {
                /* Parse kernel command line, but only if we are not a namespace instance */
                r = proc_cmdline_parse(parse_proc_cmdline_item, m, PROC_CMDLINE_STRIP_RD_PREFIX);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        manager_merge_configs(m);

        manager_adjust_configs(m);
}

static void manager_reload_config(Manager *m) {
        assert(m);

        manager_set_defaults(m);

        m->config_by_conf = JOURNAL_CONFIG_INIT;
        manager_parse_config_file(m);

        manager_merge_configs(m);
        manager_adjust_configs(m);
}

JournalFileFlags manager_get_file_flags(Manager *m, bool seal) {
        return (m->compress.enabled ? JOURNAL_COMPRESS : 0) |
                (seal ? JOURNAL_SEAL : 0) |
                JOURNAL_STRICT_ORDER;
}

static int manager_reload_journals(Manager *m) {
        assert(m);

        int r;

        if (m->system_journal && IN_SET(m->config.storage, STORAGE_PERSISTENT, STORAGE_AUTO)) {
                /* Current journal can continue being used. Update config values as needed. */
                r = journal_file_reload(
                                m->system_journal,
                                manager_get_file_flags(m, m->seal),
                                m->compress.threshold_bytes,
                                &m->system_storage.metrics);
                if (r < 0)
                        return log_warning_errno(r, "Failed to reload system journal on reload, ignoring: %m");
        } else if (m->system_journal && m->config.storage == STORAGE_VOLATILE) {
                /* Journal needs to be switched from system to runtime. */
                r = manager_relinquish_var(m);
                if (r < 0)
                        return log_warning_errno(r, "Failed to relinquish to runtime journal on reload, ignoring: %m");
        } else if (m->runtime_journal && IN_SET(m->config.storage, STORAGE_PERSISTENT, STORAGE_AUTO, STORAGE_VOLATILE)) {
                /* Current journal can continue being used. Update config values as needed.*/
                r = journal_file_reload(
                                m->runtime_journal,
                                manager_get_file_flags(m, /* seal */ false),
                                m->compress.threshold_bytes,
                                &m->runtime_storage.metrics);
                if (r < 0)
                        return log_warning_errno(r, "Failed to reload runtime journal on reload, ignoring: %m");
        }

        /* If journal-related configuration, such as SystemMaxUse, SystemMaxFileSize, RuntimeMaxUse, RuntimeMaxFileSize,
         * were to change, then we can vacuum for the change to take effect. For example, if pre-reload SystemMaxUse=2M,
         * current usage=1.5M, and the post-reload SystemMaxUse=1M, the vacuum can shrink it to 1M.
         */
        manager_vacuum(m, /* verbose */ false);

        return 0;
}

int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);
        int r;

        (void) notify_reloading();

        manager_reload_config(m);

        r = manager_reload_dev_kmsg(m);
        if (r < 0)
                return r;

        r = manager_reload_journals(m);
        if (r < 0)
                return r;

        log_info("Config file reloaded.");
        (void) sd_notify(/* unset_environment */ false, NOTIFY_READY_MESSAGE);

        return 0;
}

static const char* const storage_table[_STORAGE_MAX] = {
        [STORAGE_AUTO]       = "auto",
        [STORAGE_VOLATILE]   = "volatile",
        [STORAGE_PERSISTENT] = "persistent",
        [STORAGE_NONE]       = "none"
};

DEFINE_STRING_TABLE_LOOKUP(storage, Storage);
DEFINE_CONFIG_PARSE_ENUM(config_parse_storage, storage, Storage);

static const char* const split_mode_table[_SPLIT_MAX] = {
        [SPLIT_LOGIN] = "login",
        [SPLIT_UID]   = "uid",
        [SPLIT_NONE]  = "none",
};

DEFINE_STRING_TABLE_LOOKUP(split_mode, SplitMode);
DEFINE_CONFIG_PARSE_ENUM(config_parse_split_mode, split_mode, SplitMode);

int config_parse_line_max(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        size_t *sz = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        if (isempty(rvalue))
                /* Empty assignment means default */
                *sz = DEFAULT_LINE_MAX;
        else {
                uint64_t v;

                r = parse_size(rvalue, 1024, &v);
                if (r < 0) {
                        log_syntax(unit, LOG_WARNING, filename, line, r, "Failed to parse LineMax= value, ignoring: %s", rvalue);
                        return 0;
                }

                if (v < 79) {
                        /* Why specify 79 here as minimum line length? Simply, because the most common traditional
                         * terminal size is 80ch, and it might make sense to break one character before the natural
                         * line break would occur on that. */
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "LineMax= too small, clamping to 79: %s", rvalue);
                        *sz = 79;
                } else if (v > (uint64_t) (SSIZE_MAX-1)) {
                        /* So, why specify SSIZE_MAX-1 here? Because that's one below the largest size value read()
                         * can return, and we need one extra byte for the trailing NUL byte. Of course IRL such large
                         * memory allocations will fail anyway, hence this limit is mostly theoretical anyway, as we'll
                         * fail much earlier anyway. */
                        log_syntax(unit, LOG_WARNING, filename, line, 0, "LineMax= too large, clamping to %" PRIu64 ": %s", (uint64_t) (SSIZE_MAX-1), rvalue);
                        *sz = SSIZE_MAX-1;
                } else
                        *sz = (size_t) v;
        }

        return 0;
}

int config_parse_compress(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        JournalCompressOptions* compress = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(rvalue);

        if (isempty(rvalue)) {
                compress->enabled = true;
                compress->threshold_bytes = UINT64_MAX;
        } else if (streq(rvalue, "1")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 1, enabling compression with default threshold");
                compress->enabled = true;
        } else if (streq(rvalue, "0")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 0, disabling compression");
                compress->enabled = false;
        } else {
                r = parse_boolean(rvalue);
                if (r < 0) {
                        r = parse_size(rvalue, 1024, &compress->threshold_bytes);
                        if (r < 0)
                                log_syntax(unit, LOG_WARNING, filename, line, r,
                                           "Failed to parse Compress= value, ignoring: %s", rvalue);
                        else
                                compress->enabled = true;
                } else
                        compress->enabled = r;
        }

        return 0;
}

int config_parse_forward_to_socket(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        SocketAddress* addr = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(rvalue);

        if (isempty(rvalue))
                *addr = (SocketAddress) { .sockaddr.sa.sa_family = AF_UNSPEC };
        else {
                r = socket_address_parse(addr, rvalue);
                if (r < 0)
                        log_syntax(unit, LOG_WARNING, filename, line, r,
                                   "Failed to parse ForwardToSocket= value, ignoring: %s", rvalue);
        }

        return 0;
}
