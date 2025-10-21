/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "sd-event.h"

#include "conf-parser.h"
#include "creds-util.h"
#include "daemon-util.h"
#include "journald-audit.h"
#include "journald-config.h"
#include "journald-context.h"
#include "journald-kmsg.h"
#include "journald-manager.h"
#include "journald-socket.h"
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

void journal_config_done(JournalConfig *c) {
        assert(c);

        free(c->tty_path);
}

void journal_config_set_defaults(JournalConfig *c) {
        assert(c);

        journal_config_done(c);

        *c = (JournalConfig) {
                .storage = _STORAGE_INVALID,
                .compress.enabled = -1,
                .compress.threshold_bytes = UINT64_MAX,
                .seal = -1,
                .read_kmsg = -1,
                .set_audit = _AUDIT_SET_MODE_INVALID,
                .ratelimit_interval = DEFAULT_RATE_LIMIT_INTERVAL,
                .ratelimit_burst = DEFAULT_RATE_LIMIT_BURST,
                .forward_to_syslog = -1,
                .forward_to_kmsg = -1,
                .forward_to_console = -1,
                .forward_to_wall = -1,
                .max_level_store = -1,
                .max_level_syslog = -1,
                .max_level_kmsg = -1,
                .max_level_console = -1,
                .max_level_wall = -1,
                .max_level_socket = -1,
                .split_mode = _SPLIT_INVALID,
        };

        journal_reset_metrics(&c->system_storage_metrics);
        journal_reset_metrics(&c->runtime_storage_metrics);
}

static void manager_merge_journal_compress_options(Manager *m) {
        assert(m);

        if (m->config_by_cmdline.compress.enabled >= 0)
                m->config.compress = m->config_by_cmdline.compress;
        else if (m->config_by_conf.compress.enabled >= 0)
                m->config.compress = m->config_by_conf.compress;
        else if (m->config_by_cred.compress.enabled >= 0)
                m->config.compress = m->config_by_cred.compress;
        else
                m->config.compress = (JournalCompressOptions) {
                        .enabled = true,
                        .threshold_bytes = UINT64_MAX,
                };
}

static void manager_merge_forward_to_socket(Manager *m) {
        assert(m);

        if (m->config_by_cmdline.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC)
                m->config.forward_to_socket = m->config_by_cmdline.forward_to_socket;
        else if (m->config_by_conf.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC)
                m->config.forward_to_socket = m->config_by_conf.forward_to_socket;
        else if (m->config_by_cred.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC)
                m->config.forward_to_socket = m->config_by_cred.forward_to_socket;
        else
                m->config.forward_to_socket = (SocketAddress) {};
}

#define MERGE_NON_NEGATIVE(name, default_value)                         \
        m->config.name =                                                \
                m->config_by_cmdline.name >= 0 ? m->config_by_cmdline.name : \
                m->config_by_conf.name >= 0 ? m->config_by_conf.name :  \
                m->config_by_cred.name >= 0 ? m->config_by_cred.name :  \
                default_value

#define MERGE_NON_ZERO(name, default_value)                             \
        m->config.name =                                                \
                m->config_by_cmdline.name ?:                            \
                m->config_by_conf.name ?:                               \
                m->config_by_cred.name ?:                               \
                default_value

void manager_merge_configs(Manager *m) {
        assert(m);

        /* From highest to lowest priority: cmdline, conf, cred */

        journal_config_done(&m->config);

        MERGE_NON_NEGATIVE(storage, STORAGE_AUTO);
        manager_merge_journal_compress_options(m);
        MERGE_NON_NEGATIVE(seal, true);
        /* By default, /dev/kmsg is read only by the main namespace instance. */
        MERGE_NON_NEGATIVE(read_kmsg, !m->namespace);
        /* By default, kernel auditing is enabled by the main namespace instance, and not controlled by
         * non-default namespace instances. */
        MERGE_NON_NEGATIVE(set_audit, m->namespace ? AUDIT_KEEP : AUDIT_YES);
        MERGE_NON_ZERO(sync_interval_usec, DEFAULT_SYNC_INTERVAL_USEC);

        /* TODO: also merge them when comdline or credentials support to configure them. */
        m->config.ratelimit_interval = m->config_by_conf.ratelimit_interval;
        m->config.ratelimit_burst = m->config_by_conf.ratelimit_burst;
        m->config.system_storage_metrics = m->config_by_conf.system_storage_metrics;
        m->config.runtime_storage_metrics = m->config_by_conf.runtime_storage_metrics;

        MERGE_NON_ZERO(max_retention_usec, 0);
        MERGE_NON_ZERO(max_file_usec, DEFAULT_MAX_FILE_USEC);
        MERGE_NON_NEGATIVE(forward_to_syslog, false);
        MERGE_NON_NEGATIVE(forward_to_kmsg, false);
        MERGE_NON_NEGATIVE(forward_to_console, false);
        MERGE_NON_NEGATIVE(forward_to_wall, true);
        manager_merge_forward_to_socket(m);

        if (strdup_to(&m->config.tty_path,
                      m->config_by_cmdline.tty_path ?:
                      m->config_by_conf.tty_path ?:
                      m->config_by_cred.tty_path) < 0)
                log_oom_debug();

        MERGE_NON_NEGATIVE(max_level_store, LOG_DEBUG);
        MERGE_NON_NEGATIVE(max_level_syslog, LOG_DEBUG);
        MERGE_NON_NEGATIVE(max_level_kmsg, LOG_NOTICE);
        MERGE_NON_NEGATIVE(max_level_console, LOG_INFO);
        MERGE_NON_NEGATIVE(max_level_wall, LOG_EMERG);
        MERGE_NON_NEGATIVE(max_level_socket, LOG_DEBUG);
        MERGE_NON_NEGATIVE(split_mode, SPLIT_UID);
        MERGE_NON_ZERO(line_max, DEFAULT_LINE_MAX);
}

static void manager_adjust_configs(Manager *m) {
        assert(m);

        if ((m->config.ratelimit_interval == 0) != (m->config.ratelimit_burst == 0)) { /* One set to 0 and the other not? */
                log_debug("Setting both rate limit interval and burst from %s/%u to 0/0",
                          FORMAT_TIMESPAN(m->config.ratelimit_interval, USEC_PER_SEC),
                          m->config.ratelimit_burst);
                m->config.ratelimit_interval = 0;
                m->config.ratelimit_burst = 0;
        }

        /* copy metrics to manager */
        m->system_storage.metrics = m->config.system_storage_metrics;
        m->runtime_storage.metrics = m->config.runtime_storage_metrics;

        if (m->config.forward_to_socket.sockaddr.sa.sa_family != AF_UNSPEC && m->namespace) {
                log_debug("ForwardToSocket= is not supported in non-default namespace instance.");
                m->config.forward_to_socket = (SocketAddress) {};
        }
}

static int parse_proc_cmdline_item(const char *key, const char *value, void *data) {
        JournalConfig *c = ASSERT_PTR(data);
        int r;

        if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_syslog")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to syslog switch \"%s\". Ignoring.", value);
                else
                        c->forward_to_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_kmsg")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to kmsg switch \"%s\". Ignoring.", value);
                else
                        c->forward_to_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_console")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to console switch \"%s\". Ignoring.", value);
                else
                        c->forward_to_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.forward_to_wall")) {

                r = value ? parse_boolean(value) : true;
                if (r < 0)
                        log_warning("Failed to parse forward to wall switch \"%s\". Ignoring.", value);
                else
                        c->forward_to_wall = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_console")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level console value \"%s\". Ignoring.", value);
                else
                        c->max_level_console = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_store")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level store value \"%s\". Ignoring.", value);
                else
                        c->max_level_store = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_syslog")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level syslog value \"%s\". Ignoring.", value);
                else
                        c->max_level_syslog = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_kmsg")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level kmsg value \"%s\". Ignoring.", value);
                else
                        c->max_level_kmsg = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_wall")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level wall value \"%s\". Ignoring.", value);
                else
                        c->max_level_wall = r;

        } else if (proc_cmdline_key_streq(key, "systemd.journald.max_level_socket")) {

                if (proc_cmdline_value_missing(key, value))
                        return 0;

                r = log_level_from_string(value);
                if (r < 0)
                        log_warning("Failed to parse max level socket value \"%s\". Ignoring.", value);
                else
                        c->max_level_socket = r;

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
                        &m->config_by_conf);
}

static void manager_load_credentials(JournalConfig *c) {
        _cleanup_free_ char *data = NULL;
        int r;

        assert(c);

        r = read_credential("journal.forward_to_socket", (void**) &data, /* ret_size = */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential 'journal.forward_to_socket', ignoring: %m");
        else {
                r = socket_address_parse(&c->forward_to_socket, data);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse journal.forward_to_socket credential, ignoring: %s", data);
        }

        data = mfree(data);

        r = read_credential("journal.storage", (void**) &data, /* ret_size = */ NULL);
        if (r < 0)
                log_debug_errno(r, "Failed to read credential journal.storage, ignoring: %m");
        else {
                r = storage_from_string(data);
                if (r < 0)
                        log_debug_errno(r, "Failed to parse journal.storage credential, ignoring: %s", data);
                else
                        c->storage = r;
        }
}

void manager_load_config(Manager *m) {
        int r;

        assert(m);

        manager_load_credentials(&m->config_by_cred);
        manager_parse_config_file(m);

        if (!m->namespace) {
                /* Parse kernel command line, but only if we are not a namespace instance */
                r = proc_cmdline_parse(parse_proc_cmdline_item, &m->config_by_cmdline, PROC_CMDLINE_STRIP_RD_PREFIX);
                if (r < 0)
                        log_warning_errno(r, "Failed to parse kernel command line, ignoring: %m");
        }

        manager_merge_configs(m);
        manager_adjust_configs(m);
}

static void manager_reload_config(Manager *m) {
        assert(m);

        journal_config_set_defaults(&m->config_by_conf);
        manager_parse_config_file(m);
        manager_merge_configs(m);
        manager_adjust_configs(m);
}

int manager_dispatch_reload_signal(sd_event_source *s, const struct signalfd_siginfo *si, void *userdata) {
        Manager *m = ASSERT_PTR(userdata);

        (void) notify_reloading();

        _cleanup_(journal_config_done) JournalConfig old = TAKE_STRUCT(m->config);

        manager_reload_config(m);

        (void) manager_reopen_dev_kmsg(m, old.read_kmsg);
        manager_reset_kernel_audit(m, old.set_audit);
        manager_reload_forward_socket(m, &old.forward_to_socket);
        manager_refresh_client_contexts_on_reload(m, old.ratelimit_interval, old.ratelimit_burst);
        manager_reopen_journals(m, &old);

        log_info("Config file reloaded.");
        (void) sd_notify(/* unset_environment = */ false, NOTIFY_READY_MESSAGE);

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

static const char* const audit_set_mode_table[_AUDIT_SET_MODE_MAX] = {
        [AUDIT_NO]   = "no",
        [AUDIT_YES]  = "yes",
        [AUDIT_KEEP] = "keep",
};

DEFINE_PRIVATE_STRING_TABLE_LOOKUP_FROM_STRING_WITH_BOOLEAN(audit_set_mode, AuditSetMode, AUDIT_YES);
/* For backward compatibility, an empty string has special meaning and equals to 'keep'. */
DEFINE_CONFIG_PARSE_ENUM_WITH_DEFAULT(config_parse_audit_set_mode, audit_set_mode, AuditSetMode, AUDIT_KEEP);

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

        if (isempty(rvalue)) {
                /* Empty assignment means default */
                *sz = DEFAULT_LINE_MAX;
                return 0;
        }

        uint64_t v;
        r = parse_size(rvalue, 1024, &v);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

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

        JournalCompressOptions *compress = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                compress->enabled = -1;
                compress->threshold_bytes = UINT64_MAX;
                return 0;
        }

        if (streq(rvalue, "1")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 1, enabling compression with default threshold.");
                compress->enabled = true;
                compress->threshold_bytes = UINT64_MAX;
                return 0;
        }

        if (streq(rvalue, "0")) {
                log_syntax(unit, LOG_WARNING, filename, line, 0,
                           "Compress= ambiguously specified as 0, disabling compression.");
                compress->enabled = false;
                compress->threshold_bytes = UINT64_MAX;
                return 0;
        }

        r = parse_boolean(rvalue);
        if (r >= 0) {
                compress->enabled = r;
                compress->threshold_bytes = UINT64_MAX;
                return 0;
        }

        r = parse_size(rvalue, 1024, &compress->threshold_bytes);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        compress->enabled = true;
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

        SocketAddress *addr = ASSERT_PTR(data);
        int r;

        if (isempty(rvalue)) {
                *addr = (SocketAddress) {};
                return 0;
        }

        r = socket_address_parse(addr, rvalue);
        if (r < 0)
                return log_syntax_parse_error(unit, filename, line, r, lvalue, rvalue);

        return 0;
}
