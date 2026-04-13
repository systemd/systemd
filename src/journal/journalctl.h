/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "shared-forward.h"
#include "pcre2-util.h"

typedef enum JournalctlAction {
        ACTION_SHOW,
        ACTION_NEW_ID128,
        ACTION_SETUP_KEYS,
        ACTION_LIST_CATALOG,
        ACTION_DUMP_CATALOG,
        ACTION_UPDATE_CATALOG,
        ACTION_PRINT_HEADER,
        ACTION_VERIFY,
        ACTION_DISK_USAGE,
        ACTION_LIST_BOOTS,
        ACTION_LIST_FIELDS,
        ACTION_LIST_FIELD_NAMES,
        ACTION_LIST_INVOCATIONS,
        ACTION_LIST_NAMESPACES,
        ACTION_FLUSH,
        ACTION_RELINQUISH_VAR,
        ACTION_SYNC,
        ACTION_ROTATE,
        ACTION_VACUUM,
        ACTION_ROTATE_AND_VACUUM,
} JournalctlAction;

extern JournalctlAction arg_action;
extern OutputMode arg_output;
extern sd_json_format_flags_t arg_json_format_flags;
extern PagerFlags arg_pager_flags;
extern bool arg_utc;
extern bool arg_follow;
extern bool arg_full;
extern bool arg_all;
extern int arg_lines;
extern bool arg_lines_oldest;
extern bool arg_no_tail;
extern bool arg_truncate_newline;
extern bool arg_quiet;
extern bool arg_merge;
extern int arg_boot;
extern sd_id128_t arg_boot_id;
extern int arg_boot_offset;
extern bool arg_dmesg;
extern bool arg_no_hostname;
extern char *arg_cursor;
extern char *arg_cursor_file;
extern char *arg_after_cursor;
extern bool arg_show_cursor;
extern char *arg_directory;
extern char **arg_file;
extern bool arg_file_stdin;
extern int arg_priorities;
extern Set *arg_facilities;
extern char *arg_verify_key;
#if HAVE_GCRYPT
extern usec_t arg_interval;
extern bool arg_force;
#endif
extern usec_t arg_since;
extern usec_t arg_until;
extern bool arg_since_set;
extern bool arg_until_set;
extern char **arg_syslog_identifier;
extern char **arg_exclude_identifier;
extern char **arg_system_units;
extern char **arg_user_units;
extern bool arg_invocation;
extern sd_id128_t arg_invocation_id;
extern int arg_invocation_offset;
extern char *arg_field;
extern bool arg_catalog;
extern bool arg_reverse;
extern int arg_journal_type;
extern int arg_journal_additional_open_flags;
extern int arg_namespace_flags;
extern char *arg_root;
extern char *arg_image;
extern char *arg_machine;
extern char *arg_namespace;
extern uint64_t arg_vacuum_size;
extern uint64_t arg_vacuum_n_files;
extern usec_t arg_vacuum_time;
extern Set *arg_output_fields;
extern char *arg_pattern;
extern pcre2_code *arg_compiled_pattern;
extern PatternCompileCase arg_case;
extern ImagePolicy *arg_image_policy;
extern bool arg_synchronize_on_exit;

static inline bool arg_lines_needs_seek_end(void) {
        return arg_lines >= 0 && !arg_lines_oldest;
}

/* Only used for varlink server invocation */
extern RuntimeScope arg_varlink_runtime_scope;
