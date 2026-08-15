/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.AskPassword.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                EchoMode,
                SD_VARLINK_FIELD_COMMENT("Request that the password is prompted for without any visual feedback"),
                SD_VARLINK_DEFINE_ENUM_VALUE(off),
                SD_VARLINK_FIELD_COMMENT("Show the password in plaintext as it is typed in"),
                SD_VARLINK_DEFINE_ENUM_VALUE(on),
                SD_VARLINK_FIELD_COMMENT("Provide visual feedback as the password is typed, but mask the password plaintext"),
                SD_VARLINK_DEFINE_ENUM_VALUE(masked));

static SD_VARLINK_DEFINE_METHOD(
                Ask,
                SD_VARLINK_FIELD_COMMENT("The message to show when prompting for the password"),
                SD_VARLINK_DEFINE_INPUT(message, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The name for the kernel keyring entry used for caching"),
                SD_VARLINK_DEFINE_INPUT(keyname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The icon name to display, following the freedesktop.org icon naming specification"),
                SD_VARLINK_DEFINE_INPUT(icon, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("An recognizable id for the password prompt"),
                SD_VARLINK_DEFINE_INPUT(id, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timeout in µs (relative, CLOCK_MONOTONIC; set to zero to only check cache and not query interactively; set to UINT64_MAX to disable relative timeout; if not set defaults to 90s)"),
                SD_VARLINK_DEFINE_INPUT(timeoutUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Timeout in µs (absolute, CLOCK_MONOTONIC; if both timeoutUSec and untilUSec are specified the earlier of the two is used; "
                                         "set to zero to only check cache and not query interactively; leave unset or set to UINT64_MAX to disable absolute timeout)"),
                SD_VARLINK_DEFINE_INPUT(untilUSec, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to accept cached passwords from the kernel keyring"),
                SD_VARLINK_DEFINE_INPUT(acceptCached, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to push acquired passwords into the kernel keyring"),
                SD_VARLINK_DEFINE_INPUT(pushCache, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to give visual feedback when typing in the password"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(echo, EchoMode, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("List of acquired passwords. This typically contains one entry, but might contain more in case multiple passwords were previously cached."),
                SD_VARLINK_DEFINE_OUTPUT(passwords, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoPasswordAvailable);
static SD_VARLINK_DEFINE_ERROR(TimeoutReached);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_AskPassword,
                "io.systemd.AskPassword",
                SD_VARLINK_INTERFACE_COMMENT("An interface for interactively asking the user for a password"),
                SD_VARLINK_SYMBOL_COMMENT("Encodes whether to provide visual feedback as the password is typed in"),
                &vl_type_EchoMode,
                SD_VARLINK_SYMBOL_COMMENT("Interactively ask the user for a password, or answer from a previously cached entry"),
                &vl_method_Ask,
                SD_VARLINK_SYMBOL_COMMENT("No password available, because none was provided in the cache, and no agent was asked"),
                &vl_error_NoPasswordAvailable,
                SD_VARLINK_SYMBOL_COMMENT("Query timeout reached, user did not provide a password in time"),
                &vl_error_TimeoutReached);
