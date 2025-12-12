/* SPDX-License-Identifier: LGPL-2.1-or-later */
#ifndef foosdbusprotocolhfoo
#define foosdbusprotocolhfoo

/***
  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <https://www.gnu.org/licenses/>.
***/

#include "_sd-common.h"

_SD_BEGIN_DECLARATIONS;

/* Types of message */

enum {
        _SD_BUS_MESSAGE_TYPE_INVALID = 0,
        SD_BUS_MESSAGE_METHOD_CALL,
        SD_BUS_MESSAGE_METHOD_RETURN,
        SD_BUS_MESSAGE_METHOD_ERROR,
        SD_BUS_MESSAGE_SIGNAL,
        _SD_BUS_MESSAGE_TYPE_MAX
};

/* Primitive types */

enum {
        _SD_BUS_TYPE_INVALID         = 0,
        SD_BUS_TYPE_BYTE             = 'y',
        SD_BUS_TYPE_BOOLEAN          = 'b',
        SD_BUS_TYPE_INT16            = 'n',
        SD_BUS_TYPE_UINT16           = 'q',
        SD_BUS_TYPE_INT32            = 'i',
        SD_BUS_TYPE_UINT32           = 'u',
        SD_BUS_TYPE_INT64            = 'x',
        SD_BUS_TYPE_UINT64           = 't',
        SD_BUS_TYPE_DOUBLE           = 'd',
        SD_BUS_TYPE_STRING           = 's',
        SD_BUS_TYPE_OBJECT_PATH      = 'o',
        SD_BUS_TYPE_SIGNATURE        = 'g',
        SD_BUS_TYPE_UNIX_FD          = 'h',
        SD_BUS_TYPE_ARRAY            = 'a',
        SD_BUS_TYPE_VARIANT          = 'v',
        SD_BUS_TYPE_STRUCT           = 'r', /* not actually used in signatures */
        SD_BUS_TYPE_STRUCT_BEGIN     = '(',
        SD_BUS_TYPE_STRUCT_END       = ')',
        SD_BUS_TYPE_DICT_ENTRY       = 'e', /* not actually used in signatures */
        SD_BUS_TYPE_DICT_ENTRY_BEGIN = '{',
        SD_BUS_TYPE_DICT_ENTRY_END   = '}'
};

/* Well-known errors. Note that this is only a sanitized subset of the
 * errors that the reference implementation generates. */

#define SD_BUS_ERROR_FAILED                             "org.freedesktop.DBus.Error.Failed"
#define SD_BUS_ERROR_NO_MEMORY                          "org.freedesktop.DBus.Error.NoMemory"
#define SD_BUS_ERROR_SERVICE_UNKNOWN                    "org.freedesktop.DBus.Error.ServiceUnknown"
#define SD_BUS_ERROR_NAME_HAS_NO_OWNER                  "org.freedesktop.DBus.Error.NameHasNoOwner"
#define SD_BUS_ERROR_NO_REPLY                           "org.freedesktop.DBus.Error.NoReply"
#define SD_BUS_ERROR_IO_ERROR                           "org.freedesktop.DBus.Error.IOError"
#define SD_BUS_ERROR_BAD_ADDRESS                        "org.freedesktop.DBus.Error.BadAddress"
#define SD_BUS_ERROR_NOT_SUPPORTED                      "org.freedesktop.DBus.Error.NotSupported"
#define SD_BUS_ERROR_LIMITS_EXCEEDED                    "org.freedesktop.DBus.Error.LimitsExceeded"
#define SD_BUS_ERROR_ACCESS_DENIED                      "org.freedesktop.DBus.Error.AccessDenied"
#define SD_BUS_ERROR_AUTH_FAILED                        "org.freedesktop.DBus.Error.AuthFailed"
#define SD_BUS_ERROR_NO_SERVER                          "org.freedesktop.DBus.Error.NoServer"
#define SD_BUS_ERROR_TIMEOUT                            "org.freedesktop.DBus.Error.Timeout"
#define SD_BUS_ERROR_NO_NETWORK                         "org.freedesktop.DBus.Error.NoNetwork"
#define SD_BUS_ERROR_ADDRESS_IN_USE                     "org.freedesktop.DBus.Error.AddressInUse"
#define SD_BUS_ERROR_DISCONNECTED                       "org.freedesktop.DBus.Error.Disconnected"
#define SD_BUS_ERROR_INVALID_ARGS                       "org.freedesktop.DBus.Error.InvalidArgs"
#define SD_BUS_ERROR_FILE_NOT_FOUND                     "org.freedesktop.DBus.Error.FileNotFound"
#define SD_BUS_ERROR_FILE_EXISTS                        "org.freedesktop.DBus.Error.FileExists"
#define SD_BUS_ERROR_UNKNOWN_METHOD                     "org.freedesktop.DBus.Error.UnknownMethod"
#define SD_BUS_ERROR_UNKNOWN_OBJECT                     "org.freedesktop.DBus.Error.UnknownObject"
#define SD_BUS_ERROR_UNKNOWN_INTERFACE                  "org.freedesktop.DBus.Error.UnknownInterface"
#define SD_BUS_ERROR_UNKNOWN_PROPERTY                   "org.freedesktop.DBus.Error.UnknownProperty"
#define SD_BUS_ERROR_PROPERTY_READ_ONLY                 "org.freedesktop.DBus.Error.PropertyReadOnly"
#define SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN            "org.freedesktop.DBus.Error.UnixProcessIdUnknown"
#define SD_BUS_ERROR_INVALID_SIGNATURE                  "org.freedesktop.DBus.Error.InvalidSignature"
#define SD_BUS_ERROR_INCONSISTENT_MESSAGE               "org.freedesktop.DBus.Error.InconsistentMessage"
#define SD_BUS_ERROR_TIMED_OUT                          "org.freedesktop.DBus.Error.TimedOut"
#define SD_BUS_ERROR_MATCH_RULE_NOT_FOUND               "org.freedesktop.DBus.Error.MatchRuleNotFound"
#define SD_BUS_ERROR_MATCH_RULE_INVALID                 "org.freedesktop.DBus.Error.MatchRuleInvalid"
#define SD_BUS_ERROR_INTERACTIVE_AUTHORIZATION_REQUIRED "org.freedesktop.DBus.Error.InteractiveAuthorizationRequired"
#define SD_BUS_ERROR_INVALID_FILE_CONTENT               "org.freedesktop.DBus.Error.InvalidFileContent"
#define SD_BUS_ERROR_SELINUX_SECURITY_CONTEXT_UNKNOWN   "org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown"
#define SD_BUS_ERROR_OBJECT_PATH_IN_USE                 "org.freedesktop.DBus.Error.ObjectPathInUse"

/* https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-marshaling-signature */
#define SD_BUS_MAXIMUM_SIGNATURE_LENGTH 255

/* https://dbus.freedesktop.org/doc/dbus-specification.html#message-protocol-names */
#define SD_BUS_MAXIMUM_NAME_LENGTH 255

#define SD_BUS_DEFAULT ((sd_bus *) 1)
#define SD_BUS_DEFAULT_USER ((sd_bus *) 2)
#define SD_BUS_DEFAULT_SYSTEM ((sd_bus *) 3)

/* Types */

typedef struct sd_bus sd_bus;
typedef struct sd_bus_message sd_bus_message;
typedef struct sd_bus_slot sd_bus_slot;
typedef struct sd_bus_creds sd_bus_creds;
typedef struct sd_bus_track sd_bus_track;

typedef struct sd_bus_error {
        const char *name;
        const char *message;
        int _need_free;
} sd_bus_error;

typedef struct sd_bus_error_map {
        const char *name;
        int code;
} sd_bus_error_map;

/* Flags */

__extension__ enum {
        SD_BUS_CREDS_PID                = 1ULL << 0,
        SD_BUS_CREDS_TID                = 1ULL << 1,
        SD_BUS_CREDS_PPID               = 1ULL << 2,
        SD_BUS_CREDS_UID                = 1ULL << 3,
        SD_BUS_CREDS_EUID               = 1ULL << 4,
        SD_BUS_CREDS_SUID               = 1ULL << 5,
        SD_BUS_CREDS_FSUID              = 1ULL << 6,
        SD_BUS_CREDS_GID                = 1ULL << 7,
        SD_BUS_CREDS_EGID               = 1ULL << 8,
        SD_BUS_CREDS_SGID               = 1ULL << 9,
        SD_BUS_CREDS_FSGID              = 1ULL << 10,
        SD_BUS_CREDS_SUPPLEMENTARY_GIDS = 1ULL << 11,
        SD_BUS_CREDS_COMM               = 1ULL << 12,
        SD_BUS_CREDS_TID_COMM           = 1ULL << 13,
        SD_BUS_CREDS_EXE                = 1ULL << 14,
        SD_BUS_CREDS_CMDLINE            = 1ULL << 15,
        SD_BUS_CREDS_CGROUP             = 1ULL << 16,
        SD_BUS_CREDS_UNIT               = 1ULL << 17,
        SD_BUS_CREDS_SLICE              = 1ULL << 18,
        SD_BUS_CREDS_USER_UNIT          = 1ULL << 19,
        SD_BUS_CREDS_USER_SLICE         = 1ULL << 20,
        SD_BUS_CREDS_SESSION            = 1ULL << 21,
        SD_BUS_CREDS_OWNER_UID          = 1ULL << 22,
        SD_BUS_CREDS_EFFECTIVE_CAPS     = 1ULL << 23,
        SD_BUS_CREDS_PERMITTED_CAPS     = 1ULL << 24,
        SD_BUS_CREDS_INHERITABLE_CAPS   = 1ULL << 25,
        SD_BUS_CREDS_BOUNDING_CAPS      = 1ULL << 26,
        SD_BUS_CREDS_SELINUX_CONTEXT    = 1ULL << 27,
        SD_BUS_CREDS_AUDIT_SESSION_ID   = 1ULL << 28,
        SD_BUS_CREDS_AUDIT_LOGIN_UID    = 1ULL << 29,
        SD_BUS_CREDS_TTY                = 1ULL << 30,
        SD_BUS_CREDS_UNIQUE_NAME        = 1ULL << 31,
        SD_BUS_CREDS_WELL_KNOWN_NAMES   = 1ULL << 32,
        SD_BUS_CREDS_DESCRIPTION        = 1ULL << 33,
        SD_BUS_CREDS_PIDFD              = 1ULL << 34,
        SD_BUS_CREDS_AUGMENT            = 1ULL << 63, /* special flag, if on sd-bus will augment creds struct, in a potentially race-full way. */
        _SD_BUS_CREDS_ALL               = (1ULL << 35) -1
};

__extension__ enum {
        SD_BUS_NAME_REPLACE_EXISTING  = 1ULL << 0,
        SD_BUS_NAME_ALLOW_REPLACEMENT = 1ULL << 1,
        SD_BUS_NAME_QUEUE             = 1ULL << 2
};

__extension__ enum {
        SD_BUS_MESSAGE_DUMP_WITH_HEADER  = 1ULL << 0,
        SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY = 1ULL << 1,
        _SD_BUS_MESSAGE_DUMP_KNOWN_FLAGS = SD_BUS_MESSAGE_DUMP_WITH_HEADER | SD_BUS_MESSAGE_DUMP_SUBTREE_ONLY
};

/* Callbacks */

typedef int (*sd_bus_message_handler_t)(sd_bus_message *m, void *userdata, sd_bus_error *reterr_error);
typedef int (*sd_bus_property_get_t) (sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *reply, void *userdata, sd_bus_error *reterr_error);
typedef int (*sd_bus_property_set_t) (sd_bus *bus, const char *path, const char *interface, const char *property, sd_bus_message *value, void *userdata, sd_bus_error *reterr_error);
typedef int (*sd_bus_object_find_t) (sd_bus *bus, const char *path, const char *interface, void *userdata, void **ret_found, sd_bus_error *reterr_error);
typedef int (*sd_bus_node_enumerator_t) (sd_bus *bus, const char *prefix, void *userdata, char ***ret_nodes, sd_bus_error *reterr_error);
typedef int (*sd_bus_track_handler_t) (sd_bus_track *track, void *userdata);
typedef _sd_destroy_t sd_bus_destroy_t;

_SD_END_DECLARATIONS;

#endif
