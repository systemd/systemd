/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#ifndef foosdbusprotocolhfoo
#define foosdbusprotocolhfoo

/***
  This file is part of systemd.

  Copyright 2013 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <endian.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Types of message */

enum {
        _SD_BUS_MESSAGE_TYPE_INVALID = 0,
        SD_BUS_MESSAGE_TYPE_METHOD_CALL,
        SD_BUS_MESSAGE_TYPE_METHOD_RETURN,
        SD_BUS_MESSAGE_TYPE_METHOD_ERROR,
        SD_BUS_MESSAGE_TYPE_SIGNAL,
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
        SD_BUS_TYPE_DICT_ENTRY_END   = '}',
};

/* Endianness */

enum {
        _SD_BUS_INVALID_ENDIAN = 0,
        SD_BUS_LITTLE_ENDIAN   = 'l',
        SD_BUS_BIG_ENDIAN      = 'B',
#if __BYTE_ORDER == __BIG_ENDIAN
        SD_BUS_NATIVE_ENDIAN   = SD_BUS_BIG_ENDIAN,
        SD_BUS_REVERSE_ENDIAN  = SD_BUS_LITTLE_ENDIAN
#else
        SD_BUS_NATIVE_ENDIAN   = SD_BUS_LITTLE_ENDIAN,
        SD_BUS_REVERSE_ENDIAN  = SD_BUS_BIG_ENDIAN
#endif
};

/* Flags */

enum {
        SD_BUS_MESSAGE_NO_REPLY_EXPECTED = 1,
        SD_BUS_MESSAGE_NO_AUTO_START = 2
};

/* Header fields */

enum {
        _SD_BUS_MESSAGE_HEADER_INVALID = 0,
        SD_BUS_MESSAGE_HEADER_PATH,
        SD_BUS_MESSAGE_HEADER_INTERFACE,
        SD_BUS_MESSAGE_HEADER_MEMBER,
        SD_BUS_MESSAGE_HEADER_ERROR_NAME,
        SD_BUS_MESSAGE_HEADER_REPLY_SERIAL,
        SD_BUS_MESSAGE_HEADER_DESTINATION,
        SD_BUS_MESSAGE_HEADER_SENDER,
        SD_BUS_MESSAGE_HEADER_SIGNATURE,
        SD_BUS_MESSAGE_HEADER_UNIX_FDS,
        _SD_BUS_MESSAGE_HEADER_MAX
};

/* RequestName parameters */
enum  {
        SD_BUS_NAME_ALLOW_REPLACEMENT = 1,
        SD_BUS_NAME_REPLACE_EXISTING = 2,
        SD_BUS_NAME_DO_NOT_QUEUE = 4
};

/* RequestName returns */
enum  {
        SD_BUS_NAME_PRIMARY_OWNER = 1,
        SD_BUS_NAME_IN_QUEUE = 2,
        SD_BUS_NAME_EXISTS = 3,
        SD_BUS_NAME_ALREADY_OWNER = 4
};

/* ReleaseName returns */
enum {
        SD_BUS_NAME_RELEASED = 1,
        SD_BUS_NAME_NON_EXISTENT = 2,
        SD_BUS_NAME_NOT_OWNER = 3,
};

#define SD_BUS_INTROSPECT_DOCTYPE                                       \
        "<!DOCTYPE node PUBLIC \"-//freedesktop//DTD D-BUS Object Introspection 1.0//EN\"\n" \
        "\"http://www.freedesktop.org/standards/dbus/1.0/introspect.dtd\">\n"

#define SD_BUS_INTROSPECT_INTERFACE_PEER                                \
        " <interface name=\"org.freedesktop.DBus.Peer\">\n"             \
        "  <method name=\"Ping\"/>\n"                                   \
        "  <method name=\"GetMachineId\">\n"                            \
        "   <arg type=\"s\" name=\"machine_uuid\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        " </interface>\n"

#define SD_BUS_INTROSPECT_INTERFACE_INTROSPECTABLE                      \
        " <interface name=\"org.freedesktop.DBus.Introspectable\">\n"   \
        "  <method name=\"Introspect\">\n"                              \
        "   <arg name=\"data\" type=\"s\" direction=\"out\"/>\n"        \
        "  </method>\n"                                                 \
        " </interface>\n"

#define SD_BUS_INTROSPECT_INTERFACE_PROPERTIES                          \
        " <interface name=\"org.freedesktop.DBus.Properties\">\n"       \
        "  <method name=\"Get\">\n"                                     \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"     \
        "   <arg name=\"value\" direction=\"out\" type=\"v\"/>\n"       \
        "  </method>\n"                                                 \
        "  <method name=\"GetAll\">\n"                                  \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"properties\" direction=\"out\" type=\"a{sv}\"/>\n" \
        "  </method>\n"                                                 \
        "  <method name=\"Set\">\n"                                     \
        "   <arg name=\"interface\" direction=\"in\" type=\"s\"/>\n"    \
        "   <arg name=\"property\" direction=\"in\" type=\"s\"/>\n"     \
        "   <arg name=\"value\" direction=\"in\" type=\"v\"/>\n"        \
        "  </method>\n"                                                 \
        "  <signal name=\"PropertiesChanged\">\n"                       \
        "   <arg type=\"s\" name=\"interface\"/>\n"                     \
        "   <arg type=\"a{sv}\" name=\"changed_properties\"/>\n"        \
        "   <arg type=\"as\" name=\"invalidated_properties\"/>\n"       \
        "  </signal>\n"                                                 \
        " </interface>\n"

#define SD_BUS_INTROSPECT_INTERFACE_OBJECT_MANAGER                      \
        " <interface name=\"org.freedesktop.DBus.ObjectManager\">\n"    \
        "  <method name=\"GetManagedObjects\">\n"                       \
        "   <arg type=\"a{oa{sa{sv}}}\" name=\"object_paths_interfaces_and_properties\" direction=\"out\"/>\n" \
        "  </method>\n"                                                 \
        "  <signal name=\"InterfacesAdded\">\n"                         \
        "   <arg type=\"o\" name=\"object_path\"/>\n"                   \
        "   <arg type=\"a{sa{sv}}\" name=\"interfaces_and_properties\"/>\n" \
        "  </signal>\n"                                                 \
        "  <signal name=\"InterfacesRemoved\">\n"                       \
        "   <arg type=\"o\" name=\"object_path\"/>\n"                   \
        "   <arg type=\"as\" name=\"interfaces\"/>\n"                   \
        "  </signal>\n"                                                 \
        " </interface>\n"

/* Well-known errors. Note that this is only a sanitized subset of the
 * errors that the reference implementation generates. */
#define SD_BUS_ERROR_FAILED                     "org.freedesktop.DBus.Error.Failed"
#define SD_BUS_ERROR_NO_MEMORY                  "org.freedesktop.DBus.Error.NoMemory"
#define SD_BUS_ERROR_SERVICE_UNKNOWN            "org.freedesktop.DBus.Error.ServiceUnknown"
#define SD_BUS_ERROR_NAME_HAS_NO_OWNER          "org.freedesktop.DBus.Error.NameHasNoOwner"
#define SD_BUS_ERROR_NO_REPLY                   "org.freedesktop.DBus.Error.NoReply"
#define SD_BUS_ERROR_IO_ERROR                   "org.freedesktop.DBus.Error.IOError"
#define SD_BUS_ERROR_BAD_ADDRESS                "org.freedesktop.DBus.Error.BadAddress"
#define SD_BUS_ERROR_NOT_SUPPORTED              "org.freedesktop.DBus.Error.NotSupported"
#define SD_BUS_ERROR_LIMITS_EXCEEDED            "org.freedesktop.DBus.Error.LimitsExceeded"
#define SD_BUS_ERROR_ACCESS_DENIED              "org.freedesktop.DBus.Error.AccessDenied"
#define SD_BUS_ERROR_AUTH_FAILED                "org.freedesktop.DBus.Error.AuthFailed"
#define SD_BUS_ERROR_NO_SERVER                  "org.freedesktop.DBus.Error.NoServer"
#define SD_BUS_ERROR_TIMEOUT                    "org.freedesktop.DBus.Error.Timeout"
#define SD_BUS_ERROR_NO_NETWORK                 "org.freedesktop.DBus.Error.NoNetwork"
#define SD_BUS_ERROR_ADDRESS_IN_USE             "org.freedesktop.DBus.Error.AddressInUse"
#define SD_BUS_ERROR_DISCONNECTED               "org.freedesktop.DBus.Error.Disconnected"
#define SD_BUS_ERROR_INVALID_ARGS               "org.freedesktop.DBus.Error.InvalidArgs"
#define SD_BUS_ERROR_FILE_NOT_FOUND             "org.freedesktop.DBus.Error.FileNotFound"
#define SD_BUS_ERROR_FILE_EXISTS                "org.freedesktop.DBus.Error.FileExists"
#define SD_BUS_ERROR_UNKNOWN_METHOD             "org.freedesktop.DBus.Error.UnknownMethod"
#define SD_BUS_ERROR_UNKNOWN_OBJECT             "org.freedesktop.DBus.Error.UnknownObject"
#define SD_BUS_ERROR_UNKNOWN_INTERFACE          "org.freedesktop.DBus.Error.UnknownInterface"
#define SD_BUS_ERROR_UNKNOWN_PROPERTY           "org.freedesktop.DBus.Error.UnknownProperty"
#define SD_BUS_ERROR_PROPERTY_READ_ONLY         "org.freedesktop.DBus.Error.PropertyReadOnly"
#define SD_BUS_ERROR_UNIX_PROCESS_ID_UNKNOWN    "org.freedesktop.DBus.Error.UnixProcessIdUnknown"
#define SD_BUS_ERROR_INVALID_SIGNATURE          "org.freedesktop.DBus.Error.InvalidSignature"
#define SD_BUS_ERROR_INCONSISTENT_MESSAGE       "org.freedesktop.DBus.Error.InconsistentMessage"

#ifdef __cplusplus
}
#endif

#endif
