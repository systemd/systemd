/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-error-util.h"
#include "errno-util.h"

BUS_ERROR_MAP_ELF_REGISTER const sd_bus_error_map bus_standard_errors[] = {
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.Failed",                           EACCES),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NoMemory",                         ENOMEM),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.ServiceUnknown",                   EHOSTUNREACH),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NameHasNoOwner",                   ENXIO),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NoReply",                          ETIMEDOUT),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.IOError",                          EIO),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.BadAddress",                       EADDRNOTAVAIL),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NotSupported",                     EOPNOTSUPP),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.LimitsExceeded",                   ENOBUFS),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.AccessDenied",                     EACCES),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.AuthFailed",                       EACCES),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.InteractiveAuthorizationRequired", EACCES),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NoServer",                         EHOSTDOWN),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.Timeout",                          ETIMEDOUT),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.NoNetwork",                        ENONET),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.AddressInUse",                     EADDRINUSE),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.Disconnected",                     ECONNRESET),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.InvalidArgs",                      EINVAL),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.FileNotFound",                     ENOENT),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.FileExists",                       EEXIST),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.UnknownMethod",                    EBADR),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.UnknownObject",                    EBADR),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.UnknownInterface",                 EBADR),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.UnknownProperty",                  EBADR),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.PropertyReadOnly",                 EROFS),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.UnixProcessIdUnknown",             ESRCH),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.InvalidSignature",                 EINVAL),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.InconsistentMessage",              EBADMSG),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.TimedOut",                         ETIMEDOUT),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.MatchRuleInvalid",                 EINVAL),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.InvalidFileContent",               EINVAL),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.MatchRuleNotFound",                ENOENT),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.SELinuxSecurityContextUnknown",    ESRCH),
        SD_BUS_ERROR_MAP("org.freedesktop.DBus.Error.ObjectPathInUse",                  EBUSY),
        SD_BUS_ERROR_MAP_END
};

const char* bus_error_message(const sd_bus_error *e, int error) {
        if (e) {
                /* Sometimes, the D-Bus server is a little bit too verbose with
                 * its error messages, so let's override them here */
                if (sd_bus_error_has_name(e, SD_BUS_ERROR_ACCESS_DENIED))
                        return "Access denied";

                if (e->message)
                        return e->message;
        }

        return strerror_safe(error);
}
