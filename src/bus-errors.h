/*-*- Mode: C; c-basic-offset: 8 -*-*/

#ifndef foobuserrorshfoo
#define foobuserrorshfoo

/***
  This file is part of systemd.

  Copyright 2010 Lennart Poettering

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU General Public License as published by
  the Free Software Foundation; either version 2 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  General Public License for more details.

  You should have received a copy of the GNU General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include <string.h>
#include <dbus/dbus.h>

#define BUS_ERROR_NO_SUCH_UNIT "org.freedesktop.systemd1.NoSuchUnit"
#define BUS_ERROR_NO_SUCH_JOB "org.freedesktop.systemd1.NoSuchJob"
#define BUS_ERROR_NOT_SUBSCRIBED "org.freedesktop.systemd1.NotSubscribed"
#define BUS_ERROR_INVALID_PATH "org.freedesktop.systemd1.InvalidPath"
#define BUS_ERROR_INVALID_NAME "org.freedesktop.systemd1.InvalidName"
#define BUS_ERROR_UNIT_TYPE_MISMATCH "org.freedesktop.systemd1.UnitTypeMismatch"
#define BUS_ERROR_UNIT_EXISTS "org.freedesktop.systemd1.UnitExists"
#define BUS_ERROR_NOT_SUPPORTED "org.freedesktop.systemd1.NotSupported"
#define BUS_ERROR_INVALID_JOB_MODE "org.freedesktop.systemd1.InvalidJobMode"
#define BUS_ERROR_ONLY_BY_DEPENDENCY "org.freedesktop.systemd1.OnlyByDependency"
#define BUS_ERROR_LOAD_FAILED "org.freedesktop.systemd1.LoadFailed"
#define BUS_ERROR_JOB_TYPE_NOT_APPLICABLE "org.freedesktop.systemd1.JobTypeNotApplicable"
#define BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE "org.freedesktop.systemd1.TransactionIsDestructive"
#define BUS_ERROR_TRANSACTION_JOBS_CONFLICTING "org.freedesktop.systemd1.TransactionJobsConflicting"
#define BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC "org.freedesktop.systemd1.TransactionOrderIsCyclic"

static inline const char *bus_error(const DBusError *e, int r) {
        if (e && e->message)
                return e->message;

        if (r >= 0)
                return strerror(r);

        return strerror(-r);
}

#endif
