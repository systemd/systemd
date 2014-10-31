/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

/***
  This file is part of systemd.

  Copyright 2014 Zbigniew Jędrzejewski-Szmek

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

#include <errno.h>

#include "sd-bus.h"
#include "bus-errors.h"

SD_BUS_ERROR_MAPPING(systemd_shared) = {
        {BUS_ERROR_NO_SUCH_UNIT,                 ENOENT},
        {BUS_ERROR_NO_UNIT_FOR_PID,              ESRCH},
        {BUS_ERROR_UNIT_EXISTS,                  EEXIST},
        {BUS_ERROR_LOAD_FAILED,                  EIO},
        {BUS_ERROR_JOB_FAILED,                   EREMOTEIO},
        {BUS_ERROR_NO_SUCH_JOB,                  ENOENT},
        {BUS_ERROR_NOT_SUBSCRIBED,               EINVAL},
        {BUS_ERROR_ALREADY_SUBSCRIBED,           EINVAL},
        {BUS_ERROR_ONLY_BY_DEPENDENCY,           EINVAL},
        {BUS_ERROR_TRANSACTION_JOBS_CONFLICTING, EDEADLOCK},
        {BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC,  EDEADLOCK},
        {BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE,   EDEADLOCK},
        {BUS_ERROR_UNIT_MASKED,                  ENOSYS},
        {BUS_ERROR_JOB_TYPE_NOT_APPLICABLE,      EBADR},
        {BUS_ERROR_NO_ISOLATION,                 EPERM},
        {BUS_ERROR_SHUTTING_DOWN,                ECANCELED},
        {BUS_ERROR_SCOPE_NOT_RUNNING,            EHOSTDOWN},

        {BUS_ERROR_NO_SUCH_MACHINE,              ENXIO},
        {BUS_ERROR_NO_MACHINE_FOR_PID,           ENXIO},
        {BUS_ERROR_MACHINE_EXISTS,               EEXIST},
        {BUS_ERROR_NO_PRIVATE_NETWORKING,        ENOSYS},

        {BUS_ERROR_NO_SUCH_SESSION,              ENXIO},
        {BUS_ERROR_NO_SESSION_FOR_PID,           ENXIO},
        {BUS_ERROR_NO_SUCH_USER,                 ENXIO},
        {BUS_ERROR_NO_USER_FOR_PID,              ENXIO},
        {BUS_ERROR_NO_SUCH_SEAT,                 ENXIO},
        {BUS_ERROR_SESSION_NOT_ON_SEAT,          EINVAL},
        {BUS_ERROR_NOT_IN_CONTROL,               EINVAL},
        {BUS_ERROR_DEVICE_IS_TAKEN,              EINVAL},
        {BUS_ERROR_DEVICE_NOT_TAKEN,             EINVAL},
        {BUS_ERROR_OPERATION_IN_PROGRESS,        EINPROGRESS},
        {BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED,     ENOSYS},

        {BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED,  EALREADY},

        {BUS_ERROR_NO_SUCH_PROCESS,              ESRCH},

        {BUS_ERROR_NO_NAME_SERVERS,              EIO},
        {BUS_ERROR_INVALID_REPLY,                EINVAL},
        {BUS_ERROR_NO_SUCH_RR,                   ENOENT},
        {BUS_ERROR_NO_RESOURCES,                 ENOMEM},
        {BUS_ERROR_CNAME_LOOP,                   EDEADLOCK},
        {BUS_ERROR_ABORTED,                      ECANCELED},
};
