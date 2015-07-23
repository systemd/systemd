/*-*- Mode: C; c-basic-offset: 8; indent-tabs-mode: nil -*-*/

#pragma once

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

#include "bus-error.h"

#define BUS_ERROR_NO_SUCH_UNIT "org.freedesktop.systemd1.NoSuchUnit"
#define BUS_ERROR_NO_UNIT_FOR_PID "org.freedesktop.systemd1.NoUnitForPID"
#define BUS_ERROR_UNIT_EXISTS "org.freedesktop.systemd1.UnitExists"
#define BUS_ERROR_LOAD_FAILED "org.freedesktop.systemd1.LoadFailed"
#define BUS_ERROR_JOB_FAILED "org.freedesktop.systemd1.JobFailed"
#define BUS_ERROR_NO_SUCH_JOB "org.freedesktop.systemd1.NoSuchJob"
#define BUS_ERROR_NOT_SUBSCRIBED "org.freedesktop.systemd1.NotSubscribed"
#define BUS_ERROR_ALREADY_SUBSCRIBED "org.freedesktop.systemd1.AlreadySubscribed"
#define BUS_ERROR_ONLY_BY_DEPENDENCY "org.freedesktop.systemd1.OnlyByDependency"
#define BUS_ERROR_TRANSACTION_JOBS_CONFLICTING "org.freedesktop.systemd1.TransactionJobsConflicting"
#define BUS_ERROR_TRANSACTION_ORDER_IS_CYCLIC "org.freedesktop.systemd1.TransactionOrderIsCyclic"
#define BUS_ERROR_TRANSACTION_IS_DESTRUCTIVE "org.freedesktop.systemd1.TransactionIsDestructive"
#define BUS_ERROR_UNIT_MASKED "org.freedesktop.systemd1.UnitMasked"
#define BUS_ERROR_JOB_TYPE_NOT_APPLICABLE "org.freedesktop.systemd1.JobTypeNotApplicable"
#define BUS_ERROR_NO_ISOLATION "org.freedesktop.systemd1.NoIsolation"
#define BUS_ERROR_SHUTTING_DOWN "org.freedesktop.systemd1.ShuttingDown"
#define BUS_ERROR_SCOPE_NOT_RUNNING "org.freedesktop.systemd1.ScopeNotRunning"

#define BUS_ERROR_NO_SUCH_MACHINE "org.freedesktop.machine1.NoSuchMachine"
#define BUS_ERROR_NO_SUCH_IMAGE "org.freedesktop.machine1.NoSuchImage"
#define BUS_ERROR_NO_MACHINE_FOR_PID "org.freedesktop.machine1.NoMachineForPID"
#define BUS_ERROR_MACHINE_EXISTS "org.freedesktop.machine1.MachineExists"
#define BUS_ERROR_NO_PRIVATE_NETWORKING "org.freedesktop.machine1.NoPrivateNetworking"
#define BUS_ERROR_NO_SUCH_USER_MAPPING "org.freedesktop.machine1.NoSuchUserMapping"
#define BUS_ERROR_NO_SUCH_GROUP_MAPPING "org.freedesktop.machine1.NoSuchGroupMapping"

#define BUS_ERROR_NO_SUCH_SESSION "org.freedesktop.login1.NoSuchSession"
#define BUS_ERROR_NO_SESSION_FOR_PID "org.freedesktop.login1.NoSessionForPID"
#define BUS_ERROR_NO_SUCH_USER "org.freedesktop.login1.NoSuchUser"
#define BUS_ERROR_NO_USER_FOR_PID "org.freedesktop.login1.NoUserForPID"
#define BUS_ERROR_NO_SUCH_SEAT "org.freedesktop.login1.NoSuchSeat"
#define BUS_ERROR_SESSION_NOT_ON_SEAT "org.freedesktop.login1.SessionNotOnSeat"
#define BUS_ERROR_NOT_IN_CONTROL "org.freedesktop.login1.NotInControl"
#define BUS_ERROR_DEVICE_IS_TAKEN "org.freedesktop.login1.DeviceIsTaken"
#define BUS_ERROR_DEVICE_NOT_TAKEN "org.freedesktop.login1.DeviceNotTaken"
#define BUS_ERROR_OPERATION_IN_PROGRESS "org.freedesktop.login1.OperationInProgress"
#define BUS_ERROR_SLEEP_VERB_NOT_SUPPORTED "org.freedesktop.login1.SleepVerbNotSupported"
#define BUS_ERROR_SESSION_BUSY "org.freedesktop.login1.SessionBusy"

#define BUS_ERROR_AUTOMATIC_TIME_SYNC_ENABLED "org.freedesktop.timedate1.AutomaticTimeSyncEnabled"

#define BUS_ERROR_NO_SUCH_PROCESS "org.freedesktop.systemd1.NoSuchProcess"

#define BUS_ERROR_NO_NAME_SERVERS "org.freedesktop.resolve1.NoNameServers"
#define BUS_ERROR_INVALID_REPLY "org.freedesktop.resolve1.InvalidReply"
#define BUS_ERROR_NO_SUCH_RR "org.freedesktop.resolve1.NoSuchRR"
#define BUS_ERROR_NO_RESOURCES "org.freedesktop.resolve1.NoResources"
#define BUS_ERROR_CNAME_LOOP "org.freedesktop.resolve1.CNameLoop"
#define BUS_ERROR_ABORTED "org.freedesktop.resolve1.Aborted"
#define _BUS_ERROR_DNS "org.freedesktop.resolve1.DnsError."

#define BUS_ERROR_NO_SUCH_TRANSFER "org.freedesktop.import1.NoSuchTransfer"
#define BUS_ERROR_TRANSFER_IN_PROGRESS "org.freedesktop.import1.TransferInProgress"

BUS_ERROR_MAP_ELF_USE(bus_common_errors);
