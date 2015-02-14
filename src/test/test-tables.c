/***
  This file is part of systemd

  Copyright 2013 Zbigniew Jędrzejewski-Szmek

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

#include "automount.h"
#include "cgroup.h"
#include "compress.h"
#include "condition.h"
#include "device.h"
#include "execute.h"
#include "install.h"
#include "job.h"
#include "kill.h"
#include "log.h"
#include "logs-show.h"
#include "mount.h"
#include "path.h"
#include "scope.h"
#include "service.h"
#include "slice.h"
#include "snapshot.h"
#include "socket-util.h"
#include "socket.h"
#include "swap.h"
#include "target.h"
#include "timer.h"
#include "unit-name.h"
#include "unit.h"
#include "util.h"
#include "architecture.h"
#include "link-config.h"
#include "bus-xml-policy.h"
#include "busname.h"
#include "journald-server.h"
#include "locale-util.h"

#include "test-tables.h"

int main(int argc, char **argv) {
        test_table(architecture, ARCHITECTURE);
        test_table(automount_result, AUTOMOUNT_RESULT);
        test_table(automount_state, AUTOMOUNT_STATE);
        test_table(bus_policy_access, BUS_POLICY_ACCESS);
        test_table(busname_result, BUSNAME_RESULT);
        test_table(busname_state, BUSNAME_STATE);
        test_table(cgroup_device_policy, CGROUP_DEVICE_POLICY);
        test_table(condition_type, CONDITION_TYPE);
        test_table(assert_type, CONDITION_TYPE);
        test_table(condition_result, CONDITION_RESULT);
        test_table(device_state, DEVICE_STATE);
        test_table(exec_input, EXEC_INPUT);
        test_table(exec_output, EXEC_OUTPUT);
        test_table(failure_action, FAILURE_ACTION);
        test_table(job_mode, JOB_MODE);
        test_table(job_result, JOB_RESULT);
        test_table(job_state, JOB_STATE);
        test_table(job_type, JOB_TYPE);
        test_table(kill_mode, KILL_MODE);
        test_table(kill_who, KILL_WHO);
        test_table(log_target, LOG_TARGET);
        test_table(mac_policy, MACPOLICY);
        test_table(manager_state, MANAGER_STATE);
        test_table(mount_exec_command, MOUNT_EXEC_COMMAND);
        test_table(mount_result, MOUNT_RESULT);
        test_table(mount_state, MOUNT_STATE);
        test_table(name_policy, NAMEPOLICY);
        test_table(notify_access, NOTIFY_ACCESS);
        test_table(output_mode, OUTPUT_MODE);
        test_table(path_result, PATH_RESULT);
        test_table(path_state, PATH_STATE);
        test_table(path_type, PATH_TYPE);
        test_table(policy_item_class, POLICY_ITEM_CLASS);
        test_table(policy_item_type, POLICY_ITEM_TYPE);
        test_table(protect_home, PROTECT_HOME);
        test_table(protect_system, PROTECT_SYSTEM);
        test_table(rlimit, RLIMIT);
        test_table(scope_result, SCOPE_RESULT);
        test_table(scope_state, SCOPE_STATE);
        test_table(service_exec_command, SERVICE_EXEC_COMMAND);
        test_table(service_restart, SERVICE_RESTART);
        test_table(service_result, SERVICE_RESULT);
        test_table(service_state, SERVICE_STATE);
        test_table(service_type, SERVICE_TYPE);
        test_table(slice_state, SLICE_STATE);
        test_table(snapshot_state, SNAPSHOT_STATE);
        test_table(socket_address_bind_ipv6_only, SOCKET_ADDRESS_BIND_IPV6_ONLY);
        test_table(socket_exec_command, SOCKET_EXEC_COMMAND);
        test_table(socket_result, SOCKET_RESULT);
        test_table(socket_state, SOCKET_STATE);
        test_table(split_mode, SPLIT);
        test_table(storage, STORAGE);
        test_table(swap_exec_command, SWAP_EXEC_COMMAND);
        test_table(swap_result, SWAP_RESULT);
        test_table(swap_state, SWAP_STATE);
        test_table(target_state, TARGET_STATE);
        test_table(timer_base, TIMER_BASE);
        test_table(timer_result, TIMER_RESULT);
        test_table(timer_state, TIMER_STATE);
        test_table(unit_active_state, UNIT_ACTIVE_STATE);
        test_table(unit_dependency, UNIT_DEPENDENCY);
        test_table(unit_file_change_type, UNIT_FILE_CHANGE_TYPE);
        test_table(unit_file_preset_mode, UNIT_FILE_PRESET);
        test_table(unit_file_state, UNIT_FILE_STATE);
        test_table(unit_load_state, UNIT_LOAD_STATE);
        test_table(unit_type, UNIT_TYPE);
        test_table(locale_variable, VARIABLE_LC);

        test_table_sparse(object_compressed, OBJECT_COMPRESSED);

        return EXIT_SUCCESS;
}
