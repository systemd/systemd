/* SPDX-License-Identifier: LGPL-2.1-or-later */
#pragma once

#include "sd-varlink.h"

#include "machine.h"

#define VARLINK_ERROR_MACHINE_NO_SUCH_MACHINE           "io.systemd.Machine.NoSuchMachine"
#define VARLINK_ERROR_MACHINE_EXISTS                    "io.systemd.Machine.MachineExists"
#define VARLINK_ERROR_MACHINE_NO_PRIVATE_NETWORKING     "io.systemd.Machine.NoPrivateNetworking"
#define VARLINK_ERROR_MACHINE_NO_OS_RELEASE_INFORMATION "io.systemd.Machine.NoOSReleaseInformation"
#define VARLINK_ERROR_MACHINE_NO_UID_SHIFT              "io.systemd.Machine.NoUIDShift"
#define VARLINK_ERROR_MACHINE_NOT_AVAILABLE             "io.systemd.Machine.NotAvailable"
#define VARLINK_ERROR_MACHINE_NOT_SUPPORTED             "io.systemd.Machine.NotSupported"
#define VARLINK_ERROR_MACHINE_TOO_MANY_OPERATIONS       "io.systemd.Machine.TooManyOperations"
#define VARLINK_ERROR_MACHINE_NO_IPC                    "io.systemd.Machine.NoIPC"
#define VARLINK_ERROR_MACHINE_NO_SUCH_USER              "io.systemd.Machine.NoSuchUser"
#define VARLINK_ERROR_MACHINE_NO_SUCH_GROUP             "io.systemd.Machine.NoSuchGroup"
#define VARLINK_ERROR_MACHINE_USER_IN_HOST_RANGE        "io.systemd.Machine.UserInHostRange"
#define VARLINK_ERROR_MACHINE_GROUP_IN_HOST_RANGE       "io.systemd.Machine.GroupInHostRange"

#define VARLINK_DISPATCH_MACHINE_LOOKUP_FIELDS(t) {                     \
                .name = "name",                                         \
                .type = SD_JSON_VARIANT_STRING,                         \
                .callback = sd_json_dispatch_const_string,              \
                .offset = offsetof(t, name)                             \
        }, {                                                            \
                .name = "pid",                                          \
                .type = _SD_JSON_VARIANT_TYPE_INVALID,                  \
                .callback = json_dispatch_pidref,                       \
                .offset = offsetof(t, pidref),                          \
                .flags = SD_JSON_RELAX /* allows PID_AUTOMATIC */       \
        }

int lookup_machine_by_name_or_pidref(sd_varlink *link, Manager *manager, const char *machine_name, const PidRef *pidref, Machine **ret_machine);

int vl_method_register(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_unregister_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_terminate_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_kill(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_open(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_map_from(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_map_to(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_bind_mount(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
int vl_method_copy_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata, bool copy_from);
int vl_method_open_root_directory_internal(sd_varlink *link, sd_json_variant *parameters, sd_varlink_method_flags_t flags, void *userdata);
