/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.MachineInstance.h"

static SD_VARLINK_DEFINE_METHOD(Terminate);
static SD_VARLINK_DEFINE_METHOD(PowerOff);
static SD_VARLINK_DEFINE_METHOD(Reboot);
static SD_VARLINK_DEFINE_METHOD(Pause);
static SD_VARLINK_DEFINE_METHOD(Resume);

static SD_VARLINK_DEFINE_METHOD(
                Describe,
                SD_VARLINK_FIELD_COMMENT("True iff vCPUs are executing"),
                SD_VARLINK_DEFINE_OUTPUT(running, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Backend-specific state string (e.g. 'running', 'paused', 'shutdown'); 'unknown' if unavailable"),
                SD_VARLINK_DEFINE_OUTPUT(status, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD_FULL(
                SubscribeEvents,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_FIELD_COMMENT("If specified, only deliver events whose name matches one of these strings; null means all events"),
                SD_VARLINK_DEFINE_INPUT(filter, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Name of the event"),
                SD_VARLINK_DEFINE_OUTPUT(event, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Event-specific payload"),
                SD_VARLINK_DEFINE_OUTPUT(data, SD_VARLINK_OBJECT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                AddStorage,
                SD_VARLINK_FIELD_COMMENT("Index of the attached file descriptor for the storage volume"),
                SD_VARLINK_DEFINE_INPUT(fileDescriptorIndex, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Caller-supplied identifier for this binding (any non-empty string; machinectl uses '<provider>:<volume>' from the StorageProvider, but the form is not required)"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Backend-specific configuration"),
                SD_VARLINK_DEFINE_INPUT(config, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                RemoveStorage,
                SD_VARLINK_FIELD_COMMENT("Identifier of the binding to detach (as supplied to AddStorage)"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                ReplaceStorage,
                SD_VARLINK_FIELD_COMMENT("Index of the attached file descriptor for the new backing storage"),
                SD_VARLINK_DEFINE_INPUT(fileDescriptorIndex, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Identifier of the existing binding whose backing is being replaced (as supplied to AddStorage)"),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(NotConnected);
static SD_VARLINK_DEFINE_ERROR(NotSupported);
static SD_VARLINK_DEFINE_ERROR(NoSuchStorage);
static SD_VARLINK_DEFINE_ERROR(StorageExists);
static SD_VARLINK_DEFINE_ERROR(StorageImmutable);
static SD_VARLINK_DEFINE_ERROR(BadConfig);
static SD_VARLINK_DEFINE_ERROR(ConfigNotSupported);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_MachineInstance,
                "io.systemd.MachineInstance",
                SD_VARLINK_SYMBOL_COMMENT("Forcefully terminate the machine immediately"),
                &vl_method_Terminate,
                SD_VARLINK_SYMBOL_COMMENT("Request a clean shutdown of the machine"),
                &vl_method_PowerOff,
                SD_VARLINK_SYMBOL_COMMENT("Reboot the machine"),
                &vl_method_Reboot,
                SD_VARLINK_SYMBOL_COMMENT("Pause/freeze the machine"),
                &vl_method_Pause,
                SD_VARLINK_SYMBOL_COMMENT("Resume a paused machine"),
                &vl_method_Resume,
                SD_VARLINK_SYMBOL_COMMENT("Query the current status of the machine"),
                &vl_method_Describe,
                SD_VARLINK_SYMBOL_COMMENT("Subscribe to machine events. Returns a stream of events as they occur."),
                &vl_method_SubscribeEvents,
                SD_VARLINK_SYMBOL_COMMENT("Attach a storage volume (passed via file descriptor) to the running machine"),
                &vl_method_AddStorage,
                SD_VARLINK_SYMBOL_COMMENT("Detach a previously-attached storage volume from the running machine"),
                &vl_method_RemoveStorage,
                SD_VARLINK_SYMBOL_COMMENT("Replace the backing of a previously-attached storage volume in place"),
                &vl_method_ReplaceStorage,
                SD_VARLINK_SYMBOL_COMMENT("The connection to the machine backend is not available"),
                &vl_error_NotConnected,
                SD_VARLINK_SYMBOL_COMMENT("The requested operation is not supported"),
                &vl_error_NotSupported,
                SD_VARLINK_SYMBOL_COMMENT("The named storage binding does not exist"),
                &vl_error_NoSuchStorage,
                SD_VARLINK_SYMBOL_COMMENT("A storage binding with this name already exists"),
                &vl_error_StorageExists,
                SD_VARLINK_SYMBOL_COMMENT("The storage binding cannot be detached at runtime (e.g. attached at boot)"),
                &vl_error_StorageImmutable,
                SD_VARLINK_SYMBOL_COMMENT("The supplied 'config' value is not valid for this backend"),
                &vl_error_BadConfig,
                SD_VARLINK_SYMBOL_COMMENT("The supplied 'config' value is recognized but not supported by this backend"),
                &vl_error_ConfigNotSupported);
