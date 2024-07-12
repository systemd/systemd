/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.NamespaceResource.h"

static SD_VARLINK_DEFINE_METHOD(
                AllocateUserRange,
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(size, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(target, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                RegisterUserNamespace,
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                AddMountToUserNamespace,
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(mountFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                AddControlGroupToUserNamespace,
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(controlGroupFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                AddNetworkToUserNamespace,
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(networkNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_DEFINE_INPUT(namespaceInterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(mode, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(hostInterfaceName, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(namespaceInterfaceName, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_ERROR(UserNamespaceInterfaceNotSupported);
static SD_VARLINK_DEFINE_ERROR(NameExists);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceExists);
static SD_VARLINK_DEFINE_ERROR(DynamicRangeUnavailable);
static SD_VARLINK_DEFINE_ERROR(NoDynamicRange);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceNotRegistered);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceWithoutUserRange);
static SD_VARLINK_DEFINE_ERROR(TooManyControlGroups);
static SD_VARLINK_DEFINE_ERROR(ControlGroupAlreadyAdded);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_NamespaceResource,
                "io.systemd.NamespaceResource",
                &vl_method_AllocateUserRange,
                &vl_method_RegisterUserNamespace,
                &vl_method_AddMountToUserNamespace,
                &vl_method_AddControlGroupToUserNamespace,
                &vl_method_AddNetworkToUserNamespace,
                &vl_error_UserNamespaceInterfaceNotSupported,
                &vl_error_NameExists,
                &vl_error_UserNamespaceExists,
                &vl_error_DynamicRangeUnavailable,
                &vl_error_NoDynamicRange,
                &vl_error_UserNamespaceNotRegistered,
                &vl_error_UserNamespaceWithoutUserRange,
                &vl_error_TooManyControlGroups,
                &vl_error_ControlGroupAlreadyAdded);
