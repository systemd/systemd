/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.sysext.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ImageClass,
                SD_VARLINK_DEFINE_ENUM_VALUE(sysext),
                SD_VARLINK_DEFINE_ENUM_VALUE(confext));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ImageType,
                SD_VARLINK_DEFINE_ENUM_VALUE(directory),
                SD_VARLINK_DEFINE_ENUM_VALUE(subvolume),
                SD_VARLINK_DEFINE_ENUM_VALUE(raw),
                SD_VARLINK_DEFINE_ENUM_VALUE(block),
                SD_VARLINK_DEFINE_ENUM_VALUE(mstack));

static SD_VARLINK_DEFINE_METHOD(
                Merge,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(noReload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(noexec, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Unmerge,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(noReload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD(
                Refresh,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(noReload, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(alwaysRefresh, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_INPUT(noexec, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT);

static SD_VARLINK_DEFINE_METHOD_FULL(
                List,
                SD_VARLINK_REQUIRES_MORE,
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(class, ImageClass, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Class, ImageClass, 0),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(Type, ImageType, 0),
                SD_VARLINK_DEFINE_OUTPUT(Name, SD_VARLINK_STRING, 0),
                SD_VARLINK_DEFINE_OUTPUT(Path, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ReadOnly, SD_VARLINK_BOOL, 0),
                SD_VARLINK_DEFINE_OUTPUT(CreationTimestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(ModificationTimestamp, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Usage, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(UsageExclusive, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(Limit, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_DEFINE_OUTPUT(LimitExclusive, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoImagesFound);

static SD_VARLINK_DEFINE_ERROR(
                AlreadyMerged,
                SD_VARLINK_DEFINE_FIELD(hierarchy, SD_VARLINK_STRING, 0));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_sysext,
                "io.systemd.sysext",
                &vl_type_ImageClass,
                &vl_type_ImageType,
                &vl_method_Merge,
                &vl_method_Unmerge,
                &vl_method_Refresh,
                &vl_method_List,
                &vl_error_NoImagesFound,
                &vl_error_AlreadyMerged);
