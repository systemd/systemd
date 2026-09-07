/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.SysUpdate.Provider.h"

/* We want to reuse the Target structure from the io.systemd.SysUpdate interface, hence import it here */
#include "varlink-io.systemd.SysUpdate.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Feature,
                SD_VARLINK_FIELD_COMMENT("Identifier of the feature. Corresponds to the file name of a sysupdate.features(5) file, without the .feature suffix."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A short human readable description of the feature, see Description= in sysupdate.features(5)."),
                SD_VARLINK_DEFINE_FIELD(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A URL to documentation about the feature, see Documentation= in sysupdate.features(5)."),
                SD_VARLINK_DEFINE_FIELD(documentation, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A URL to an AppStream catalog XML file describing the feature, see AppStream= in sysupdate.features(5)."),
                SD_VARLINK_DEFINE_FIELD(appStream, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the feature is enabled, see Enabled= in sysupdate.features(5). If unset, the feature is disabled."),
                SD_VARLINK_DEFINE_FIELD(enabled, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the feature is suggested for enablement, see Suggest= in sysupdate.features(5). If unset, the feature is not suggested."),
                SD_VARLINK_DEFINE_FIELD(suggest, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                ResourceType,
                SD_VARLINK_FIELD_COMMENT("A file downloaded from a URL, see Type=url-file in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(url_file),
                SD_VARLINK_FIELD_COMMENT("A tarball downloaded from a URL, see Type=url-tar in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(url_tar),
                SD_VARLINK_FIELD_COMMENT("A local tarball, see Type=tar in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(tar),
                SD_VARLINK_FIELD_COMMENT("A partition in a GPT partition table, see Type=partition in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(partition),
                SD_VARLINK_FIELD_COMMENT("A regular file, see Type=regular-file in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(regular_file),
                SD_VARLINK_FIELD_COMMENT("A directory, see Type=directory in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(directory),
                SD_VARLINK_FIELD_COMMENT("A btrfs subvolume, see Type=subvolume in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(subvolume));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                PathRelativeTo,
                SD_VARLINK_FIELD_COMMENT("The path is relative to the root directory, see PathRelativeTo=root in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(root),
                SD_VARLINK_FIELD_COMMENT("The path is relative to the EFI System Partition, see PathRelativeTo=esp in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(esp),
                SD_VARLINK_FIELD_COMMENT("The path is relative to the Extended Boot Loader partition, see PathRelativeTo=xbootldr in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(xbootldr),
                SD_VARLINK_FIELD_COMMENT("The path is relative to $BOOT as defined by the Boot Loader Specification, see PathRelativeTo=boot in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(boot),
                SD_VARLINK_FIELD_COMMENT("The path is relative to the directory specified with --transfer-source= on the systemd-sysupdate command line, see PathRelativeTo=explicit in sysupdate.d(5)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(explicit));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TransferSource,
                SD_VARLINK_FIELD_COMMENT("The resource type of the source, see Type= in the [Source] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(type, ResourceType, 0),
                SD_VARLINK_FIELD_COMMENT("The path or URL of the source, see Path= in the [Source] section of sysupdate.d(5). Unlike in the configuration file no specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("What the path is relative to, see PathRelativeTo= in the [Source] section of sysupdate.d(5). If unset, the path is relative to the root directory."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(pathRelativeTo, PathRelativeTo, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Patterns to match the source against, see MatchPattern= in the [Source] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(matchPattern, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                TransferTarget,
                SD_VARLINK_FIELD_COMMENT("The resource type of the target, see Type= in the [Target] section of sysupdate.d(5). If unset, it is derived from the source type."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(type, ResourceType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path of the target, see Path= in the [Target] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(path, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("What the path is relative to, see PathRelativeTo= in the [Target] section of sysupdate.d(5). If unset, the path is relative to the root directory."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(pathRelativeTo, PathRelativeTo, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Patterns to match the target against, see MatchPattern= in the [Target] section of sysupdate.d(5). If unset, the source patterns are used. No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(matchPattern, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The GPT partition type to match, see MatchPartitionType= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(matchPartitionType, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The partition UUID to use for newly created partitions, see PartitionUUID= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(partitionUUID, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The partition flags to use for newly created partitions, see PartitionFlags= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(partitionFlags, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to set the NoAuto partition flag, see PartitionNoAuto= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(partitionNoAuto, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to set the GrowFileSystem partition flag, see PartitionGrowFileSystem= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(partitionGrowFileSystem, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to mark the target read-only, see ReadOnly= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(readOnly, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The UNIX file access mode to use for the target, as octal string, see Mode= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(mode, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The boot counting tries left, see TriesLeft= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(triesLeft, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The boot counting tries done, see TriesDone= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(triesDone, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The maximum number of instances to keep, see InstancesMax= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(instancesMax, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to remove temporary files from previous runs, see RemoveTemporary= in the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(removeTemporary, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The path of a symlink to maintain pointing to the newest instance, see CurrentSymlink= in the [Target] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(currentSymlink, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Transfer,
                SD_VARLINK_FIELD_COMMENT("Identifier of the transfer. Corresponds to the file name of a sysupdate.d(5) transfer file, without the .transfer suffix."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The minimum version to permit, see MinVersion= in the [Transfer] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(minVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The maximum version to permit, see MaxVersion= in the [Transfer] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(maxVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Versions to protect from removal, see ProtectVersion= in the [Transfer] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(protectVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether to cryptographically verify downloads, see Verify= in the [Transfer] section of sysupdate.d(5). If unset, verification is enabled."),
                SD_VARLINK_DEFINE_FIELD(verify, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("URLs to changelogs, see ChangeLog= in the [Transfer] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(changeLog, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("URLs to AppStream catalog XML files, see AppStream= in the [Transfer] section of sysupdate.d(5). No specifier expansion is applied."),
                SD_VARLINK_DEFINE_FIELD(appStream, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Identifiers of the optional features the transfer belongs to, see Features= in the [Transfer] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(features, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Identifiers of the optional features the transfer requires, see RequisiteFeatures= in the [Transfer] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD(requisiteFeatures, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The source of the transfer, see the [Source] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(source, TransferSource, 0),
                SD_VARLINK_FIELD_COMMENT("The target of the transfer, see the [Target] section of sysupdate.d(5)."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(target, TransferTarget, 0));

static SD_VARLINK_DEFINE_METHOD(
                ListTargets,
                SD_VARLINK_FIELD_COMMENT("The components this provider offers, as targets of class 'component', in the same format as returned by ListTargets() of the io.systemd.SysUpdate interface. Targets of other classes are ignored. Metadata fields left unset take their documented defaults."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(targets, Target, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                DescribeTarget,
                SD_VARLINK_FIELD_COMMENT("The identifier of the target to describe. Currently only targets of class 'component' are supported."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(id, TargetIdentifier, 0),
                SD_VARLINK_FIELD_COMMENT("The target object, carrying the component's metadata, as also returned by ListTargets()."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(target, Target, 0),
                SD_VARLINK_FIELD_COMMENT("The optional features of the component, equivalent to the *.feature files of a component defined in the file system."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(features, Feature, SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The transfers of the component, equivalent to the *.transfer files of a component defined in the file system."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(transfers, Transfer, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoSuchTarget);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_SysUpdate_Provider,
                "io.systemd.SysUpdate.Provider",
                SD_VARLINK_INTERFACE_COMMENT("Interface implemented by services that provide component definitions to systemd-sysupdate(8). "
                                             "systemd-sysupdate connects to all sockets bound in /run/systemd/sysupdate/provider/ and "
                                             "merges the components they provide with those defined in the file system. Components "
                                             "defined in the file system take precedence; among providers claiming the same component the "
                                             "one whose socket name sorts first wins. Unlike in the configuration files no specifier "
                                             "expansion is applied to any of the strings returned by a provider."),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Lists the components this provider offers, as targets."),
                &vl_method_ListTargets,
                SD_VARLINK_SYMBOL_COMMENT("Returns the full definition of one target: the target object with its metadata, and for components their features and transfers."),
                &vl_method_DescribeTarget,

                /* Types */
                SD_VARLINK_SYMBOL_COMMENT("Class of a target."),
                &vl_type_TargetClass,
                SD_VARLINK_SYMBOL_COMMENT("Identifier of a target."),
                &vl_type_TargetIdentifier,
                SD_VARLINK_SYMBOL_COMMENT("A target, i.e. a component offered by the provider along with its metadata, mirroring sysupdate.components(5)."),
                &vl_type_Target,
                SD_VARLINK_SYMBOL_COMMENT("An optional feature, mirroring sysupdate.features(5)."),
                &vl_type_Feature,
                SD_VARLINK_SYMBOL_COMMENT("The type of a source or target resource of a transfer."),
                &vl_type_ResourceType,
                SD_VARLINK_SYMBOL_COMMENT("What a resource path is relative to."),
                &vl_type_PathRelativeTo,
                SD_VARLINK_SYMBOL_COMMENT("The source of a transfer, mirroring the [Source] section of sysupdate.d(5)."),
                &vl_type_TransferSource,
                SD_VARLINK_SYMBOL_COMMENT("The target of a transfer, mirroring the [Target] section of sysupdate.d(5)."),
                &vl_type_TransferTarget,
                SD_VARLINK_SYMBOL_COMMENT("A transfer, mirroring a sysupdate.d(5) transfer file."),
                &vl_type_Transfer,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("The provider does not offer the specified target."),
                &vl_error_NoSuchTarget);
