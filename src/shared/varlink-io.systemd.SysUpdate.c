/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "bus-polkit.h"
#include "varlink-io.systemd.SysUpdate.h"

SD_VARLINK_DEFINE_ENUM_TYPE(
                TargetClass,
                SD_VARLINK_FIELD_COMMENT("Container or machine managed by systemd-machined.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(machine),
                SD_VARLINK_FIELD_COMMENT("Portable service."),
                SD_VARLINK_DEFINE_ENUM_VALUE(portable),
                SD_VARLINK_FIELD_COMMENT("System extension managed by systemd-sysext.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(sysext),
                SD_VARLINK_FIELD_COMMENT("Configuration extension managed by systemd-confext.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(confext),
                SD_VARLINK_FIELD_COMMENT("Host system."),
                SD_VARLINK_DEFINE_ENUM_VALUE(host),
                SD_VARLINK_FIELD_COMMENT("Component managed by systemd-sysupdate.service(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(component));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                TargetIdentifier,
                SD_VARLINK_FIELD_COMMENT("Where the target was enumerated."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(class, TargetClass, 0),
                SD_VARLINK_FIELD_COMMENT("Name of the target, unique within a class."),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ComponentSuccessAction,
                SD_VARLINK_FIELD_COMMENT("Continue with the next component"),
                SD_VARLINK_DEFINE_ENUM_VALUE(continue),
                SD_VARLINK_FIELD_COMMENT("Finish the current update iteration, and start the next one"),
                SD_VARLINK_DEFINE_ENUM_VALUE(restart));

SD_VARLINK_DEFINE_ENUM_TYPE(
                ComponentFailureAction,
                SD_VARLINK_FIELD_COMMENT("Continue with the next component, but fail at the very end"),
                SD_VARLINK_DEFINE_ENUM_VALUE(continue),
                SD_VARLINK_FIELD_COMMENT("Fail immediately"),
                SD_VARLINK_DEFINE_ENUM_VALUE(fail));

SD_VARLINK_DEFINE_STRUCT_TYPE(
                Target,
                SD_VARLINK_FIELD_COMMENT("Identifier for the target."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(id, TargetIdentifier, 0),
                SD_VARLINK_FIELD_COMMENT("The currently installed version of the target, if any."),
                SD_VARLINK_DEFINE_FIELD(currentVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("All locally-known versions of the target."),
                SD_VARLINK_DEFINE_FIELD(allVersions, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether the current version is installed but pending a reboot to become active. Always set when returned by ListTargets(). Not set by component providers, since this is a property of the local installation."),
                SD_VARLINK_DEFINE_FIELD(currentVersionIsPending, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("URLs to zero or more AppStream catalog XML files describing the target."),
                SD_VARLINK_DEFINE_FIELD(appStream, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("The following fields carry the metadata of targets of class 'component', mirroring the settings of sysupdate.components(5). They are unset for targets of other classes. A short human readable description of the component."),
                SD_VARLINK_DEFINE_FIELD(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("URLs to documentation for the component."),
                SD_VARLINK_DEFINE_FIELD(documentation, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether the component is enabled. When returned by ListTargets() this is the effective state and always set for components. If unset, the component is enabled."),
                SD_VARLINK_DEFINE_FIELD(enabled, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("What to do after the component has been updated successfully, see SuccessAction= in sysupdate.components(5)."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(successAction, ComponentSuccessAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("What to do if updating the component failed, see FailureAction= in sysupdate.components(5)."),
                SD_VARLINK_DEFINE_FIELD_BY_TYPE(failureAction, ComponentFailureAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether the component is suggested for enablement. When returned by ListTargets() this is the evaluated state and always set for components. If unset, the component is not suggested."),
                SD_VARLINK_DEFINE_FIELD(suggested, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The minimum version to permit for all transfers of the component, see MinVersion= in sysupdate.components(5)."),
                SD_VARLINK_DEFINE_FIELD(minVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The maximum version to permit for all transfers of the component, see MaxVersion= in sysupdate.components(5)."),
                SD_VARLINK_DEFINE_FIELD(maxVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Versions to protect from removal for all transfers of the component, see ProtectVersion= in sysupdate.components(5)."),
                SD_VARLINK_DEFINE_FIELD(protectVersion, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Feature,
                SD_VARLINK_FIELD_COMMENT("Identifier for the feature."),
                SD_VARLINK_DEFINE_FIELD(id, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("A short human readable description of the feature."),
                SD_VARLINK_DEFINE_FIELD(description, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("URLs to documentation for the feature."),
                SD_VARLINK_DEFINE_FIELD(documentation, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("URLs to zero or more AppStream catalog XML files describing the feature."),
                SD_VARLINK_DEFINE_FIELD(appStream, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY),
                SD_VARLINK_FIELD_COMMENT("Whether the feature is enabled."),
                SD_VARLINK_DEFINE_FIELD(enabled, SD_VARLINK_BOOL, 0),
                SD_VARLINK_FIELD_COMMENT("Whether the feature is suggested for enablement."),
                SD_VARLINK_DEFINE_FIELD(suggested, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Array of IDs of the transfers (including currently disabled ones) which are controlled by this feature."),
                SD_VARLINK_DEFINE_FIELD(transfers, SD_VARLINK_STRING, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD(
                ListFeatures,
                SD_VARLINK_FIELD_COMMENT("Target to list features for."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, 0),
                SD_VARLINK_FIELD_COMMENT("The configured features."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(features, Feature, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_METHOD_FULL(
                CheckNew,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Target to check for updates for. If not specified, the default installation of the host (if there is one) and all of its enabled components are checked, similar to the --component-all switch of systemd-sysupdate(8). In that case the 'more' flag must be set, and one reply is sent for each of them, regardless of whether a new version is available. If there is nothing to check, the NoSuchTarget error is returned."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("If no target is specified, the component the reply refers to. Unset for the default installation."),
                SD_VARLINK_DEFINE_OUTPUT(component, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The version string for the new version which is available. If no target is specified and no new version is available for the component, this is null. (If a target is specified, the NoUpdateNeeded error is returned instead in that case.)"),
                SD_VARLINK_DEFINE_OUTPUT(available, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                UpdateAction,
                SD_VARLINK_FIELD_COMMENT("Acquire (download) the new version and install it, see the 'update' command of systemd-sysupdate(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(update),
                SD_VARLINK_FIELD_COMMENT("Only acquire (download) the new version, see the 'acquire' command of systemd-sysupdate(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(acquire),
                SD_VARLINK_FIELD_COMMENT("Only install a previously acquired new version, see 'update --offline' in systemd-sysupdate(8)."),
                SD_VARLINK_DEFINE_ENUM_VALUE(install));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                UpdatePhase,
                SD_VARLINK_FIELD_COMMENT("Waiting for another update of the same component to finish."),
                SD_VARLINK_DEFINE_ENUM_VALUE(waiting_for_lock),
                SD_VARLINK_FIELD_COMMENT("Loading the definitions and determining the version to update to."),
                SD_VARLINK_DEFINE_ENUM_VALUE(preparing),
                SD_VARLINK_FIELD_COMMENT("Removing old versions to make room for the new one."),
                SD_VARLINK_DEFINE_ENUM_VALUE(vacuuming),
                SD_VARLINK_FIELD_COMMENT("Acquiring (downloading) a transfer of the new version."),
                SD_VARLINK_DEFINE_ENUM_VALUE(acquiring),
                SD_VARLINK_FIELD_COMMENT("Installing the new version."),
                SD_VARLINK_DEFINE_ENUM_VALUE(installing),
                SD_VARLINK_FIELD_COMMENT("Notifying other components about the new version."),
                SD_VARLINK_DEFINE_ENUM_VALUE(notifying));

static SD_VARLINK_DEFINE_METHOD_FULL(
                Update,
                SD_VARLINK_SUPPORTS_MORE,
                SD_VARLINK_FIELD_COMMENT("Target to update. If not specified, the default installation of the host and all of its enabled components are updated, similar to the --component-all switch of systemd-sysupdate(8)."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(target, TargetIdentifier, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The version to update to. If not specified, updates to the newest version available."),
                SD_VARLINK_DEFINE_INPUT(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("What to do. Defaults to 'update'."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(action, UpdateAction, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The maximum number of update iterations to run, see the --loop= switch of systemd-sysupdate(8). Values above 1 are only permitted for the 'update' and 'install' actions. Defaults to 1, like the command line tool, but for unattended updates a higher value such as 16 (which is what systemd-sysupdate-update.service uses) is recommended."),
                SD_VARLINK_DEFINE_INPUT(loop, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Whether to remove resources of components that are no longer installed, see the --cleanup= switch of systemd-sysupdate(8). Defaults to false."),
                SD_VARLINK_DEFINE_INPUT(cleanup, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                VARLINK_DEFINE_POLKIT_INPUT,
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, the phase of the update is sent in progress notifications. Note that phases might be added in later versions, and clients should ignore phases they do not know."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(phase, UpdatePhase, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, the update iteration (counting from 1) the progress notification refers to, see the 'loop' parameter."),
                SD_VARLINK_DEFINE_OUTPUT(iteration, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, the component the progress notification refers to. Unset for the default installation."),
                SD_VARLINK_DEFINE_OUTPUT(component, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, the identifier of the transfer the progress notification refers to, if any."),
                SD_VARLINK_DEFINE_OUTPUT(transfer, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, the version the progress notification refers to, if known."),
                SD_VARLINK_DEFINE_OUTPUT(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("If used with the 'more' flag, a progress percentage, specific to the phase, component and transfer. Only sent if known."),
                SD_VARLINK_DEFINE_OUTPUT(progress, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("In the final reply, whether a new version was installed."),
                SD_VARLINK_DEFINE_OUTPUT(installed, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("In the final reply, whether a reboot is needed to activate the newly installed version. Only set for targets of class 'host', and only if the booted version is known."),
                SD_VARLINK_DEFINE_OUTPUT(rebootNeeded, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                ListTargets,
                SD_VARLINK_FIELD_COMMENT("The configured targets."),
                SD_VARLINK_DEFINE_OUTPUT_BY_TYPE(targets, Target, SD_VARLINK_ARRAY));

static SD_VARLINK_DEFINE_ERROR(NoUpdateNeeded);
SD_VARLINK_DEFINE_ERROR(NoSuchTarget);
static SD_VARLINK_DEFINE_ERROR(ComponentDisabled);

SD_VARLINK_DEFINE_INTERFACE_FULL(
                io_systemd_SysUpdate,
                "io.systemd.SysUpdate",
                SD_VARLINK_EXPERIMENTAL,
                SD_VARLINK_INTERFACE_COMMENT("APIs to manage system updates"),

                /* Methods */
                SD_VARLINK_SYMBOL_COMMENT("Show optional features"),
                &vl_method_ListFeatures,
                SD_VARLINK_SYMBOL_COMMENT("Check if there’s a new version available"),
                &vl_method_CheckNew,
                SD_VARLINK_SYMBOL_COMMENT("Show targets"),
                &vl_method_ListTargets,
                SD_VARLINK_SYMBOL_COMMENT("Update a target to a new version. If invoked with the 'more' flag, reports progress via notifications, otherwise only replies once the update is complete. Note that the update is not affected if the client disconnects before it is complete."),
                &vl_method_Update,

                /* Types */
                SD_VARLINK_SYMBOL_COMMENT("Class of a Target."),
                &vl_type_TargetClass,
                SD_VARLINK_SYMBOL_COMMENT("Identifier for a component of the system (i.e. the host itself, a sysext, a confext, etc.) that can be updated by systemd-sysupdate(8)."),
                &vl_type_TargetIdentifier,
                SD_VARLINK_SYMBOL_COMMENT("Action to take after a component has been updated successfully."),
                &vl_type_ComponentSuccessAction,
                SD_VARLINK_SYMBOL_COMMENT("Action to take if updating a component failed."),
                &vl_type_ComponentFailureAction,
                SD_VARLINK_SYMBOL_COMMENT("Type containing a configured sysupdate target, along with its metadata if it is a component."),
                &vl_type_Target,
                SD_VARLINK_SYMBOL_COMMENT("Type containing a configured sysupdate feature."),
                &vl_type_Feature,
                SD_VARLINK_SYMBOL_COMMENT("The action to execute when updating."),
                &vl_type_UpdateAction,
                SD_VARLINK_SYMBOL_COMMENT("Phase of an update, reported in progress notifications."),
                &vl_type_UpdatePhase,

                /* Errors */
                SD_VARLINK_SYMBOL_COMMENT("Error indicating that no update is currently available to update to."),
                &vl_error_NoUpdateNeeded,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating the specified target doesn’t exist, or, if no target is specified, that there's nothing to operate on"),
                &vl_error_NoSuchTarget,
                SD_VARLINK_SYMBOL_COMMENT("Error indicating the specified target is a component that exists, but is disabled"),
                &vl_error_ComponentDisabled);
