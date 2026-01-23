/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.NamespaceResource.h"

static SD_VARLINK_DEFINE_METHOD(
                AllocateUserRange,
                SD_VARLINK_FIELD_COMMENT("The name for the user namespace, a short string that must be fit to be included in a file name and in a user name. This name is included in the user records announced via NSS and is otherwise useful for debugging."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Controls whether to mangle the provided name if needed so that it is suitable for naming a user namespace. If true this will shorten the name as necessary or randomize it if that's not sufficient. If null defaults to false."),
                SD_VARLINK_DEFINE_INPUT(mangleName, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The number of UIDs to assign. Must be 1 or 65536."),
                SD_VARLINK_DEFINE_INPUT(size, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The target UID inside the user namespace. If not specified defaults to 0."),
                SD_VARLINK_DEFINE_INPUT(target, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A file descriptor to an allocated userns with no current UID range assignments"),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("Number of transient 64K container UID/GID ranges to delegate. These are mapped 1:1 into the user namespace and can be used by nested user namespaces for container workloads. Must be between 0 and 16. Defaults to 0."),
                SD_VARLINK_DEFINE_INPUT(delegateContainerRanges, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The name assigned to the user namespace. (This is particularly interesting in case mangleName was enabled)."),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                RegisterUserNamespace,
                SD_VARLINK_FIELD_COMMENT("The name for the user namespace, a short string that must be fit to be included in a file name and in a user name, as in AllocateUserRange()."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Controls whether to mangle the provided name if needed so that it is suitable for naming a user namespace, as in AllocateUserRange()"),
                SD_VARLINK_DEFINE_INPUT(mangleName, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("A user namespace file descriptor that is fully initialized"),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("The name assigned to the user namespace"),
                SD_VARLINK_DEFINE_OUTPUT(name, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                AddMountToUserNamespace,
                SD_VARLINK_FIELD_COMMENT("A user namespace file descriptor previously allocated via AllocateUserRange() or registered via RegisterUserNamespace()."),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("A mount file descriptor for the mount to allowlist for the specified user namespace."),
                SD_VARLINK_DEFINE_INPUT(mountFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                AddControlGroupToUserNamespace,
                SD_VARLINK_FIELD_COMMENT("A user namespace file descriptor previously allocated via AllocateUserRange() or registered via RegisterUserNamespace()."),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("A file descriptor referencing a cgroup to assign to the root user of the specified user namespace."),
                SD_VARLINK_DEFINE_INPUT(controlGroupFileDescriptor, SD_VARLINK_INT, 0));

static SD_VARLINK_DEFINE_METHOD(
                AddNetworkToUserNamespace,
                SD_VARLINK_FIELD_COMMENT("A user namespace file descriptor previously allocated via AllocateUserRange() or registered via RegisterUserNamespace()."),
                SD_VARLINK_DEFINE_INPUT(userNamespaceFileDescriptor, SD_VARLINK_INT, 0),
                SD_VARLINK_FIELD_COMMENT("A network namespace file descriptor to assign the network interface to. Only applies to network interfaces of type 'veth'."),
                SD_VARLINK_DEFINE_INPUT(networkNamespaceFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The network interface name to use for the network interface inside the network namespace. Only applies to network interfaces of type 'veth'."),
                SD_VARLINK_DEFINE_INPUT(namespaceInterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The networking mode, one of 'veth' or 'tap'. If the former is selected a virtual Ethernet link between host and namespace is created. If the latter is selected an Ethernet Tap link is created and a file descriptor is returned for the namespace side."),
                SD_VARLINK_DEFINE_INPUT(mode, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The chosen network interface name for the host side of the network."),
                SD_VARLINK_DEFINE_OUTPUT(hostInterfaceName, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The chosen network interface name for the namespace side of the network. Only applies to network interfaces of type 'veth'."),
                SD_VARLINK_DEFINE_OUTPUT(namespaceInterfaceName, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The file descriptor for the namespace side of the network. Only applies to network interfaces of type 'tap'."),
                SD_VARLINK_DEFINE_OUTPUT(interfaceFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(UserNamespaceInterfaceNotSupported);
static SD_VARLINK_DEFINE_ERROR(NameExists);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceExists);
static SD_VARLINK_DEFINE_ERROR(DynamicRangeUnavailable);
static SD_VARLINK_DEFINE_ERROR(NoDynamicRange);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceNotRegistered);
static SD_VARLINK_DEFINE_ERROR(UserNamespaceWithoutUserRange);
static SD_VARLINK_DEFINE_ERROR(TooManyControlGroups);
static SD_VARLINK_DEFINE_ERROR(ControlGroupAlreadyAdded);
static SD_VARLINK_DEFINE_ERROR(TooManyNetworkInterfaces);
static SD_VARLINK_DEFINE_ERROR(TooManyDelegations);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_NamespaceResource,
                "io.systemd.NamespaceResource",
                SD_VARLINK_INTERFACE_COMMENT("Allocate transient UID ranges for user namespace, and assign mounts, cgroups and networking devices to them"),
                SD_VARLINK_SYMBOL_COMMENT("Assigns a UID range to a client-allocated user namespace that has no UID range assigned so far, and registers it for assignment of other resources."),
                &vl_method_AllocateUserRange,
                SD_VARLINK_SYMBOL_COMMENT("Registers an already initialized user namespace for assignment of resources."),
                &vl_method_RegisterUserNamespace,
                SD_VARLINK_SYMBOL_COMMENT("Adds a mount to a user namespace previously allocated or registered via AllocateUserRange() or RegisterUserNamespace(). This allowlists the mount for access by the user namespace."),
                &vl_method_AddMountToUserNamespace,
                SD_VARLINK_SYMBOL_COMMENT("Adds a cgroup to a user namespace previously allocated or registered via AllocateUserRange() or RegisterUserNamespace(). This passes ownership of the referenced cgroup to the user namespace's root user, and ensures the cgroup gets deleted when the user namespace is released."),
                &vl_method_AddControlGroupToUserNamespace,
                SD_VARLINK_SYMBOL_COMMENT("Adds a network interface to a user namespace previously allocated or registered via AllocateUserRange() or RegisterUserNamespace(). This creates a 'veth' or 'tap' device that is assigned to the user namespace, or owned by its root user."),
                &vl_method_AddNetworkToUserNamespace,
                SD_VARLINK_SYMBOL_COMMENT("User namespace delegation via io.systemd.NamespaceResource is not supported."),
                &vl_error_UserNamespaceInterfaceNotSupported,
                SD_VARLINK_SYMBOL_COMMENT("A user namespace under the specified name exists already."),
                &vl_error_NameExists,
                SD_VARLINK_SYMBOL_COMMENT("The specified user namespace has been registered before."),
                &vl_error_UserNamespaceExists,
                SD_VARLINK_SYMBOL_COMMENT("The dynamic UID range is exhausted already."),
                &vl_error_DynamicRangeUnavailable,
                SD_VARLINK_SYMBOL_COMMENT("The dynamic UID range is not available on this system."),
                &vl_error_NoDynamicRange,
                SD_VARLINK_SYMBOL_COMMENT("The specified user namespace has not been registered."),
                &vl_error_UserNamespaceNotRegistered,
                SD_VARLINK_SYMBOL_COMMENT("The specified user namespace has no UID range assigned."),
                &vl_error_UserNamespaceWithoutUserRange,
                SD_VARLINK_SYMBOL_COMMENT("The per-user namespace limit of cgroups has been reached."),
                &vl_error_TooManyControlGroups,
                SD_VARLINK_SYMBOL_COMMENT("The specified cgroup has already been added to the user namespace."),
                &vl_error_ControlGroupAlreadyAdded,
                SD_VARLINK_SYMBOL_COMMENT("The per-user namespace limit of network interfaces has been reached."),
                &vl_error_TooManyNetworkInterfaces,
                SD_VARLINK_SYMBOL_COMMENT("The specified number of delegations exceeds the maximum allowed."),
                &vl_error_TooManyDelegations);
