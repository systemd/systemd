/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.ResourceProvider.h"

static SD_VARLINK_DEFINE_METHOD_FULL(
                AcquireResource,
                SD_VARLINK_REQUIRES_UPGRADE,
                SD_VARLINK_FIELD_COMMENT("The name of the resource to acquire. This is the part of a 'provider:[…]/…' URL following the closing bracket and slash, i.e. an opaque, non-empty string that may contain slashes, but no '.' or '..' components."),
                SD_VARLINK_DEFINE_INPUT(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("The size of the resource in bytes, if known. Clients may use this for progress reporting and to detect truncated transfers."),
                SD_VARLINK_DEFINE_OUTPUT(size, SD_VARLINK_INT, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_ERROR(NoSuchResource);

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_ResourceProvider,
                "io.systemd.ResourceProvider",
                SD_VARLINK_INTERFACE_COMMENT("Generic interface for acquiring the contents of named resources from a local service. "
                                             "It is addressed via URLs of the form 'provider:[/path/to/socket]/resource', which "
                                             "systemd-pull(1) accepts wherever it accepts HTTP URLs, e.g. in systemd-sysupdate(8) "
                                             "transfer definitions. The resource contents are transferred via a protocol upgrade: "
                                             "after the reply to AcquireResource() the connection carries the raw resource data until "
                                             "the provider closes it."),
                SD_VARLINK_SYMBOL_COMMENT("Acquires the resource with the specified name. Must be called with the 'upgrade' flag set. "
                                          "On success the provider replies (optionally announcing the size) and then writes the raw "
                                          "resource contents to the connection, closing it once all data has been written. Errors can "
                                          "only be reported before the upgrade; a connection closed before the announced size was "
                                          "reached indicates a truncated transfer."),
                &vl_method_AcquireResource,
                SD_VARLINK_SYMBOL_COMMENT("No resource by the specified name exists."),
                &vl_error_NoSuchResource);
