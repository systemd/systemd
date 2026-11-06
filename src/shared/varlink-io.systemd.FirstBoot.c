/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.FirstBoot.h"

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                Settings,
                SD_VARLINK_FIELD_COMMENT("The system locale, i.e. LANG=, e.g. 'de_DE.UTF-8'."),
                SD_VARLINK_DEFINE_FIELD(locale, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The locale for messages, i.e. LC_MESSAGES=."),
                SD_VARLINK_DEFINE_FIELD(localeMessages, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The console keymap, e.g. 'de'."),
                SD_VARLINK_DEFINE_FIELD(keymap, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The timezone, e.g. 'Europe/Berlin'."),
                SD_VARLINK_DEFINE_FIELD(timezone, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The static hostname."),
                SD_VARLINK_DEFINE_FIELD(hostname, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The machine ID, formatted as 32 hexadecimal characters. Only accepted when a root directory or image is specified, or force is true."),
                SD_VARLINK_DEFINE_FIELD(machineId, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Tags to label the machine with, see machine-info(5)."),
                SD_VARLINK_DEFINE_FIELD(machineTags, SD_VARLINK_STRING, SD_VARLINK_ARRAY|SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The root password in plain text, it is hashed before it is stored anywhere. Mutually exclusive with rootPasswordHashed."),
                SD_VARLINK_DEFINE_FIELD(rootPassword, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The root password, already hashed in a format crypt(3) understands. Mutually exclusive with rootPassword."),
                SD_VARLINK_DEFINE_FIELD(rootPasswordHashed, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The shell of the root user, as absolute path."),
                SD_VARLINK_DEFINE_FIELD(rootShell, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Additional kernel command line options."),
                SD_VARLINK_DEFINE_FIELD(kernelCommandLine, SD_VARLINK_STRING, SD_VARLINK_NULLABLE));

static SD_VARLINK_DEFINE_METHOD(
                Configure,
                SD_VARLINK_FIELD_COMMENT("Index of a file descriptor passed along with the call, referring to the root directory to operate on. If unset, the host is configured. Mutually exclusive with imageFileDescriptor."),
                SD_VARLINK_DEFINE_INPUT(rootFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Index of a file descriptor passed along with the call, referring to a disk image or block device to operate on, instead of the host. It is dissected and mounted for this. Mutually exclusive with rootFileDescriptor."),
                SD_VARLINK_DEFINE_INPUT(imageFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Image policy to dissect the image with, see systemd.image-policy(7)."),
                SD_VARLINK_DEFINE_INPUT(imagePolicy, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The settings to apply, at least one must be set."),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(settings, Settings, 0),
                SD_VARLINK_FIELD_COMMENT("If true, overwrite existing configuration files, like the --force switch. Defaults to false, i.e. settings that are already configured are left as they are."),
                SD_VARLINK_DEFINE_INPUT(force, SD_VARLINK_BOOL, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("The names of the fields of the settings parameter that were written to the system. Specified settings that were skipped, because they were configured already, are not listed."),
                SD_VARLINK_DEFINE_OUTPUT(applied, SD_VARLINK_STRING, SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE_FULL(
                io_systemd_FirstBoot,
                "io.systemd.FirstBoot",
                SD_VARLINK_EXPERIMENTAL,
                SD_VARLINK_INTERFACE_COMMENT("API for provisioning systems with basic settings, see systemd-firstboot(1)."),

                SD_VARLINK_SYMBOL_COMMENT("Basic system settings, as systemd-firstboot configures them."),
                &vl_type_Settings,

                SD_VARLINK_SYMBOL_COMMENT("Applies settings to the host, or to the root directory or disk image passed as file descriptor, the same way the systemd-firstboot command line tool does. Settings that are already configured are not changed, unless force is set. Requires root privileges."),
                &vl_method_Configure);
