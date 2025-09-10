/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "varlink-io.systemd.KernelInstall.h"

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntryType,
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #1 entries (.conf files)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type1),
                SD_VARLINK_FIELD_COMMENT("Boot Loader Specification Type #2 entries (UKIs)"),
                SD_VARLINK_DEFINE_ENUM_VALUE(type2),
                SD_VARLINK_FIELD_COMMENT("Additional entries reported by boot loader"),
                SD_VARLINK_DEFINE_ENUM_VALUE(loader),
                SD_VARLINK_FIELD_COMMENT("Automatically generated entries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                BootEntryTokenType,
                SD_VARLINK_FIELD_COMMENT("Identify Type #1 boot entries via /etc/machine-id."),
                SD_VARLINK_DEFINE_ENUM_VALUE(machine_id),
                SD_VARLINK_FIELD_COMMENT("Identify Type #1 boot entries via the IMAGE_ID= field from /etc/os-release"),
                SD_VARLINK_DEFINE_ENUM_VALUE(os_image_id),
                SD_VARLINK_FIELD_COMMENT("Identify Type #1 boot entries via the ID= field from /etc/os-release"),
                SD_VARLINK_DEFINE_ENUM_VALUE(os_id),
                SD_VARLINK_FIELD_COMMENT("Identity type #1 boot entries via a manually chosen string"),
                SD_VARLINK_DEFINE_ENUM_VALUE(literal),
                SD_VARLINK_FIELD_COMMENT("Automatically choose how to identify type #1 boot entries"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                KernelSearch,
                SD_VARLINK_FIELD_COMMENT("Path to the kernel image has been passed literally"),
                SD_VARLINK_DEFINE_ENUM_VALUE(literal),
                SD_VARLINK_FIELD_COMMENT("Kernel image will be searched for in /usr/lib/modules/"),
                SD_VARLINK_DEFINE_ENUM_VALUE(usr),
                SD_VARLINK_FIELD_COMMENT("Currently booted kernel image is used"),
                SD_VARLINK_DEFINE_ENUM_VALUE(current));

static SD_VARLINK_DEFINE_ENUM_TYPE(
                InstallSource,
                SD_VARLINK_FIELD_COMMENT("Copy installation files from the image into the image's boot file system"),
                SD_VARLINK_DEFINE_ENUM_VALUE(image),
                SD_VARLINK_FIELD_COMMENT("Copy installation files from the host into the image's boot file system"),
                SD_VARLINK_DEFINE_ENUM_VALUE(host),
                SD_VARLINK_FIELD_COMMENT("Copy installation files from the image into the image's boot file system if they exist, otherwise from the host"),
                SD_VARLINK_DEFINE_ENUM_VALUE(auto));

static SD_VARLINK_DEFINE_STRUCT_TYPE(
                ExtraFile,
                SD_VARLINK_FIELD_COMMENT("Filename for the extra file to place next to the UKI when installing"),
                SD_VARLINK_DEFINE_FIELD(name, SD_VARLINK_STRING, 0),
                SD_VARLINK_FIELD_COMMENT("Contents for the extra file (Base64 encoded)"),
                SD_VARLINK_DEFINE_FIELD(data, SD_VARLINK_STRING, 0));

static SD_VARLINK_DEFINE_METHOD(
                Add,
                SD_VARLINK_FIELD_COMMENT("Index into file descriptor array associated with this message, referencing the root directory to operate in."),
                SD_VARLINK_DEFINE_INPUT(rootFileDescriptor, SD_VARLINK_INT, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to root directory to operate in. Purely informational when rootFileDescriptor is specified too."),
                SD_VARLINK_DEFINE_INPUT(rootDirectory, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("kernel version to install"),
                SD_VARLINK_DEFINE_INPUT(version, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Path to kernel image to install"),
                SD_VARLINK_DEFINE_INPUT(kernel, SD_VARLINK_STRING, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Boot entry type to generate"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(bootEntryType, BootEntryType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("How to determine the kernel to install"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(kernelSearch, KernelSearch, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Where to copy kernels from, when operating relative to a root directory"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(installSource, InstallSource, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Entry token type selection"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(bootEntryTokenType, BootEntryTokenType, SD_VARLINK_NULLABLE),
                SD_VARLINK_FIELD_COMMENT("Additional files to place next to the installed UKI in the .extra.d/ directory"),
                SD_VARLINK_DEFINE_INPUT_BY_TYPE(extraFiles, ExtraFile, SD_VARLINK_NULLABLE|SD_VARLINK_ARRAY));

SD_VARLINK_DEFINE_INTERFACE(
                io_systemd_KernelInstall,
                "io.systemd.KernelInstall",
                SD_VARLINK_INTERFACE_COMMENT("Kernel Installation APIs"),
                SD_VARLINK_SYMBOL_COMMENT("The type of a boot entry"),
                &vl_type_BootEntryType,
                SD_VARLINK_SYMBOL_COMMENT("The type of token for identifying entries belonging to an OS installation"),
                &vl_type_BootEntryTokenType,
                SD_VARLINK_SYMBOL_COMMENT("How to find the kernel image to install"),
                &vl_type_KernelSearch,
                SD_VARLINK_SYMBOL_COMMENT("Which source to install the kernel image from"),
                &vl_type_InstallSource,
                SD_VARLINK_SYMBOL_COMMENT("Information about an extra file to install along with an UKI"),
                &vl_type_ExtraFile,
                SD_VARLINK_SYMBOL_COMMENT("Install a kernel image"),
                &vl_method_Add);
