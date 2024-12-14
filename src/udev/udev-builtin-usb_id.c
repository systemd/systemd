/* SPDX-License-Identifier: GPL-2.0-or-later */
/*
 * USB device properties and persistent device path
 *
 * Copyright (c) 2005 SUSE Linux Products GmbH, Germany
 *   Author: Hannes Reinecke <hare@suse.de>
 */

#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <stdarg.h>
#include <stdio.h>
#include <unistd.h>

#include "alloc-util.h"
#include "device-nodes.h"
#include "device-util.h"
#include "fd-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-builtin.h"
#include "udev-util.h"

static void set_usb_iftype(char *to, int if_class_num, size_t len) {
        const char *type = "generic";

        switch (if_class_num) {
        case 1:
                type = "audio";
                break;
        case 2: /* CDC-Control */
                break;
        case 3:
                type = "hid";
                break;
        case 5: /* Physical */
                break;
        case 6:
                type = "media";
                break;
        case 7:
                type = "printer";
                break;
        case 8:
                type = "storage";
                break;
        case 9:
                type = "hub";
                break;
        case 0x0a: /* CDC-Data */
                break;
        case 0x0b: /* Chip/Smart Card */
                break;
        case 0x0d: /* Content Security */
                break;
        case 0x0e:
                type = "video";
                break;
        case 0xdc: /* Diagnostic Device */
                break;
        case 0xe0: /* Wireless Controller */
                break;
        case 0xfe: /* Application-specific */
                break;
        case 0xff: /* Vendor-specific */
                break;
        default:
                break;
        }
        strncpy(to, type, len);
        to[len-1] = '\0';
}

static int set_usb_mass_storage_ifsubtype(char *to, const char *from, size_t len) {
        int type_num = 0;
        const char *type = "generic";

        if (safe_atoi(from, &type_num) >= 0) {
                switch (type_num) {
                case 1: /* RBC devices */
                        type = "rbc";
                        break;
                case 2:
                        type = "atapi";
                        break;
                case 3:
                        type = "tape";
                        break;
                case 4: /* UFI */
                        type = "floppy";
                        break;
                case 6: /* Transparent SPC-2 devices */
                        type = "scsi";
                        break;
                default:
                        break;
                }
        }
        strscpy(to, len, type);
        return type_num;
}

static void set_scsi_type(char *to, const char *from, size_t len) {
        unsigned type_num;
        const char *type = "generic";

        if (safe_atou(from, &type_num) >= 0) {
                switch (type_num) {
                case 0:
                case 0xe:
                        type = "disk";
                        break;
                case 1:
                        type = "tape";
                        break;
                case 4:
                case 7:
                case 0xf:
                        type = "optical";
                        break;
                case 5:
                        type = "cd";
                        break;
                default:
                        break;
                }
        }
        strscpy(to, len, type);
}

#define USB_DT_DEVICE                        0x01
#define USB_DT_INTERFACE                0x04

static int dev_if_packed_info(sd_device *dev, char *ifs_str, size_t len) {
        _cleanup_close_ int fd = -EBADF;
        ssize_t size;
        unsigned char buf[18 + 65535];
        size_t pos = 0;
        unsigned strpos = 0;
        const char *filename, *syspath;
        int r;
        struct usb_interface_descriptor {
                uint8_t bLength;
                uint8_t bDescriptorType;
                uint8_t bInterfaceNumber;
                uint8_t bAlternateSetting;
                uint8_t bNumEndpoints;
                uint8_t bInterfaceClass;
                uint8_t bInterfaceSubClass;
                uint8_t bInterfaceProtocol;
                uint8_t iInterface;
        } _packed_;

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        filename = strjoina(syspath, "/descriptors");
        fd = open(filename, O_RDONLY|O_CLOEXEC|O_NOCTTY);
        if (fd < 0)
                return log_device_debug_errno(dev, errno, "Failed to open \"%s\": %m", filename);

        size = read(fd, buf, sizeof(buf));
        if (size < 18)
                return log_device_warning_errno(dev, SYNTHETIC_ERRNO(EIO),
                                                "Short read from \"%s\"", filename);
        assert((size_t) size <= sizeof buf);

        ifs_str[0] = '\0';
        while (pos + sizeof(struct usb_interface_descriptor) < (size_t) size &&
               strpos + 7 < len - 2) {

                struct usb_interface_descriptor *desc;
                char if_str[8];

                desc = (struct usb_interface_descriptor *) (buf + pos);
                if (desc->bLength < 3)
                        break;
                if (desc->bLength > size - sizeof(struct usb_interface_descriptor))
                        return log_device_debug_errno(dev, SYNTHETIC_ERRNO(EIO),
                                                      "Corrupt data read from \"%s\"", filename);
                pos += desc->bLength;

                if (desc->bDescriptorType != USB_DT_INTERFACE)
                        continue;

                if (snprintf(if_str, 8, ":%02x%02x%02x",
                             desc->bInterfaceClass,
                             desc->bInterfaceSubClass,
                             desc->bInterfaceProtocol) != 7)
                        continue;

                if (strstr(ifs_str, if_str))
                        continue;

                memcpy(&ifs_str[strpos], if_str, 8),
                strpos += 7;
        }

        if (strpos > 0) {
                ifs_str[strpos++] = ':';
                ifs_str[strpos++] = '\0';
        }

        return 0;
}

/*
 * A unique USB identification is generated like this:
 *
 * 1.) Get the USB device type from InterfaceClass and InterfaceSubClass
 * 2.) If the device type is 'Mass-Storage/SPC-2' or 'Mass-Storage/RBC',
 *     use the SCSI vendor and model as USB-Vendor and USB-model.
 * 3.) Otherwise, use the USB manufacturer and product as
 *     USB-Vendor and USB-model. Any non-printable characters
 *     in those strings will be skipped; a slash '/' will be converted
 *     into a full stop '.'.
 * 4.) If that fails, too, we will use idVendor and idProduct
 *     as USB-Vendor and USB-model.
 * 5.) The USB identification is the USB-vendor and USB-model
 *     string concatenated with an underscore '_'.
 * 6.) If the device supplies a serial number, this number
 *     is concatenated with the identification with an underscore '_'.
 */
static int builtin_usb_id(UdevEvent *event, int argc, char *argv[]) {
        sd_device *dev_interface, *dev_usb, *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        const char *syspath, *sysname, *interface_syspath, *vendor_id, *product_id,
                *ifnum = NULL, *driver = NULL, *if_class, *if_subclass;
        char *s, model_str[64] = "", model_str_enc[256], serial_str[UDEV_NAME_SIZE] = "",
                packed_if_str[UDEV_NAME_SIZE] = "", revision_str[64] = "", type_str[64] = "",
                instance_str[64] = "", serial[256], vendor_str[64] = "", vendor_str_enc[256];
        unsigned if_class_num;
        int r, protocol = 0;
        size_t l;

        r = sd_device_get_syspath(dev, &syspath);
        if (r < 0)
                return r;

        r = sd_device_get_sysname(dev, &sysname);
        if (r < 0)
                return r;

        /* shortcut, if we are called directly for a "usb_device" type */
        if (device_is_devtype(dev, "usb_device")) {
                dev_if_packed_info(dev, packed_if_str, sizeof(packed_if_str));
                dev_usb = dev;
                goto fallback;
        }

        /* usb interface directory */
        r = sd_device_get_parent_with_subsystem_devtype(dev, "usb", "usb_interface", &dev_interface);
        if (r < 0)
                return log_device_debug_errno(dev, r, "Failed to access usb_interface: %m");

        r = sd_device_get_syspath(dev_interface, &interface_syspath);
        if (r < 0)
                return log_device_debug_errno(dev_interface, r, "Failed to get syspath: %m");
        (void) sd_device_get_sysattr_value(dev_interface, "bInterfaceNumber", &ifnum);
        (void) sd_device_get_sysattr_value(dev_interface, "driver", &driver);

        r = sd_device_get_sysattr_value(dev_interface, "bInterfaceClass", &if_class);
        if (r < 0)
                return log_device_debug_errno(dev_interface, r, "Failed to get bInterfaceClass attribute: %m");

        r = safe_atou_full(if_class, 16, &if_class_num);
        if (r < 0)
                return log_device_debug_errno(dev_interface, r, "Failed to parse if_class: %m");
        if (if_class_num == 8) {
                /* mass storage */
                if (sd_device_get_sysattr_value(dev_interface, "bInterfaceSubClass", &if_subclass) >= 0)
                        protocol = set_usb_mass_storage_ifsubtype(type_str, if_subclass, sizeof(type_str)-1);
        } else
                set_usb_iftype(type_str, if_class_num, sizeof(type_str)-1);

        log_device_debug(dev_interface, "if_class:%u protocol:%i", if_class_num, protocol);

        /* usb device directory */
        r = sd_device_get_parent_with_subsystem_devtype(dev_interface, "usb", "usb_device", &dev_usb);
        if (r < 0)
                return log_device_debug_errno(dev_interface, r, "Failed to find parent 'usb' device");

        /* all interfaces of the device in a single string */
        dev_if_packed_info(dev_usb, packed_if_str, sizeof(packed_if_str));

        /* mass storage : SCSI or ATAPI */
        if (IN_SET(protocol, 6, 2)) {
                sd_device *dev_scsi;
                const char *scsi_sysname, *scsi_model, *scsi_vendor, *scsi_type, *scsi_rev;
                int host, bus, target, lun;

                /* get scsi device */
                r = sd_device_get_parent_with_subsystem_devtype(dev, "scsi", "scsi_device", &dev_scsi);
                if (r < 0) {
                        log_device_debug_errno(dev, r, "Unable to find parent SCSI device");
                        goto fallback;
                }
                if (sd_device_get_sysname(dev_scsi, &scsi_sysname) < 0)
                        goto fallback;
                if (sscanf(scsi_sysname, "%d:%d:%d:%d", &host, &bus, &target, &lun) != 4) {
                        log_device_debug(dev_scsi, "Invalid SCSI device");
                        goto fallback;
                }

                /* Generic SPC-2 device */
                r = sd_device_get_sysattr_value(dev_scsi, "vendor", &scsi_vendor);
                if (r < 0) {
                        log_device_debug_errno(dev_scsi, r, "Failed to get SCSI vendor attribute: %m");
                        goto fallback;
                }
                encode_devnode_name(scsi_vendor, vendor_str_enc, sizeof(vendor_str_enc));
                udev_replace_whitespace(scsi_vendor, vendor_str, sizeof(vendor_str)-1);
                udev_replace_chars(vendor_str, NULL);

                r = sd_device_get_sysattr_value(dev_scsi, "model", &scsi_model);
                if (r < 0) {
                        log_device_debug_errno(dev_scsi, r, "Failed to get SCSI model attribute: %m");
                        goto fallback;
                }
                encode_devnode_name(scsi_model, model_str_enc, sizeof(model_str_enc));
                udev_replace_whitespace(scsi_model, model_str, sizeof(model_str)-1);
                udev_replace_chars(model_str, NULL);

                r = sd_device_get_sysattr_value(dev_scsi, "type", &scsi_type);
                if (r < 0) {
                        log_device_debug_errno(dev_scsi, r, "Failed to get SCSI type attribute: %m");
                        goto fallback;
                }
                set_scsi_type(type_str, scsi_type, sizeof(type_str)-1);

                r = sd_device_get_sysattr_value(dev_scsi, "rev", &scsi_rev);
                if (r < 0) {
                        log_device_debug_errno(dev_scsi, r, "Failed to get SCSI revision attribute: %m");
                        goto fallback;
                }
                udev_replace_whitespace(scsi_rev, revision_str, sizeof(revision_str)-1);
                udev_replace_chars(revision_str, NULL);

                /*
                 * some broken devices have the same identifiers
                 * for all luns, export the target:lun number
                 */
                sprintf(instance_str, "%d:%d", target, lun);
        }

fallback:
        r = sd_device_get_sysattr_value(dev_usb, "idVendor", &vendor_id);
        if (r < 0)
                return log_device_debug_errno(dev_usb, r, "Failed to get idVendor attribute: %m");

        r = sd_device_get_sysattr_value(dev_usb, "idProduct", &product_id);
        if (r < 0)
                return log_device_debug_errno(dev_usb, r, "Failed to get idProduct attribute: %m");

        /* fall back to USB vendor & device */
        if (vendor_str[0] == '\0') {
                const char *usb_vendor;

                if (sd_device_get_sysattr_value(dev_usb, "manufacturer", &usb_vendor) < 0)
                        usb_vendor = vendor_id;
                encode_devnode_name(usb_vendor, vendor_str_enc, sizeof(vendor_str_enc));
                udev_replace_whitespace(usb_vendor, vendor_str, sizeof(vendor_str)-1);
                udev_replace_chars(vendor_str, NULL);
        }

        if (model_str[0] == '\0') {
                const char *usb_model;

                if (sd_device_get_sysattr_value(dev_usb, "product", &usb_model) < 0)
                        usb_model = product_id;
                encode_devnode_name(usb_model, model_str_enc, sizeof(model_str_enc));
                udev_replace_whitespace(usb_model, model_str, sizeof(model_str)-1);
                udev_replace_chars(model_str, NULL);
        }

        if (revision_str[0] == '\0') {
                const char *usb_rev;

                if (sd_device_get_sysattr_value(dev_usb, "bcdDevice", &usb_rev) >= 0) {
                        udev_replace_whitespace(usb_rev, revision_str, sizeof(revision_str)-1);
                        udev_replace_chars(revision_str, NULL);
                }
        }

        if (serial_str[0] == '\0') {
                const char *usb_serial;

                if (sd_device_get_sysattr_value(dev_usb, "serial", &usb_serial) >= 0) {
                        /* http://msdn.microsoft.com/en-us/library/windows/hardware/gg487321.aspx */
                        for (const unsigned char *p = (unsigned char*) usb_serial; *p != '\0'; p++)
                                if (*p < 0x20 || *p > 0x7f || *p == ',') {
                                        usb_serial = NULL;
                                        break;
                                }

                        if (usb_serial) {
                                udev_replace_whitespace(usb_serial, serial_str, sizeof(serial_str)-1);
                                udev_replace_chars(serial_str, NULL);
                        }
                }
        }

        s = serial;
        l = strpcpyl(&s, sizeof(serial), vendor_str, "_", model_str, NULL);
        if (!isempty(serial_str))
                l = strpcpyl(&s, l, "_", serial_str, NULL);

        if (!isempty(instance_str))
                strpcpyl(&s, l, "-", instance_str, NULL);

        if (sd_device_get_property_value(dev, "ID_BUS", NULL) >= 0)
                log_device_debug(dev, "ID_BUS property is already set, setting only properties prefixed with \"ID_USB_\".");
        else {
                udev_builtin_add_property(event, "ID_BUS", "usb");

                udev_builtin_add_property(event, "ID_MODEL", model_str);
                udev_builtin_add_property(event, "ID_MODEL_ENC", model_str_enc);
                udev_builtin_add_property(event, "ID_MODEL_ID", product_id);

                udev_builtin_add_property(event, "ID_SERIAL", serial);
                if (!isempty(serial_str))
                        udev_builtin_add_property(event, "ID_SERIAL_SHORT", serial_str);

                udev_builtin_add_property(event, "ID_VENDOR", vendor_str);
                udev_builtin_add_property(event, "ID_VENDOR_ENC", vendor_str_enc);
                udev_builtin_add_property(event, "ID_VENDOR_ID", vendor_id);

                udev_builtin_add_property(event, "ID_REVISION", revision_str);

                if (!isempty(type_str))
                        udev_builtin_add_property(event, "ID_TYPE", type_str);

                if (!isempty(instance_str))
                        udev_builtin_add_property(event, "ID_INSTANCE", instance_str);
        }

        /* Also export the same values in the above by prefixing ID_USB_. */
        udev_builtin_add_property(event, "ID_USB_MODEL", model_str);
        udev_builtin_add_property(event, "ID_USB_MODEL_ENC", model_str_enc);
        udev_builtin_add_property(event, "ID_USB_MODEL_ID", product_id);
        udev_builtin_add_property(event, "ID_USB_SERIAL", serial);
        if (!isempty(serial_str))
                udev_builtin_add_property(event, "ID_USB_SERIAL_SHORT", serial_str);

        udev_builtin_add_property(event, "ID_USB_VENDOR", vendor_str);
        udev_builtin_add_property(event, "ID_USB_VENDOR_ENC", vendor_str_enc);
        udev_builtin_add_property(event, "ID_USB_VENDOR_ID", vendor_id);

        udev_builtin_add_property(event, "ID_USB_REVISION", revision_str);

        if (!isempty(type_str))
                udev_builtin_add_property(event, "ID_USB_TYPE", type_str);

        if (!isempty(instance_str))
                udev_builtin_add_property(event, "ID_USB_INSTANCE", instance_str);

        if (!isempty(packed_if_str))
                udev_builtin_add_property(event, "ID_USB_INTERFACES", packed_if_str);
        if (ifnum)
                udev_builtin_add_property(event, "ID_USB_INTERFACE_NUM", ifnum);
        if (driver)
                udev_builtin_add_property(event, "ID_USB_DRIVER", driver);
        return 0;
}

const UdevBuiltin udev_builtin_usb_id = {
        .name = "usb_id",
        .cmd = builtin_usb_id,
        .help = "USB device properties",
        .run_once = true,
};
