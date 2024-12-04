/* SPDX-License-Identifier: GPL-2.0-or-later */

#include "device-util.h"
#include "errno-util.h"
#include "parse-util.h"
#include "string-util.h"
#include "strxcpyx.h"
#include "udev-event.h"
#include "udev-format.h"
#include "udev-util.h"
#include "udev-worker.h"

typedef enum {
        FORMAT_SUBST_DEVNODE,
        FORMAT_SUBST_ATTR,
        FORMAT_SUBST_ENV,
        FORMAT_SUBST_KERNEL,
        FORMAT_SUBST_KERNEL_NUMBER,
        FORMAT_SUBST_DRIVER,
        FORMAT_SUBST_DEVPATH,
        FORMAT_SUBST_ID,
        FORMAT_SUBST_MAJOR,
        FORMAT_SUBST_MINOR,
        FORMAT_SUBST_RESULT,
        FORMAT_SUBST_PARENT,
        FORMAT_SUBST_NAME,
        FORMAT_SUBST_LINKS,
        FORMAT_SUBST_ROOT,
        FORMAT_SUBST_SYS,
        _FORMAT_SUBST_TYPE_MAX,
        _FORMAT_SUBST_TYPE_INVALID = -EINVAL,
} FormatSubstitutionType;

struct subst_map_entry {
        const char *name;
        const char fmt;
        FormatSubstitutionType type;
};

static const struct subst_map_entry map[] = {
           { .name = "devnode",  .fmt = 'N', .type = FORMAT_SUBST_DEVNODE       },
           { .name = "tempnode", .fmt = 'N', .type = FORMAT_SUBST_DEVNODE       }, /* deprecated */
           { .name = "attr",     .fmt = 's', .type = FORMAT_SUBST_ATTR          },
           { .name = "sysfs",    .fmt = 's', .type = FORMAT_SUBST_ATTR          }, /* deprecated */
           { .name = "env",      .fmt = 'E', .type = FORMAT_SUBST_ENV           },
           { .name = "kernel",   .fmt = 'k', .type = FORMAT_SUBST_KERNEL        },
           { .name = "number",   .fmt = 'n', .type = FORMAT_SUBST_KERNEL_NUMBER },
           { .name = "driver",   .fmt = 'd', .type = FORMAT_SUBST_DRIVER        },
           { .name = "devpath",  .fmt = 'p', .type = FORMAT_SUBST_DEVPATH       },
           { .name = "id",       .fmt = 'b', .type = FORMAT_SUBST_ID            },
           { .name = "major",    .fmt = 'M', .type = FORMAT_SUBST_MAJOR         },
           { .name = "minor",    .fmt = 'm', .type = FORMAT_SUBST_MINOR         },
           { .name = "result",   .fmt = 'c', .type = FORMAT_SUBST_RESULT        },
           { .name = "parent",   .fmt = 'P', .type = FORMAT_SUBST_PARENT        },
           { .name = "name",     .fmt = 'D', .type = FORMAT_SUBST_NAME          },
           { .name = "links",    .fmt = 'L', .type = FORMAT_SUBST_LINKS         },
           { .name = "root",     .fmt = 'r', .type = FORMAT_SUBST_ROOT          },
           { .name = "sys",      .fmt = 'S', .type = FORMAT_SUBST_SYS           },
};

static const char* format_type_to_string(FormatSubstitutionType t) {
        FOREACH_ELEMENT(entry, map)
                if (entry->type == t)
                        return entry->name;
        return NULL;
}

static char format_type_to_char(FormatSubstitutionType t) {
        FOREACH_ELEMENT(entry, map)
                if (entry->type == t)
                        return entry->fmt;
        return '\0';
}

static int get_subst_type(const char **str, bool strict, FormatSubstitutionType *ret_type, char ret_attr[static UDEV_PATH_SIZE]) {
        const char *p = *str, *q = NULL;
        size_t i;

        assert(str);
        assert(*str);
        assert(ret_type);
        assert(ret_attr);

        if (*p == '$') {
                p++;
                if (*p == '$') {
                        *str = p;
                        return 0;
                }
                for (i = 0; i < ELEMENTSOF(map); i++)
                        if ((q = startswith(p, map[i].name)))
                                break;
        } else if (*p == '%') {
                p++;
                if (*p == '%') {
                        *str = p;
                        return 0;
                }

                for (i = 0; i < ELEMENTSOF(map); i++)
                        if (*p == map[i].fmt) {
                                q = p + 1;
                                break;
                        }
        } else
                return 0;
        if (!q)
                /* When 'strict' flag is set, then '$' and '%' must be escaped. */
                return strict ? -EINVAL : 0;

        if (*q == '{') {
                const char *start, *end;
                size_t len;

                start = q + 1;
                end = strchr(start, '}');
                if (!end)
                        return -EINVAL;

                len = end - start;
                if (len == 0 || len >= UDEV_PATH_SIZE)
                        return -EINVAL;

                strnscpy(ret_attr, UDEV_PATH_SIZE, start, len);
                q = end + 1;
        } else
                *ret_attr = '\0';

        *str = q;
        *ret_type = map[i].type;
        return 1;
}

static int safe_atou_optional_plus(const char *s, unsigned *ret) {
        const char *p;
        int r;

        assert(s);
        assert(ret);

        /* Returns 1 if plus, 0 if no plus, negative on error */

        p = endswith(s, "+");
        if (p)
                s = strndupa_safe(s, p - s);

        r = safe_atou(s, ret);
        if (r < 0)
                return r;

        return !!p;
}

static ssize_t udev_event_subst_format(
                UdevEvent *event,
                FormatSubstitutionType type,
                const char *attr,
                char *dest,
                size_t l,
                bool *ret_truncated) {

        sd_device *parent, *dev = ASSERT_PTR(ASSERT_PTR(event)->dev);
        const char *val = NULL;
        bool truncated = false;
        char *s = dest;
        int r;

        switch (type) {
        case FORMAT_SUBST_DEVPATH:
                r = sd_device_get_devpath(dev, &val);
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_KERNEL:
                r = sd_device_get_sysname(dev, &val);
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_KERNEL_NUMBER:
                r = sd_device_get_sysnum(dev, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_ID:
                if (!event->dev_parent)
                        goto null_terminate;
                r = sd_device_get_sysname(event->dev_parent, &val);
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_DRIVER:
                if (!event->dev_parent)
                        goto null_terminate;
                r = sd_device_get_driver(event->dev_parent, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_MAJOR:
        case FORMAT_SUBST_MINOR: {
                dev_t devnum;

                r = sd_device_get_devnum(dev, &devnum);
                if (r < 0 && r != -ENOENT)
                        return r;
                strpcpyf_full(&s, l, &truncated, "%u", r < 0 ? 0 : type == FORMAT_SUBST_MAJOR ? major(devnum) : minor(devnum));
                break;
        }
        case FORMAT_SUBST_RESULT: {
                unsigned index = 0; /* 0 means whole string */
                bool has_plus;

                if (!event->program_result)
                        goto null_terminate;

                if (!isempty(attr)) {
                        r = safe_atou_optional_plus(attr, &index);
                        if (r < 0)
                                return r;

                        has_plus = r;
                }

                if (index == 0)
                        strpcpy_full(&s, l, event->program_result, &truncated);
                else {
                        const char *start, *p;
                        unsigned i;

                        p = skip_leading_chars(event->program_result, NULL);

                        for (i = 1; i < index; i++) {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                p = skip_leading_chars(p, NULL);
                                if (*p == '\0')
                                        break;
                        }
                        if (i != index) {
                                log_device_debug(dev, "requested part of result string not found");
                                goto null_terminate;
                        }

                        start = p;
                        /* %c{2+} copies the whole string from the second part on */
                        if (has_plus)
                                strpcpy_full(&s, l, start, &truncated);
                        else {
                                while (*p && !strchr(WHITESPACE, *p))
                                        p++;
                                strnpcpy_full(&s, l, start, p - start, &truncated);
                        }
                }
                break;
        }
        case FORMAT_SUBST_ATTR: {
                char vbuf[UDEV_NAME_SIZE];
                int count;
                bool t;

                if (isempty(attr))
                        return -EINVAL;

                /* try to read the value specified by "[dmi/id]product_name" */
                if (udev_resolve_subsys_kernel(attr, vbuf, sizeof(vbuf), true) == 0)
                        val = vbuf;

                /* try to read the attribute the device */
                if (!val)
                        (void) sd_device_get_sysattr_value(dev, attr, &val);

                /* try to read the attribute of the parent device, other matches have selected */
                if (!val && event->dev_parent && event->dev_parent != dev)
                        (void) sd_device_get_sysattr_value(event->dev_parent, attr, &val);

                if (!val)
                        goto null_terminate;

                /* strip trailing whitespace, and replace unwanted characters */
                if (val != vbuf)
                        strscpy_full(vbuf, sizeof(vbuf), val, &truncated);
                delete_trailing_chars(vbuf, NULL);
                count = udev_replace_chars(vbuf, UDEV_ALLOWED_CHARS_INPUT);
                if (count > 0)
                        log_device_debug(dev, "%i character(s) replaced", count);
                strpcpy_full(&s, l, vbuf, &t);
                truncated = truncated || t;
                break;
        }
        case FORMAT_SUBST_PARENT:
                r = sd_device_get_parent(dev, &parent);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                r = sd_device_get_devname(parent, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val + STRLEN("/dev/"), &truncated);
                break;
        case FORMAT_SUBST_DEVNODE:
                r = sd_device_get_devname(dev, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        case FORMAT_SUBST_NAME:
                if (event->name)
                        strpcpy_full(&s, l, event->name, &truncated);
                else if (sd_device_get_devname(dev, &val) >= 0)
                        strpcpy_full(&s, l, val + STRLEN("/dev/"), &truncated);
                else {
                        r = sd_device_get_sysname(dev, &val);
                        if (r < 0)
                                return r;
                        strpcpy_full(&s, l, val, &truncated);
                }
                break;
        case FORMAT_SUBST_LINKS:
                FOREACH_DEVICE_DEVLINK(dev, link) {
                        if (s == dest)
                                strpcpy_full(&s, l, link + STRLEN("/dev/"), &truncated);
                        else
                                strpcpyl_full(&s, l, &truncated, " ", link + STRLEN("/dev/"), NULL);
                        if (truncated)
                                break;
                }
                if (s == dest)
                        goto null_terminate;
                break;
        case FORMAT_SUBST_ROOT:
                strpcpy_full(&s, l, "/dev", &truncated);
                break;
        case FORMAT_SUBST_SYS:
                strpcpy_full(&s, l, "/sys", &truncated);
                break;
        case FORMAT_SUBST_ENV:
                if (isempty(attr))
                        return -EINVAL;
                r = device_get_property_value_with_fallback(dev, attr, event->worker ? event->worker->properties : NULL, &val);
                if (r == -ENOENT)
                        goto null_terminate;
                if (r < 0)
                        return r;
                strpcpy_full(&s, l, val, &truncated);
                break;
        default:
                assert_not_reached();
        }

        if (ret_truncated)
                *ret_truncated = truncated;

        return s - dest;

null_terminate:
        if (ret_truncated)
                *ret_truncated = truncated;

        *s = '\0';
        return 0;
}

size_t udev_event_apply_format(
                UdevEvent *event,
                const char *src,
                char *dest,
                size_t size,
                bool replace_whitespace,
                bool *ret_truncated) {

        bool truncated = false;
        const char *s = ASSERT_PTR(src);
        int r;

        assert(event);
        assert(event->dev);
        assert(dest);
        assert(size > 0);

        while (*s) {
                FormatSubstitutionType type;
                char attr[UDEV_PATH_SIZE];
                ssize_t subst_len;
                bool t;

                r = get_subst_type(&s, false, &type, attr);
                if (r < 0) {
                        log_device_warning_errno(event->dev, r, "Invalid format string, ignoring: %s", src);
                        break;
                } else if (r == 0) {
                        if (size < 2) {
                                /* need space for this char and the terminating NUL */
                                truncated = true;
                                break;
                        }
                        *dest++ = *s++;
                        size--;
                        continue;
                }

                subst_len = udev_event_subst_format(event, type, attr, dest, size, &t);
                if (subst_len < 0) {
                        log_device_warning_errno(event->dev, subst_len,
                                                 "Failed to substitute variable '$%s' or apply format '%%%c', ignoring: %m",
                                                 format_type_to_string(type), format_type_to_char(type));
                        break;
                }

                truncated = truncated || t;

                /* FORMAT_SUBST_RESULT handles spaces itself */
                if (replace_whitespace && type != FORMAT_SUBST_RESULT)
                        /* udev_replace_whitespace can replace in-place,
                         * and does nothing if subst_len == 0 */
                        subst_len = udev_replace_whitespace(dest, dest, subst_len);

                dest += subst_len;
                size -= subst_len;
        }

        assert(size >= 1);

        if (ret_truncated)
                *ret_truncated = truncated;

        *dest = '\0';
        return size;
}

int udev_check_format(const char *value, size_t *offset, const char **hint) {
        FormatSubstitutionType type;
        const char *s = value;
        char attr[UDEV_PATH_SIZE];
        int r;

        while (*s) {
                r = get_subst_type(&s, true, &type, attr);
                if (r < 0) {
                        if (offset)
                                *offset = s - value;
                        if (hint)
                                *hint = "invalid substitution type";
                        return r;
                } else if (r == 0) {
                        s++;
                        continue;
                }

                if (IN_SET(type, FORMAT_SUBST_ATTR, FORMAT_SUBST_ENV) && isempty(attr)) {
                        if (offset)
                                *offset = s - value;
                        if (hint)
                                *hint = "attribute value missing";
                        return -EINVAL;
                }

                if (type == FORMAT_SUBST_RESULT && !isempty(attr)) {
                        unsigned i;

                        r = safe_atou_optional_plus(attr, &i);
                        if (r < 0) {
                                if (offset)
                                        *offset = s - value;
                                if (hint)
                                        *hint = "attribute value not a valid number";
                                return r;
                        }
                }
        }

        return 0;
}

int udev_resolve_subsys_kernel(const char *string, char *result, size_t maxsize, bool read_value) {
        _cleanup_(sd_device_unrefp) sd_device *dev = NULL;
        _cleanup_free_ char *temp = NULL;
        char *subsys, *sysname, *attr;
        const char *val;
        int r;

        assert(string);
        assert(result);

        /* handle "[<SUBSYSTEM>/<KERNEL>]<attribute>" format */

        if (string[0] != '[')
                return -EINVAL;

        temp = strdup(string);
        if (!temp)
                return -ENOMEM;

        subsys = &temp[1];

        sysname = strchr(subsys, '/');
        if (!sysname)
                return -EINVAL;
        sysname[0] = '\0';
        sysname = &sysname[1];

        attr = strchr(sysname, ']');
        if (!attr)
                return -EINVAL;
        attr[0] = '\0';
        attr = &attr[1];
        if (attr[0] == '/')
                attr = &attr[1];
        if (attr[0] == '\0')
                attr = NULL;

        if (read_value && !attr)
                return -EINVAL;

        r = sd_device_new_from_subsystem_sysname(&dev, subsys, sysname);
        if (r < 0)
                return r;

        if (read_value) {
                r = sd_device_get_sysattr_value(dev, attr, &val);
                if (r < 0 && !ERRNO_IS_PRIVILEGE(r) && r != -ENOENT)
                        return r;
                if (r >= 0)
                        strscpy(result, maxsize, val);
                else
                        result[0] = '\0';
                log_debug("value '[%s/%s]%s' is '%s'", subsys, sysname, attr, result);
        } else {
                r = sd_device_get_syspath(dev, &val);
                if (r < 0)
                        return r;

                strscpyl(result, maxsize, val, attr ? "/" : NULL, attr ?: NULL, NULL);
                log_debug("path '[%s/%s]%s' is '%s'", subsys, sysname, strempty(attr), result);
        }
        return 0;
}
