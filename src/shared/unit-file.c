/* SPDX-License-Identifier: LGPL-2.1+ */

#include "macro.h"
#include "string-util.h"
#include "unit-file.h"

bool unit_type_may_alias(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_DEVICE,
                      UNIT_TIMER,
                      UNIT_PATH);
}

bool unit_type_may_template(UnitType type) {
        return IN_SET(type,
                      UNIT_SERVICE,
                      UNIT_SOCKET,
                      UNIT_TARGET,
                      UNIT_TIMER,
                      UNIT_PATH);
}

int unit_validate_alias_symlink_and_warn(const char *filename, const char *target) {
        const char *src, *dst;
        _cleanup_free_ char *src_instance = NULL, *dst_instance = NULL;
        UnitType src_unit_type, dst_unit_type;
        int src_name_type, dst_name_type;

        /* Check if the *alias* symlink is valid. This applies to symlinks like
         * /etc/systemd/system/dbus.service → dbus-broker.service, but not to .wants or .requires symlinks
         * and such. Neither does this apply to symlinks which *link* units, i.e. symlinks to outside of the
         * unit lookup path.
         *
         * -EINVAL is returned if the something is wrong with the source filename or the source unit type is
         *         not allowed to symlink,
         * -EXDEV if the target filename is not a valid unit name or doesn't match the source.
         */

        src = basename(filename);
        dst = basename(target);

        /* src checks */

        src_name_type = unit_name_to_instance(src, &src_instance);
        if (src_name_type < 0)
                return log_notice_errno(src_name_type,
                                        "%s: not a valid unit name \"%s\": %m", filename, src);

        src_unit_type = unit_name_to_type(src);
        assert(src_unit_type >= 0); /* unit_name_to_instance() checked the suffix already */

        if (!unit_type_may_alias(src_unit_type))
                return log_notice_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "%s: symlinks are not allowed for units of this type, rejecting.",
                                        filename);

        if (src_name_type != UNIT_NAME_PLAIN &&
            !unit_type_may_template(src_unit_type))
                return log_notice_errno(SYNTHETIC_ERRNO(EINVAL),
                                        "%s: templates not allowed for %s units, rejecting.",
                                        filename, unit_type_to_string(src_unit_type));

        /* dst checks */

        dst_name_type = unit_name_to_instance(dst, &dst_instance);
        if (dst_name_type < 0)
                return log_notice_errno(dst_name_type == -EINVAL ? SYNTHETIC_ERRNO(EXDEV) : dst_name_type,
                                        "%s points to \"%s\" which is not a valid unit name: %m",
                                        filename, dst);

        if (!(dst_name_type == src_name_type ||
              (src_name_type == UNIT_NAME_INSTANCE && dst_name_type == UNIT_NAME_TEMPLATE)))
                return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                        "%s: symlink target name type \"%s\" does not match source, rejecting.",
                                        filename, dst);

        if (dst_name_type == UNIT_NAME_INSTANCE) {
                assert(src_instance);
                assert(dst_instance);
                if (!streq(src_instance, dst_instance))
                        return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                                "%s: unit symlink target \"%s\" instance name doesn't match, rejecting.",
                                                filename, dst);
        }

        dst_unit_type = unit_name_to_type(dst);
        if (dst_unit_type != src_unit_type)
                return log_notice_errno(SYNTHETIC_ERRNO(EXDEV),
                                        "%s: symlink target \"%s\" has incompatible suffix, rejecting.",
                                        filename, dst);

        return 0;
}
