/* SPDX-License-Identifier: LGPL-2.1-or-later */

#include "conf-parser.h"
#include "parse-util.h"
#include "string-util.h"
#include "vlan-util.h"

int parse_vlanid(const char *p, uint16_t *ret) {
        uint16_t id;
        int r;

        assert(p);
        assert(ret);

        r = safe_atou16(p, &id);
        if (r < 0)
                return r;
        if (!vlanid_is_valid(id))
                return -ERANGE;

        *ret = id;
        return 0;
}

int parse_vid_range(const char *p, uint16_t *vid, uint16_t *vid_end) {
        unsigned lower, upper;
        int r;

        r = parse_range(p, &lower, &upper);
        if (r < 0)
                return r;

        if (lower > VLANID_MAX || upper > VLANID_MAX || lower > upper)
                return -EINVAL;

        *vid = lower;
        *vid_end = upper;
        return 0;
}

int config_parse_default_port_vlanid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {
        uint16_t *id = ASSERT_PTR(data);

        assert(lvalue);
        assert(rvalue);

        if (streq(rvalue, "none")) {
                *id = 0;
                return 0;
        }

        return config_parse_vlanid(unit, filename, line, section, section_line,
                                   lvalue, ltype, rvalue, data, userdata);
}

int config_parse_vlanid(
                const char *unit,
                const char *filename,
                unsigned line,
                const char *section,
                unsigned section_line,
                const char *lvalue,
                int ltype,
                const char *rvalue,
                void *data,
                void *userdata) {

        uint16_t *id = ASSERT_PTR(data);
        int r;

        assert(filename);
        assert(lvalue);
        assert(rvalue);

        r = parse_vlanid(rvalue, id);
        if (r == -ERANGE) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "VLAN identifier outside of valid range 0…4094, ignoring: %s", rvalue);
                return 0;
        }
        if (r < 0) {
                log_syntax(unit, LOG_WARNING, filename, line, r,
                           "Failed to parse VLAN identifier value, ignoring: %s", rvalue);
                return 0;
        }

        return 0;
}
