/***
  This file is part of systemd.

  Copyright 2016 Zbigniew Jędrzejewski-Szmek

  systemd is free software; you can redistribute it and/or modify it
  under the terms of the GNU Lesser General Public License as published by
  the Free Software Foundation; either version 2.1 of the License, or
  (at your option) any later version.

  systemd is distributed in the hope that it will be useful, but
  WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public License
  along with systemd; If not, see <http://www.gnu.org/licenses/>.
***/

#include "hexdecoct.h"
#include "log.h"
#include "macro.h"
#include "string-util.h"

#include "networkd-conf.h"
#include "networkd-network.h"

static void test_config_parse_duid_type_one(const char *rvalue, int ret, DUIDType expected) {
        DUIDType actual = 0;
        int r;

        r = config_parse_duid_type("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL);
        log_info_errno(r, "\"%s\" → %d (%m)", rvalue, actual);
        assert_se(r == ret);
        assert_se(expected == actual);
}

static void test_config_parse_duid_type(void) {
        test_config_parse_duid_type_one("", 0, 0);
        test_config_parse_duid_type_one("link-layer-time", 0, DUID_TYPE_LLT);
        test_config_parse_duid_type_one("vendor", 0, DUID_TYPE_EN);
        test_config_parse_duid_type_one("link-layer", 0, DUID_TYPE_LL);
        test_config_parse_duid_type_one("uuid", 0, DUID_TYPE_UUID);
        test_config_parse_duid_type_one("foo", 0, 0);
}

static void test_config_parse_duid_rawdata_one(const char *rvalue, int ret, const DUID* expected) {
        DUID actual = {};
        int r;
        _cleanup_free_ char *d = NULL;

        r = config_parse_duid_rawdata("network", "filename", 1, "section", 1, "lvalue", 0, rvalue, &actual, NULL);
        d = hexmem(actual.raw_data, actual.raw_data_len);
        log_info_errno(r, "\"%s\" → \"%s\" (%m)",
                       rvalue, strnull(d));
        assert_se(r == ret);
        if (expected) {
                assert_se(actual.raw_data_len == expected->raw_data_len);
                assert_se(memcmp(actual.raw_data, expected->raw_data, expected->raw_data_len) == 0);
        }
}

#define BYTES_0_128 "0:1:2:3:4:5:6:7:8:9:a:b:c:d:e:f:10:11:12:13:14:15:16:17:18:19:1a:1b:1c:1d:1e:1f:20:21:22:23:24:25:26:27:28:29:2a:2b:2c:2d:2e:2f:30:31:32:33:34:35:36:37:38:39:3a:3b:3c:3d:3e:3f:40:41:42:43:44:45:46:47:48:49:4a:4b:4c:4d:4e:4f:50:51:52:53:54:55:56:57:58:59:5a:5b:5c:5d:5e:5f:60:61:62:63:64:65:66:67:68:69:6a:6b:6c:6d:6e:6f:70:71:72:73:74:75:76:77:78:79:7a:7b:7c:7d:7e:7f:80"

#define BYTES_1_128 {0x1,0x2,0x3,0x4,0x5,0x6,0x7,0x8,0x9,0xa,0xb,0xc,0xd,0xe,0xf,0x10,0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20,0x21,0x22,0x23,0x24,0x25,0x26,0x27,0x28,0x29,0x2a,0x2b,0x2c,0x2d,0x2e,0x2f,0x30,0x31,0x32,0x33,0x34,0x35,0x36,0x37,0x38,0x39,0x3a,0x3b,0x3c,0x3d,0x3e,0x3f,0x40,0x41,0x42,0x43,0x44,0x45,0x46,0x47,0x48,0x49,0x4a,0x4b,0x4c,0x4d,0x4e,0x4f,0x50,0x51,0x52,0x53,0x54,0x55,0x56,0x57,0x58,0x59,0x5a,0x5b,0x5c,0x5d,0x5e,0x5f,0x60,0x61,0x62,0x63,0x64,0x65,0x66,0x67,0x68,0x69,0x6a,0x6b,0x6c,0x6d,0x6e,0x6f,0x70,0x71,0x72,0x73,0x74,0x75,0x76,0x77,0x78,0x79,0x7a,0x7b,0x7c,0x7d,0x7e,0x7f,0x80}

static void test_config_parse_duid_rawdata(void) {
        test_config_parse_duid_rawdata_one("", 0, &(DUID){});
        test_config_parse_duid_rawdata_one("00:11:22:33:44:55:66:77", 0,
                                           &(DUID){0, 8, {0x00,0x11,0x22,0x33,0x44,0x55,0x66,0x77}});
        test_config_parse_duid_rawdata_one("00:11:22:", 0,
                                           &(DUID){0, 3, {0x00,0x11,0x22}});
        test_config_parse_duid_rawdata_one("000:11:22", 0, &(DUID){}); /* error, output is all zeros */
        test_config_parse_duid_rawdata_one("00:111:22", 0, &(DUID){});
        test_config_parse_duid_rawdata_one("0:1:2:3:4:5:6:7", 0,
                                           &(DUID){0, 8, {0x0, 0x1, 0x2, 0x3, 0x4, 0x5, 0x6, 0x7}});
        test_config_parse_duid_rawdata_one("11::", 0, &(DUID){0, 1, {0x11}});  /* FIXME: should this be an error? */
        test_config_parse_duid_rawdata_one("abcdef", 0, &(DUID){});
        test_config_parse_duid_rawdata_one(BYTES_0_128, 0, &(DUID){});
        test_config_parse_duid_rawdata_one(BYTES_0_128 + 2, 0, &(DUID){0, 128, BYTES_1_128});
}

int main(int argc, char **argv) {
        log_parse_environment();
        log_open();

        test_config_parse_duid_type();
        test_config_parse_duid_rawdata();

        return 0;
}
