# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "const char* statx_attribute_to_name(uint64_t attr) {"
        print "        switch (attr) {"
}
{
        printf "        case %s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;"
        print "        }"
        print "}"
}
