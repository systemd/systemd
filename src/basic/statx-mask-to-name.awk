# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "const char* statx_mask_one_to_name(unsigned mask) {"
        print "        switch (mask) {"
}
{
        printf "        case %s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;"
        print "        }"
        print "}"
}
