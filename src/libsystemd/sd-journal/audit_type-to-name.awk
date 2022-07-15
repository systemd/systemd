# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "const char *audit_type_to_string(int type) {"
        print "        switch (type) {"
}
{
        printf "        case AUDIT_%s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;"
        print "        }"
        print "}"
}
