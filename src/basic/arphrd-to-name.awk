# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "const char *arphrd_to_name(int id) {"
        print "        switch (id) {"
}
!/^HDLC$/ {
        printf "        case ARPHRD_%s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;"
        print "        }"
        print "}"
}
