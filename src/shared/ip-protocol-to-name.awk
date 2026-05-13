# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "static const char* const ip_protocol_names[] = { "
}
!/HOPOPTS/ {
        printf "        [IPPROTO_%s] = \"%s\",\n", $1, tolower($1)
}
END{
        print "};"
}
