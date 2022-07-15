# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "static const char* const af_names[] = { "
}
!/AF_FILE/ && !/AF_ROUTE/ && !/AF_LOCAL/ {
        printf "        [%s] = \"%s\",\n", $1, $1
}
END{
        print "};"
}
