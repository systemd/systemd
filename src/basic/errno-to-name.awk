# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        print "static const char* const errno_names[] = { "
}
!/(EDEADLOCK|EWOULDBLOCK|ENOTSUP)/ {
        printf "        [%s] = \"%s\",\n", $1, $1
}
END{
        print "};"
}
