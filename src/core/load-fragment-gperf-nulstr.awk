# SPDX-License-Identifier: LGPL-2.1-or-later

BEGIN{
        keywords=0 ; FS="," ;
        print "extern const char load_fragment_gperf_nulstr[];" ;
        print "const char load_fragment_gperf_nulstr[] ="
}
keyword==1 {
        print "\"" $1 "\\0\""
}
/%%/ {
        keyword=1
}
END {
        print ";"
}
