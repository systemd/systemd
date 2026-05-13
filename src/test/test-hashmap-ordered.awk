# SPDX-License-Identifier: LGPL-2.1-or-later
BEGIN {
        print "/* GENERATED FILE */";
        print "#define ORDERED"
}
{
        if (!match($0, "^#include"))
                gsub(/hashmap/, "ordered_hashmap");
        gsub(/HASHMAP/, "ORDERED_HASHMAP");
        gsub(/Hashmap/, "OrderedHashmap");
        print
}
