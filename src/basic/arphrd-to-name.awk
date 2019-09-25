BEGIN{
        print "const char *arphrd_to_name(int id) {"
        print "        switch(id) {"
}
!/CISCO|NETROM/ {
        printf "        case ARPHRD_%s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;"
        print "        }"
        print "}"
}
