BEGIN{
        print "static const char* const arphrd_names[] = { "
}
!/CISCO/ {
        printf "        [ARPHRD_%s] = \"%s\",\n", $1, $1
}
END{
        print "};"
}
