BEGIN{
        print "static const char* const errno_names[] = { "
}
!/EDEADLOCK/ && !/EWOULDBLOCK/ && !/ENOTSUP/ {
        printf "        [%s] = \"%s\",\n", $1, $1
}
END{
        print "};"
}
