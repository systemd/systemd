BEGIN{
        print "static const char* const capability_names[] = { "
}
{
        printf "        [%s] = \"%s\",\n", $1, tolower($1)
}
END{
        print "};"
}
