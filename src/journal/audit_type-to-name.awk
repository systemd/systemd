BEGIN{
        print "const char *audit_type_to_string(int type) {\n\tswitch(type) {"
}
{
        printf "        case AUDIT_%s: return \"%s\";\n", $1, $1
}
END{
        print "        default: return NULL;\n\t}\n}\n"
}
