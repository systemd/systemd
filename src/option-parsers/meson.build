# SPDX-License-Identifier: LGPL-2.1-or-later

# We generate all the parsing helpers in this separate directory. We want to
# use #include for those files, but they cannot be in the main build directory,
# because we don't want that directory to be added to the top-level build
# directory, see 30d20907bddfe064cc3437a888dd8f00d14929e4.

option_parser_include_dir = include_directories('.')

foreach dict : executables
        if not dict.has_key('option_parser')
                continue
        endif

        source = dict.get('sources')[0]

        options_inc = custom_target(
                input : source,
                output : fs.name(source) + '.inc',
                command : [make_option_parser_py, '@INPUT@'],
                capture : true,
        )

        option_parsers += { dict['name'] : options_inc }
        generated_sources += options_inc
endforeach
