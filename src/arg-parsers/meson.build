# SPDX-License-Identifier: LGPL-2.1-or-later

# We generate all the args parsers in this separate directory. We want to use
# #include for those files, but they cannot be in the main build directory,
# because we don't want that directory to be added to the top-level build
# directory, see 30d20907bddfe064cc3437a888dd8f00d14929e4.

arg_parser_include_dir = include_directories('.')

foreach dict : executables
        if not dict.has_key('arg_parser')
                continue
        endif

        name = dict.get('name', '')
        if name == ''
                name = fs.stem(dict.get('sources')[0])
        endif

        args = dict['arg_parser']
        args_inc = custom_target(
                input : args,
                output : fs.name(args) + '.inc',
                command : [make_arg_parser_py, '@INPUT@'],
                capture : true,
        )

        arg_parsers += { dict['name'] : args_inc }
        generated_sources += args_inc
endforeach
