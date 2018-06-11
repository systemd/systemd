# SPDX-License-Identifier: LGPL-2.1+
#
# Copyright 2018 Zbigniew Jędrzejewski-Szmek

sanitize_address = custom_target(
        'sanitize-address-fuzzers',
        output : 'sanitize-address-fuzzers',
        command : [meson_build_sh,
                   meson.source_root(),
                   '@OUTPUT@',
                   'fuzzers',
                   '-Db_lundef=false -Db_sanitize=address'])

sanitizers = [['address', sanitize_address]]

fuzz_regression_tests = '''
        fuzz-dns-packet/oss-fuzz-5465
        fuzz-dns-packet/issue-7888
        fuzz-unit-file/oss-fuzz-6884
        fuzz-unit-file/oss-fuzz-6885
        fuzz-unit-file/oss-fuzz-6886
        fuzz-unit-file/oss-fuzz-6892
        fuzz-unit-file/oss-fuzz-6897
        fuzz-unit-file/oss-fuzz-6897-evverx
        fuzz-unit-file/oss-fuzz-6908
        fuzz-unit-file/oss-fuzz-6917
        fuzz-unit-file/oss-fuzz-6977
        fuzz-unit-file/oss-fuzz-7004
        fuzz-unit-file/oss-fuzz-8064
        fuzz-unit-file/oss-fuzz-8827
'''.split()
