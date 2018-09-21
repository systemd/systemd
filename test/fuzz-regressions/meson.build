# SPDX-License-Identifier: LGPL-2.1+

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
        fuzz-dns-packet/issue-7888
        fuzz-dns-packet/oss-fuzz-5465
        fuzz-journal-remote/crash-5a8f03d4c3a46fcded39527084f437e8e4b54b76
        fuzz-journal-remote/crash-96dee870ea66d03e89ac321eee28ea63a9b9aa45
        fuzz-journal-remote/oss-fuzz-8659
        fuzz-journal-remote/oss-fuzz-8686
        fuzz-journald-syslog/github-9795
        fuzz-journald-syslog/github-9820
        fuzz-journald-syslog/github-9827
        fuzz-journald-syslog/github-9829
        fuzz-unit-file/oss-fuzz-6884
        fuzz-unit-file/oss-fuzz-6885
        fuzz-unit-file/oss-fuzz-6886
        fuzz-unit-file/oss-fuzz-6892
        fuzz-unit-file/oss-fuzz-6897
        fuzz-unit-file/oss-fuzz-6897-evverx
        fuzz-unit-file/oss-fuzz-6908
        fuzz-unit-file/oss-fuzz-6917
        fuzz-unit-file/oss-fuzz-6977
        fuzz-unit-file/oss-fuzz-6977-unminimized
        fuzz-unit-file/oss-fuzz-7004
        fuzz-unit-file/oss-fuzz-8064
        fuzz-unit-file/oss-fuzz-8827
        fuzz-unit-file/oss-fuzz-10007
'''.split()
