# SPDX-License-Identifier: LGPL-2.1-or-later

systemd_analyze_sources = files('''
        analyze.c
        analyze-condition.c
        analyze-condition.h
        analyze-verify.c
        analyze-verify.h
        analyze-security.c
        analyze-security.h
'''.split())

tests += [
        [['src/analyze/test-verify.c',
          'src/analyze/analyze-verify.c',
          'src/analyze/analyze-verify.h'],
         [libcore,
          libshared],
         [],
         core_includes],
]
