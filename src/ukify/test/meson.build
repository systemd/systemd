# SPDX-License-Identifier: LGPL-2.1-or-later

if want_ukify and want_tests != 'false'
        have_pytest_flakes = pymod.find_installation('python3', required : false, modules : ['elftools']).found()

        args = ['-v']
        if have_pytest_flakes
                args += ['--flakes']
        endif

        test('test-ukify',
             files('test_ukify.py'),
             args: args,
             env : test_env)
endif
