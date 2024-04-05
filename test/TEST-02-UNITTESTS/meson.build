test_params += {
        'mkosi_args': test_params['mkosi_args'] + [
                '--kernel-command-line-extra=' + ' '.join([
                        '''
frobnicate!

systemd.setenv=TEST_CMDLINE_NEWLINE=foo
systemd.setenv=TEST_CMDLINE_NEWLINE=bar

''',
                ]),
        ],
}
