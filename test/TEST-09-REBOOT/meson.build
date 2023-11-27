# The journal tests require that the logs aren't rotated
# and the clock going backwards causes a rotation
# so it's better to potentially have the wrong time than potentially rotate
test_params += {
        'mkosi_args': test_params['mkosi_args'] + ['--kernel-command-line-extra=systemd.mask=systemd-timesyncd.service'],
}
