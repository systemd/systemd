p = run_command('date', '-u', '+%Y-%m-%dT%H:%M:%S', '-d', '+3 days', check: true)
rtc_base = p.stdout().strip()
test_params += {
        'mkosi_args' : test_params['mkosi_args'] + [f'--qemu-args=-rtc base=@rtc_base@'],
}
