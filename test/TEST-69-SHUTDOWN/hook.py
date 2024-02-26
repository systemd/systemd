#!/usr/bin/python3

from logging import getLogger as logging_get_logger
from pathlib import Path
from shlex import quote
from shutil import which
from subprocess import run


log = logging_get_logger(__name__)


def wrap_run(args, **kwargs):
    args[0] = which(args[0])
    clargs = [Path(__file__).parents[1] / 'test-shutdown.py', '-v', '--']
    clargs += args
    log.debug(f"Running {' '.join(quote(str(a)) for a in clargs)}")
    run(clargs, **kwargs)


def check_result(mountpoint, console_log):
    # This test determines success by whether the wrapper command failed
    pass
