#!/usr/bin/python3

from contextlib import contextmanager, ExitStack
from subprocess import run
from tempfile import TemporaryDirectory


@contextmanager
def attached_disk(image_path):
    result = run(['systemd-dissect', '--attach', image_path],
                 check=True, capture_output=True)
    loop_path = result.stdout.rstrip(b'\n')
    try:
        yield loop_path
    finally:
        run(['systemd-dissect', '--detach', loop_path], check=True)


@contextmanager
def mounted_partition(file_path, target_path):
    run(['mount', file_path, target_path], check=True)
    try:
        yield
    finally:
        run(['umount', target_path], check=True)


@contextmanager
def mounted_disk(image_path):
    with ExitStack() as stack:
        loop_path = stack.enter_context(attached_disk(image_path))
        td = stack.enter_context(TemporaryDirectory())
        stack.enter_context(mounted_partition(loop_path + b"p7", td))

        yield td
