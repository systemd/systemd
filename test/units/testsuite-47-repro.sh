#!/usr/bin/env bash

sleep infinity &
echo $! > /leakedtestpid
wait $!
