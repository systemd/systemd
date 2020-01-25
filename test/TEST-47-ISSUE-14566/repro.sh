#!/bin/bash

sleep infinity &
echo $! > /leakedtestpid
wait $!
