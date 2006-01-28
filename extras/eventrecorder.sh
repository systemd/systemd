#!/bin/sh

[ -d /events ] || exit 0
set > /events/debug.$SEQNUM.$SUBSYSTEM.$ACTION.$$
