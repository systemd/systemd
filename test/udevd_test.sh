#!/bin/bash

# kill daemon, first event will start it again
killall udevd

# connect(123) - disconnect(456) - connect(789) sequence of sda/sdb/sdc

export SEQNUM=1
export ACTION=add
export DEVPATH=/block/sda
./udevsend block

export SEQNUM=2
export ACTION=add
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=4
export ACTION=remove
export DEVPATH=/block/sda
./udevsend block

export SEQNUM=3
export ACTION=add
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=6
export ACTION=remove
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=5
export ACTION=remove
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=7
export ACTION=add
export DEVPATH=/block/sda
#./udevsend block

export SEQNUM=9
export ACTION=add
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=8
export ACTION=add
export DEVPATH=/block/sdb
./udevsend block

