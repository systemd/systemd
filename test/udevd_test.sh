#!/bin/bash

# kill daemon, first event will start it again
killall udevd

# 3 x connect/disconnect sequence of sda/sdb/sdc

export SEQNUM=3
export ACTION=add
export DEVPATH=/block/sdc
./udevsend block

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
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=5
export ACTION=remove
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=8
export ACTION=add
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=6
export ACTION=remove
export DEVPATH=/block/sda
./udevsend block

export SEQNUM=7
export ACTION=add
export DEVPATH=/block/sda
#./udevsend block

sleep 2

export SEQNUM=9
export ACTION=add
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=11
export ACTION=remove
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=10
export ACTION=remove
export DEVPATH=/block/sdc
./udevsend block

export SEQNUM=13
export ACTION=add
export DEVPATH=/block/sda
./udevsend block

export SEQNUM=14
export ACTION=add
export DEVPATH=/block/sdb
./udevsend block

export SEQNUM=15
export ACTION=add
export DEVPATH=/block/sdc
./udevsend block

sleep 2

export SEQNUM=12
export ACTION=remove
export DEVPATH=/block/sda
./udevsend block
