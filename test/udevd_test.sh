#!/bin/sh

# add/rem/add/rem/add sequence of sda/sdb/sdc
# a few days longer and the socket of my usb-flash-reader is gone :)

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
