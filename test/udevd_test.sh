#!/bin/bash

# reset udevd, expected sequence number and empty queue
killall -HUP udevd

export ACTION=add
export DEVPATH=/block/sda

export SEQNUM=1
./udevsend block

export SEQNUM=2
./udevsend block

export SEQNUM=3
./udevsend block

export SEQNUM=5
./udevsend block

export SEQNUM=4
./udevsend block

export SEQNUM=6
./udevsend block

export SEQNUM=7
./udevsend block

export SEQNUM=10
./udevsend block

export SEQNUM=9
#./udevsend block

export SEQNUM=8
#./udevsend block

export SEQNUM=13
./udevsend block

export SEQNUM=12
./udevsend block

export SEQNUM=11
./udevsend block

