#! /bin/sh
#
#  scsi-devfs.sh: udev external PROGRAM script
#
#  Copyright 2004  Richard Gooch <rgooch@atnf.csiro.au>
#  Copyright 2004  Fujitsu Ltd.
#  Distributed under the GNU Copyleft version 2.0.
#
# return devfs-names for scsi-devices
# Usage in udev.rules:
# BUS="scsi", KERNEL="sd*", PROGRAM="/etc/udev/scripts/scsi-devfs.sh sd %b %n", NAME="%c{1}", SYMLINK="%c{2} %k %c{3} %c{4}"
# BUS="scsi", KERNEL="sr*", PROGRAM="/etc/udev/scripts/scsi-devfs.sh sr %b %n", NAME="%c{1}", SYMLINK="%c{2} %k %c{3} %c{4}"
# BUS="scsi", KERNEL="st*", PROGRAM="/etc/udev/scripts/scsi-devfs.sh st %b %n", NAME="%c{1}", SYMLINK="%c{2} %k %c{3} %c{4}"
# BUS="scsi", KERNEL="sg*", PROGRAM="/etc/udev/scripts/scsi-devfs.sh sg %b %n", NAME="%c{1}", SYMLINK="%c{2} %k %c{3} %c{4}"

# Find out where sysfs is mounted. Exit if not available
sysfs=`grep -F sysfs /proc/mounts | awk '{print $2}'`
if [ "$sysfs" = "" ]; then
    echo "sysfs is required"
    exit 1
fi
cd $sysfs/bus/scsi/devices

case "$1" in
  sd)
    # Extract partition component
    if [ "$3" = "" ]; then
	lpart="disc"
	spart=""
    else
	lpart="part$3"
	spart="p$3"
    fi
    ;;
  sr)
    lpart="cdrom"
    spart=""
    ;;
  st)
    # Not supported yet
    exit 1
    ;;
  sg)
    lpart="generic"
    spart=""
    ;;
  *)
    exit 1
    ;;
esac

# Extract SCSI logical address components
scsi_host=`echo $2 | cut -f 1 -d:`
scsi_bus=`echo $2 | cut -f 2 -d:`
scsi_target=`echo $2 | cut -f 3 -d:`
scsi_lun=`echo $2 | cut -f 4 -d:`

# Generate long and short common name parts
l_com="bus$scsi_bus/target$scsi_target/lun$scsi_lun/$lpart"
s_com="b${scsi_bus}t${scsi_target}u${scsi_lun}$spart"

# Generate long and short logical names
l_log="scsi/host$scsi_host/$l_com"
s_log="$1/c${scsi_host}${s_com}"

readlink $2 | grep -F -q pci
if [ "$?" != "0" ]; then
    # Not a PCI controller, show logical locations only
    echo $l_log $s_log
    exit 0
fi

# Extract PCI address
tmp=`readlink $2 | sed -e 's@/host.*/.*@@'`
pci_addr=`basename "$tmp"`
pci_domain=`echo $pci_addr | cut -f 1 -d:`
pci_bus=`echo $pci_addr | cut -f 2 -d:`
pci_slot=`echo $pci_addr | tr . : | cut -f 3 -d:`
pci_function=`echo $pci_addr | cut -f 2 -d.`

# Generate long and short physical names
l_pci="domain$pci_domain/bus$pci_bus/slot$pci_slot/function$pci_function"
l_phy="bus/pci/$l_pci/scsi/$l_com"
s_phy="$1/pci/$pci_addr/$s_com"

echo $l_phy $s_phy $l_log $s_log


