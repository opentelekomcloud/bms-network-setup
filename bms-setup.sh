#!/bin/bash

THISDIR=$(dirname $0)
PYTHON=$(which python3 2>/dev/null || which python2 2>/dev/null)
ARG=

# Remove unwanted ifcfg-e* on EulerOS due to long delays
if test -e /etc/euleros-release; then 
    ARG="-c"
fi

echo $THISDIR

$PYTHON $THISDIR/bms-network-setup.py $ARG || exit 1
$THISDIR/bms-disable-cloudinit-network > "/var/log/bms-network-setup.log"

# Tune readahead for local disk cluster
if [ -f /sys/block/sda/queue/read_ahead_kb ]; then
    read readahead </sys/block/sda/queue/read_ahead_kb || exit 0
    if test "$readahead" == "512"; then
        echo 1280 > /sys/block/sda/queue/read_ahead_kb
    fi
fi

