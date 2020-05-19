#!/bin/bash

umount /mnt
if [ "$1" = "fc" ]; then
    ./mke2fs -t ext4 -b 4096 -O fast_commit /dev/pmem0
else
    ./mke2fs -t ext4 -b 4096 /dev/pmem0

mount -o dax /dev/pmem0 /mnt
