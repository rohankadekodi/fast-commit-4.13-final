#!/bin/bash

if [ "$1" = "fast" ]; then
  mkfs.ext4 /dev/pmem0 -O fast_commit
elif [ "$1" = "no" ]; then
  mkfs.ext4 -O ^has_journal /dev/pmem0
else
  mkfs.ext4 /dev/pmem0
fi
mount /dev/pmem0 /mnt -o dax,commit=200000

echo 1 > /sys/kernel/debug/tracing/events/ext4/ext4_journal_fc_stats/enable
echo 1 > /sys/kernel/debug/tracing/events/ext4/ext4_journal_fc_commit_cb_stop/enable
echo "" > /sys/kernel/debug/tracing/trace
/vtmp/filebench -f /vtmp/varmail.f
cp /sys/kernel/debug/tracing/trace /vtmp/trace
umount /dev/pmem0

