#!/bin/bash

set -x

echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/trace
echo 1 > /sys/kernel/debug/tracing/events/ext4/ext4_journal_fc_commit_cb_stop/enable
echo 1 > /sys/kernel/debug/tracing/events/ext4/ext4_journal_fc_stats/enable
echo 1 > /sys/kernel/debug/tracing/tracing_on
echo "STARTING VARMAIL" > /sys/kernel/debug/tracing/trace_marker
./filebench -f ../filebench/workloads/varmail.f
echo "ENDING VARMAIL" > /sys/kernel/debug/tracing/trace_marker
echo 0 > /sys/kernel/debug/tracing/tracing_on
