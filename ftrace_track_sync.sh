#!/bin/bash

set -x

echo function_graph > /sys/kernel/debug/tracing/current_tracer
echo 0 > /sys/kernel/debug/tracing/tracing_on
echo 0 > /sys/kernel/debug/tracing/trace
echo jbd2_complete_transaction > /sys/kernel/debug/tracing/set_ftrace_filter
echo ext4_sync_file >> /sys/kernel/debug/tracing/set_ftrace_filter
echo 1 > /sys/kernel/debug/tracing/tracing_on
echo "STARTING VARMAIL" > /sys/kernel/debug/tracing/trace_marker
./filebench -f ../filebench/workloads/varmail.f
echo "ENDING VARMAIL" > /sys/kernel/debug/tracing/trace_marker;
echo 0 > /sys/kernel/debug/tracing/tracing_on
