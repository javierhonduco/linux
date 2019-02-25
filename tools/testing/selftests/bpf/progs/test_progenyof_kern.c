// SPDX-License-Identifier: GPL-2.0

#include <linux/bpf.h>
#include "bpf_helpers.h"

struct bpf_map_def SEC("maps") pidmap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 2,
};

struct bpf_map_def SEC("maps") resultmap = {
	.type = BPF_MAP_TYPE_ARRAY,
	.key_size = sizeof(__u32),
	.value_size = sizeof(__u32),
	.max_entries = 1,
};

SEC("tracepoint/syscalls/sys_enter_open")
int trace(void *ctx)
{
	__u32 pid = bpf_get_current_pid_tgid();
	__u32 current_key = 0, ancestor_key = 1, *expected_pid, *ancestor_pid;
	__u32 *val;

	expected_pid = bpf_map_lookup_elem(&pidmap, &current_key);
	if (!expected_pid || *expected_pid != pid)
		return 0;

	ancestor_pid = bpf_map_lookup_elem(&pidmap, &ancestor_key);
	if (!ancestor_pid)
		return 0;

	if (!bpf_progenyof(*ancestor_pid))
		return 0;

	val = bpf_map_lookup_elem(&resultmap, &current_key);
	if (val)
		*val = *ancestor_pid;

	return 0;
}

char _license[] SEC("license") = "GPL";
__u32 _version SEC("version") = 1;
