//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"

char __license[] SEC("license") = "Dual MIT/GPL";

struct data_t {
	u32 pid;
	char program_name[16];
};

struct bpf_map_def SEC("maps") events = {
	.type        = BPF_MAP_TYPE_PERF_EVENT_ARRAY,
	.key_size    = sizeof(u32),
	.value_size  = 0,
	.max_entries = 2,
};

SEC("kprobe/sys_execve")
int bpf_capture_exec(struct pt_regs *ctx) {
	struct data_t data = {};

	data.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&data.program_name, sizeof(data.program_name));
	bpf_perf_event_output(ctx, &events, 0, &data, sizeof(data));

	return 0;
}
