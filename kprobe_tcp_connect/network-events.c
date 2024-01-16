//go:build ignore

#include "../headers/common.h"
#include "../headers/bpf_helpers.h"
#include "../headers/bpf_tracing.h"
#include "../headers/bpf_core_read.h"

#define MAXCOMM 	16
#define MAXEVENT 	1024

struct sock_common {
	union {
		struct {
			__be32 skc_daddr;
			__be32 skc_rcv_saddr;
		};
	};
	union {
		// Padding out union skc_hash.
		__u32 _;
	};
	union {
		struct {
			__be16 skc_dport;
			__u16 skc_num;
		};
	};
	short unsigned int skc_family;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
	struct sock_common __sk_common;
};


struct data_t {
	u32 pid;
	u32 daddr;
	u64 ts;
	char comm[MAXCOMM];
};

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, 0);
    __uint(max_entries, 1024);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe__tcp_v4_connect(struct pt_regs *ctx)
{
	struct sock *sk = (struct sock *)PT_REGS_PARM1(ctx);
	if (!sk) {
	  return 0;
	}

	struct data_t data = {};
	data.pid = bpf_get_current_pid_tgid() >> 32;
	bpf_get_current_comm(&data.comm, sizeof(data.comm));
	data.ts = bpf_ktime_get_ns();
	data.daddr= BPF_CORE_READ(sk, __sk_common.skc_daddr);


	bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &data, sizeof(data));

	return 0;
};

char __license[] SEC("license") = "GPL";
