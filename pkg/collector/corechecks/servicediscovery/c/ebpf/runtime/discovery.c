#include "ktypes.h"
#include "bpf_metadata.h"

#ifdef COMPILE_RUNTIME
#include "kconfig.h"

#if LINUX_VERSION_CODE < KERNEL_VERSION(4, 8, 0)
// 4.8 is the first version where `bpf_get_current_task` is available
#error Versions of Linux previous to 4.8.0 are not supported by this probe
#endif
#endif

#include "discovery-user.h"

#include "pid_tgid.h"
#include "bpf_tracing.h"
#include "bpf_core_read.h"
#include "map-defs.h"

BPF_HASH_MAP(network_stats, struct network_stats_key, struct network_stats, 1024)

static __always_inline struct network_stats *get_stats() {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = GET_USER_MODE_PID(pid_tgid);
    struct network_stats_key key = { .pid = pid };

    return bpf_map_lookup_elem(&network_stats, &key);
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(kretprobe__tcp_recvmsg, int bytes) {
    if (bytes <= 0) {
        return 0;
    }

    struct network_stats *stats = get_stats();
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->rx, bytes);

    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_KRETPROBE(kretprobe__tcp_sendmsg, int bytes) {
    if (bytes <= 0) {
        return 0;
    }

    struct network_stats *stats = get_stats();
    if (!stats) {
        return 0;
    }

    __sync_fetch_and_add(&stats->tx, bytes);

    return 0;
}

char _license[] SEC("license") = "GPL";
