#ifndef TCP_QUEUE_LENGTH_KERN_USER_H
#define TCP_QUEUE_LENGTH_KERN_USER_H

#include "ktypes.h"

struct network_stats_key {
    __u32 pid;
};

struct network_stats {
    __u64 rx;
    __u64 tx;
};

#endif /* defined(TCP_QUEUE_LENGTH_KERN_USER_H) */
