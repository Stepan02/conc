#ifndef SANDBOX_RESOURCES_H
#define SANDBOX_RESOURCES_H
#include <sched.h>
#include <stdint.h>
#include "include/types.h"

int allocate_resources(pid_t child_pid, uint64_t ram_mb, uint64_t cpu_us, uint64_t pid_limit);
int set_limits(int oom_score_adj);
int setup_sysctl(const object_t *sysctl, int sysctl_count);

#endif //SANDBOX_RESOURCES_H
