#ifndef SANDBOX_RESOURCES_H
#define SANDBOX_RESOURCES_H
#include <sched.h>
#include <stdint.h>

int allocate_resources(pid_t child_pid, int ram_mb, uint64_t cpu_us);

#endif //SANDBOX_RESOURCES_H
